/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use crate::{
    capi::ret::{self, IntoCReturn},
    error::{self, Error},
    syscalls,
    utils::RawFdExt,
    InodeType, OpenFlags, RenameFlags, Root,
};

use std::{
    ffi::{CStr, OsStr},
    fs::Permissions,
    os::unix::ffi::OsStrExt,
    os::unix::{
        fs::PermissionsExt,
        io::{AsRawFd, RawFd},
    },
    path::Path,
};

use libc::{c_char, c_int, c_uint, dev_t};
use snafu::ResultExt;

fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, Error> {
    ensure!(
        !path.is_null(),
        error::InvalidArgument {
            name: "path",
            description: "cannot be NULL",
        }
    );
    // SAFETY: C caller guarantees that the path is a valid C-style string.
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    Ok(OsStr::from_bytes(bytes).as_ref())
}

/// Open a root handle.
///
/// The provided path must be an existing directory.
///
/// Note that root handles are not special -- this function is effectively
/// equivalent to
///
/// ```c
/// fd = open(path, O_PATH|O_DIRECTORY);
/// ```
///
/// # Return Value
///
/// On success, this function returns a file descriptor that can be used as a
/// root handle in subsequent pathrs_* operations.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_root_open(path: *const c_char) -> RawFd {
    parse_path(path).and_then(Root::open).into_c_return()
}

/// "Upgrade" an O_PATH file descriptor to a usable fd, suitable for reading and
/// writing. This does not consume the original file descriptor. (This can be
/// used with non-O_PATH file descriptors as well.)
///
/// It should be noted that the use of O_CREAT *is not* supported (and will
/// result in an error). Handles only refer to *existing* files. Instead you
/// need to use pathrs_creat().
///
/// In addition, O_NOCTTY is automatically set when opening the path. If you
/// want to use the path as a controlling terminal, you will have to do
/// ioctl(fd, TIOCSCTTY, 0) yourself.
///
/// # Return Value
///
/// On success, this function returns a file descriptor.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_reopen(fd: RawFd, flags: c_int) -> RawFd {
    let flags = OpenFlags(flags);

    fd.reopen(flags)
        .and_then(|file| {
            // Rust sets O_CLOEXEC by default, without an opt-out. We need to
            // disable it if we weren't asked to do O_CLOEXEC.
            if flags.0 & libc::O_CLOEXEC == 0 {
                syscalls::fcntl_unset_cloexec(file.as_raw_fd()).context(error::RawOsError {
                    operation: "clear O_CLOEXEC on fd",
                })?;
            }
            Ok(file)
        })
        .into_c_return()
}

/// Resolve the given path within the rootfs referenced by root_fd. The path
/// *must already exist*, otherwise an error will occur.
///
/// # Return Value
///
/// On success, this function returns an O_PATH file descriptor referencing the
/// resolved path.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_resolve(root_fd: RawFd, path: *const c_char) -> RawFd {
    ret::with_fd(root_fd, |root: &mut Root| root.resolve(parse_path(path)?))
}

/// Rename a path within the rootfs referenced by root_fd. The flags argument is
/// identical to the renameat2(2) flags that are supported on the system.
///
/// # Return Value
///
/// On success, this function returns 0.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_rename(
    root_fd: RawFd,
    src: *const c_char,
    dst: *const c_char,
    flags: u32,
) -> c_int {
    ret::with_fd(root_fd, |root: &mut Root| {
        let flags = RenameFlags(flags);
        root.rename(parse_path(src)?, parse_path(dst)?, flags)
    })
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each pathrs_* corresponds to the matching syscall.

// TODO: Replace all these wrappers with macros. It's quite repetitive.

/// Create a new regular file within the rootfs referenced by root_fd. This is
/// effectively an O_CREAT|O_EXCL operation, and so (unlike pathrs_resolve()),
/// this function can be used on non-existent paths.
///
/// If you want to create a file without opening a handle to it, you can do
/// pathrs_mknod(root_fd, path, S_IFREG|mode, 0) instead.
///
/// NOTE: Unlike O_CREAT, pathrs_creat() will return an error if the final
/// component is a dangling symlink. O_CREAT will create such files, and while
/// openat2 does support this it would be difficult to implement this in the
/// emulated resolver.
///
/// # Return Value
///
/// On success, this function returns a file descriptor to the requested file.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_creat(root_fd: RawFd, path: *const c_char, mode: c_uint) -> RawFd {
    ret::with_fd(root_fd, |root: &mut Root| {
        let mode = mode & !libc::S_IFMT;
        let perm = Permissions::from_mode(mode);
        root.create_file(parse_path(path)?, &perm)
    })
}

/// Create a new directory within the rootfs referenced by root_fd.
///
/// This is shorthand for pathrs_mknod(root_fd, path, S_IFDIR|mode, 0).
///
/// # Return Value
///
/// On success, this function returns 0.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_mkdir(root_fd: RawFd, path: *const c_char, mode: c_uint) -> c_int {
    let mode = mode & !libc::S_IFMT;
    pathrs_mknod(root_fd, path, libc::S_IFDIR | mode, 0)
}

/// Create a inode within the rootfs referenced by root_fd. The type of inode to
/// be created is configured using the S_IFMT bits in mode (a-la mknod(2)).
///
/// # Return Value
///
/// On success, this function returns 0.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_mknod(
    root_fd: RawFd,
    path: *const c_char,
    mode: c_uint,
    dev: dev_t,
) -> c_int {
    ret::with_fd(root_fd, |root: &mut Root| {
        let fmt = mode & libc::S_IFMT;
        let perms = Permissions::from_mode(mode ^ fmt);
        let path = parse_path(path)?;
        let inode_type = match fmt {
            libc::S_IFREG => InodeType::File(&perms),
            libc::S_IFDIR => InodeType::Directory(&perms),
            libc::S_IFBLK => InodeType::BlockDevice(&perms, dev),
            libc::S_IFCHR => InodeType::CharacterDevice(&perms, dev),
            libc::S_IFIFO => InodeType::Fifo(&perms),
            libc::S_IFSOCK => error::NotImplemented {
                feature: "mknod(S_IFSOCK)",
            }
            .fail()?,
            _ => error::InvalidArgument {
                name: "mode",
                description: "invalid S_IFMT mask",
            }
            .fail()?,
        };
        root.create(path, &inode_type)
    })
}

/// Create a symlink within the rootfs referenced by root_fd. Note that the
/// symlink target string is not modified when creating the symlink.
///
/// # Return Value
///
/// On success, this function returns 0.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_symlink(
    root_fd: RawFd,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    ret::with_fd(root_fd, |root: &mut Root| {
        let path = parse_path(path)?;
        let target = parse_path(target)?;
        root.create(path, &InodeType::Symlink(target))
    })
}

/// Create a hardlink within the rootfs referenced by root_fd. Both the hardlink
/// path and target are resolved within the rootfs.
///
/// # Return Value
///
/// On success, this function returns 0.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_hardlink(
    root_fd: RawFd,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    ret::with_fd(root_fd, |root: &mut Root| {
        let path = parse_path(path)?;
        let target = parse_path(target)?;
        root.create(path, &InodeType::Hardlink(target))
    })
}

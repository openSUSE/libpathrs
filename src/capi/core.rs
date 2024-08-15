/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use crate::{
    capi::{
        ret::{self, IntoCReturn},
        utils,
    },
    error::ErrorImpl,
    flags::{OpenFlags, RenameFlags},
    procfs::PROCFS_HANDLE,
    syscalls,
    utils::RawFdExt,
    InodeType, Root,
};

use std::{
    fs::Permissions,
    os::unix::{
        fs::PermissionsExt,
        io::{AsRawFd, RawFd},
    },
};

use libc::{c_char, c_int, c_uint, dev_t, size_t};

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
    utils::parse_path(path).and_then(Root::open).into_c_return()
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
    let flags = OpenFlags::from_bits_retain(flags);

    fd.reopen(&PROCFS_HANDLE, flags)
        .and_then(|file| {
            // Rust sets O_CLOEXEC by default, without an opt-out. We need to
            // disable it if we weren't asked to do O_CLOEXEC.
            if !flags.contains(OpenFlags::O_CLOEXEC) {
                syscalls::fcntl_unset_cloexec(file.as_raw_fd()).map_err(|err| {
                    ErrorImpl::RawOsError {
                        operation: "clear O_CLOEXEC on fd".into(),
                        source: err,
                    }
                })?;
            }
            Ok(file)
        })
        .into_c_return()
}

/// Resolve the given path within the rootfs referenced by root_fd. The path
/// *must already exist*, otherwise an error will occur.
///
/// All symlinks (including trailing symlinks) are followed, but they are
/// resolved within the rootfs. If you wish to open a handle to the symlink
/// itself, use pathrs_resolve_nofollow().
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
    ret::with_fd(root_fd, |root: &mut Root| {
        root.resolve(utils::parse_path(path)?)
    })
}

/// pathrs_resolve_nofollow() is effectively an O_NOFOLLOW version of
/// pathrs_resolve(). Their behaviour is identical, except that *trailing*
/// symlinks will not be followed. If the final component is a trailing symlink,
/// an O_PATH|O_NOFOLLOW handle to the symlink itself is returned.
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
pub extern "C" fn pathrs_resolve_nofollow(root_fd: RawFd, path: *const c_char) -> RawFd {
    ret::with_fd(root_fd, |root: &mut Root| {
        root.resolve_nofollow(utils::parse_path(path)?)
    })
}

/// Get the target of a symlink within the rootfs referenced by root_fd.
///
/// NOTE: The returned path is not modified to be "safe" outside of the
/// root. You should not use this path for doing further path lookups -- use
/// pathrs_resolve() instead.
///
/// This method is just shorthand for:
///
/// ```c
/// int linkfd = pathrs_resolve_nofollow(rootfd, path);
/// if (linkfd < 0) {
///     liberr = fd; // for use with pathrs_errorinfo()
///     goto err;
/// }
/// copied = readlinkat(linkfd, "", linkbuf, linkbuf_size);
/// close(linkfd);
/// ```
///
/// # Return Value
///
/// On success, this function copies the symlink contents to `linkbuf` (up to
/// `linkbuf_size` bytes) and returns the full size of the symlink path buffer.
/// This function will not copy the trailing NUL byte, and the return size does
/// not include the NUL byte. A `NULL` `linkbuf` or invalid `linkbuf_size` are
/// treated as zero-size buffers.
///
/// NOTE: Unlike readlinkat(2), in the case where linkbuf is too small to
/// contain the symlink contents, pathrs_readlink() will return *the number of
/// bytes it would have copied if the buffer was large enough*. This matches the
/// behaviour of pathrs_proc_readlink().
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_readlink(
    root_fd: RawFd,
    path: *const c_char,
    linkbuf: *mut c_char,
    linkbuf_size: size_t,
) -> RawFd {
    ret::with_fd(root_fd, |root: &mut Root| {
        let link_target = root.readlink(utils::parse_path(path)?)?;
        utils::copy_path_into_buffer(link_target, linkbuf, linkbuf_size)
    })
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
        let rflags = RenameFlags::from_bits_retain(flags);
        root.rename(utils::parse_path(src)?, utils::parse_path(dst)?, rflags)
    })
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each pathrs_* corresponds to the matching syscall.

// TODO: Replace all these wrappers with macros. It's quite repetitive.

/// Create a new regular file within the rootfs referenced by root_fd. This is
/// effectively an O_CREAT operation, and so (unlike pathrs_resolve()), this
/// function can be used on non-existent paths.
///
/// If you want to ensure the creation is a new file, use O_EXCL.
///
/// If you want to create a file without opening a handle to it, you can do
/// pathrs_mknod(root_fd, path, S_IFREG|mode, 0) instead.
///
/// As with pathrs_reopen(), O_NOCTTY is automatically set when opening the
/// path. If you want to use the path as a controlling terminal, you will have
/// to do ioctl(fd, TIOCSCTTY, 0) yourself.
///
/// NOTE: Unlike O_CREAT, pathrs_creat() will return an error if the final
/// component is a dangling symlink. O_CREAT will create such files, and while
/// openat2 does support this it would be difficult to implement this in the
/// emulated resolver.
///
/// # Return Value
///
/// On success, this function returns a file descriptor to the requested file.
/// The open flags are based on the provided flags.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_creat(
    root_fd: RawFd,
    path: *const c_char,
    flags: c_int,
    mode: c_uint,
) -> RawFd {
    ret::with_fd(root_fd, |root: &mut Root| {
        let mode = mode & !libc::S_IFMT;
        let perm = Permissions::from_mode(mode);
        root.create_file(
            utils::parse_path(path)?,
            OpenFlags::from_bits_retain(flags),
            &perm,
        )
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

/// Create a new directory (and any of its path components if they don't exist)
/// within the rootfs referenced by root_fd.
///
/// # Return Value
///
/// On success, this function returns an O_DIRECTORY file descriptor to the
/// newly created directory.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_mkdir_all(root_fd: RawFd, path: *const c_char, mode: c_uint) -> RawFd {
    ret::with_fd(root_fd, |root: &mut Root| {
        let mode = mode & !libc::S_IFMT;
        let perm = Permissions::from_mode(mode);
        root.mkdir_all(utils::parse_path(path)?, &perm)
    })
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
        let path = utils::parse_path(path)?;
        let inode_type = match fmt {
            libc::S_IFREG => InodeType::File(perms),
            libc::S_IFDIR => InodeType::Directory(perms),
            libc::S_IFBLK => InodeType::BlockDevice(perms, dev),
            libc::S_IFCHR => InodeType::CharacterDevice(perms, dev),
            libc::S_IFIFO => InodeType::Fifo(perms),
            libc::S_IFSOCK => Err(ErrorImpl::NotImplemented {
                feature: "mknod(S_IFSOCK)".into(),
            })?,
            _ => Err(ErrorImpl::InvalidArgument {
                name: "mode".into(),
                description: "invalid S_IFMT mask".into(),
            })?,
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
        let path = utils::parse_path(path)?;
        let target = utils::parse_path(target)?;
        root.create(path, &InodeType::Symlink(target.into()))
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
        let path = utils::parse_path(path)?;
        let target = utils::parse_path(target)?;
        root.create(path, &InodeType::Hardlink(target.into()))
    })
}

/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2020 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2020 SUSE LLC
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
    capi::utils::{self, CHandle, CRoot, Leakable},
    error, syscalls, InodeType, OpenFlags, RenameFlags, Root,
};

use std::{
    fs::Permissions,
    os::unix::{
        fs::PermissionsExt,
        io::{AsRawFd, IntoRawFd, RawFd},
    },
};

use libc::{c_char, c_int, c_uint, dev_t};
use snafu::ResultExt;

/// Open a root handle.
///
/// The default resolver is automatically chosen based on the running kernel.
/// You can switch the resolver used with pathrs_configure() -- though this
/// is not strictly recommended unless you have a good reason to do it.
///
/// The provided path must be an existing directory.
///
/// # Errors
///
///  Unlike other libpathrs methods, pathrs_open will *always* return a
///  pathrs_root_t (but in the case of an error, the returned root handle will
///  be a "dummy" which is just used to store the error encountered during
///  setup). Errors during pathrs_open() can only be detected by immediately
///  calling pathrs_error() with the returned root handle -- and as with valid
///  root handles, the caller must free it with pathrs_free().
///
///  This unfortunate API wart is necessary because there is no obvious place to
///  store a libpathrs error when first creating an root handle (other than
///  using thread-local storage but that opens several other cans of worms).
///  This approach was chosen because in principle users could call
///  pathrs_error() after every libpathrs API call.
#[no_mangle]
pub extern "C" fn pathrs_open(path: *const c_char) -> &'static mut CRoot {
    match utils::parse_path(path).and_then(Root::open) {
        Ok(root) => CRoot::from(root),
        Err(err) => CRoot::from_err(err),
    }
    .leak()
}

/// "Upgrade" the handle to a usable fd, suitable for reading and writing. This
/// does not consume the original handle (allowing for it to be used many
/// times).
///
/// It should be noted that the use of O_CREAT *is not* supported (and will
/// result in an error). Handles only refer to *existing* files. Instead you
/// need to use creat().
///
/// In addition, O_NOCTTY is automatically set when opening the path. If you
/// want to use the path as a controlling terminal, you will have to do
/// ioctl(fd, TIOCSCTTY, 0) yourself.
#[no_mangle]
pub extern "C" fn pathrs_reopen(handle: &CHandle, flags: c_int) -> RawFd {
    handle.wrap_err(-1, |handle| {
        let flags = OpenFlags(flags);
        let file = handle.reopen(flags)?;
        // Rust sets O_CLOEXEC by default, without an opt-out. We need to
        // disable it if we weren't asked to do O_CLOEXEC.
        if flags.0 & libc::O_CLOEXEC == 0 {
            syscalls::fcntl_unset_cloexec(file.as_raw_fd()).context(error::RawOsError {
                operation: "clear O_CLOEXEC on fd",
            })?;
        }
        Ok(file.into_raw_fd())
    })
}

/// Within the given root's tree, resolve the given path (with all symlinks
/// being scoped to the root) and return a handle to that path. The path *must
/// already exist*, otherwise an error will occur.
#[no_mangle]
pub extern "C" fn pathrs_resolve(
    root: &CRoot,
    path: *const c_char,
) -> Option<&'static mut CHandle> {
    root.wrap_err(None, |root| {
        root.resolve(utils::parse_path(path)?)
            .map(CHandle::from)
            .map(Leakable::leak)
            .map(Option::from)
    })
}

/// Within the given root's tree, perform the rename (with all symlinks being
/// scoped to the root). The flags argument is identical to the renameat2(2)
/// flags that are supported on the system.
#[no_mangle]
pub extern "C" fn pathrs_rename(
    root: &CRoot,
    src: *const c_char,
    dst: *const c_char,
    flags: c_int,
) -> c_int {
    root.wrap_err(-1, |root| {
        let flags = RenameFlags(flags);
        root.rename(utils::parse_path(src)?, utils::parse_path(dst)?, flags)
            .and(Ok(0))
    })
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each pathrs_* corresponds to the matching syscall.

// TODO: Replace all these wrappers with macros. It's quite repetitive.

#[no_mangle]
pub extern "C" fn pathrs_creat(
    root: &CRoot,
    path: *const c_char,
    mode: c_uint,
) -> Option<&'static mut CHandle> {
    root.wrap_err(None, |root| {
        let mode = mode & !libc::S_IFMT;
        let perm = Permissions::from_mode(mode);
        root.create_file(utils::parse_path(path)?, &perm)
            .map(CHandle::from)
            .map(Leakable::leak)
            .map(Option::from)
    })
}

#[no_mangle]
pub extern "C" fn pathrs_mkdir(root: &CRoot, path: *const c_char, mode: c_uint) -> c_int {
    let mode = mode & !libc::S_IFMT;

    pathrs_mknod(root, path, libc::S_IFDIR | mode, 0)
}

#[no_mangle]
pub extern "C" fn pathrs_mknod(
    root: &CRoot,
    path: *const c_char,
    mode: c_uint,
    dev: dev_t,
) -> c_int {
    root.wrap_err(-1, |root| {
        let fmt = mode & libc::S_IFMT;
        let perms = Permissions::from_mode(mode ^ fmt);
        let path = utils::parse_path(path)?;
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
        root.create(path, &inode_type).and(Ok(0))
    })
}

#[no_mangle]
pub extern "C" fn pathrs_symlink(
    root: &CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    root.wrap_err(-1, |root| {
        let path = utils::parse_path(path)?;
        let target = utils::parse_path(target)?;
        root.create(path, &InodeType::Symlink(target)).and(Ok(0))
    })
}

#[no_mangle]
pub extern "C" fn pathrs_hardlink(
    root: &CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    root.wrap_err(-1, |root| {
        let path = utils::parse_path(path)?;
        let target = utils::parse_path(target)?;
        root.create(path, &InodeType::Hardlink(target)).and(Ok(0))
    })
}

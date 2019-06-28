/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019 SUSE LLC
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

// Import ourselves to make this an example of using libpathrs.
use crate as libpathrs;
use libpathrs::ffi::error;
use libpathrs::{Handle, InodeType, Root};

use std::ffi::CStr;
use std::fs::{OpenOptions, Permissions};
use std::ops::{Deref, DerefMut};
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    io::{AsRawFd, RawFd},
};
use std::path::Path;

use failure::Error;
use libc::{c_char, c_int, c_uint, dev_t};

/// Wrapping struct which we can given C a pointer to. `&T` isn't an option,
/// because DSTs (fat pointers) like `dyn T` (and thus `&dyn T`) have no
/// FFI-safe representation. So we need to hide it within an FFI-safe pointer
/// (such as a trivial struct).
pub struct CPointer<T> {
    inner: T,
}

// Private trait necessary to work around the "orphan trait" restriction.
trait Pointer<T: ?Sized>: Deref + DerefMut {
    fn new(inner: T) -> &'static mut Self;
    fn free(&mut self);
}

impl<T> Deref for CPointer<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for CPointer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// A basic way of having consistent and simple errors when passing NULL
// incorrectly to a libpathrs API call, and freeing it later.
impl<T> Pointer<T> for CPointer<T> {
    // Heap-allocate a new CPointer, but then leak it for C FFI usage.
    fn new(inner: T) -> &'static mut Self {
        Box::leak(Box::new(CPointer { inner: inner }))
    }

    // Take an already-leaked CPointer and un-leak it so we can drop it in Rust.
    fn free(&mut self) {
        unsafe { Box::from_raw(self as *mut Self) }.inner;
        // drop the Box
    }
}

/// A handle to the root of a directory tree to resolve within. The only purpose
/// of this "root handle" is to get Handles to inodes within the directory tree.
///
/// At the time of writing, it is considered a *VERY BAD IDEA* to open a Root
/// inside a possibly-attacker-controlled directory tree. While we do have
/// protections that should defend against it (for both drivers), it's far more
/// dangerous than just opening a directory tree which is not inside a
/// potentially-untrusted directory.
pub type CRoot = CPointer<Box<dyn Root>>;

/// A handle to a path within a given Root. This handle references an
/// already-resolved path which can be used for only one purpose -- to "re-open"
/// the handle and get an actual fs::File which can be used for ordinary
/// operations.
///
/// It is critical for the safety of users of this library that *at no point* do
/// you use interfaces like libc::openat directly on file descriptors you get
/// from using this library (or extract the RawFd from a fs::File). You must
/// always use operations through a Root.
pub type CHandle = CPointer<Box<dyn Handle>>;

/// Open a root handle. The correct backend (native/kernel or emulated) to use
/// is auto-detected based on whether the kernel supports openat2(2).
///
/// The provided path must be an existing directory. If using the emulated
/// driver, it also must be the fully-expanded path to a real directory (with no
/// symlink components) because the given path is used to double-check that the
/// open operation was not affected by an attacker.
#[no_mangle]
pub extern "C" fn pathrs_open(path: *const c_char) -> Option<&'static mut CRoot> {
    error::ffi_wrap(None, move || {
        if path.is_null() {
            bail!("pathrs_open got NULL path");
        }
        let path = unsafe { CStr::from_ptr(path) }.to_str()?;

        // Leak the box so we can return the pointer to the caller.
        libpathrs::open(Path::new(path))
            .map(CPointer::new)
            .map(Option::Some)
    })
}

/// Free a root handle.
#[no_mangle]
pub extern "C" fn pathrs_rfree(root: &mut CRoot) {
    root.free();
}

/// "Upgrade" the handle to a usable fd, suitable for reading and writing. This
/// does not consume the original handle (allowing for it to be used many
/// times).
///
/// It should be noted that the use of O_CREAT *is not* supported (and will
/// result in an error). Handles only refer to *existing* files. Instead you
/// need to use inroot_creat().
#[no_mangle]
pub extern "C" fn handle_reopen(handle: &CHandle, flags: c_int) -> RawFd {
    error::ffi_wrap(-1, move || {
        // Construct options from the C-style flags. Due to weird restrictions
        // with OpenOptions we need to manually set the O_ACCMODE bits.
        let mut options = OpenOptions::new();
        handle
            .inner
            .reopen(
                match flags & libc::O_ACCMODE {
                    libc::O_RDONLY => options.read(true),
                    libc::O_WRONLY => options.write(true),
                    libc::O_RDWR => options.read(true).write(true),
                    _ => bail!("invalid flags to reopen: {:?}", flags),
                }
                .custom_flags(flags),
            )
            .map(|f| f.as_raw_fd())
    })
}

/// Free a handle.
#[no_mangle]
pub extern "C" fn pathrs_hfree(handle: &mut CHandle) {
    handle.free();
}

/// Within the given root's tree, resolve the given path (with all symlinks
/// being scoped to the root) and return a handle to that path. The path *must
/// already exist*, otherwise an error will occur.
#[no_mangle]
pub extern "C" fn inroot_resolve(
    root: &CRoot,
    path: *const c_char,
) -> Option<&'static mut CHandle> {
    error::ffi_wrap(None, move || {
        if path.is_null() {
            bail!("inroot_subpath got NULL path");
        }
        let path = unsafe { CStr::from_ptr(path) }.to_str()?;
        root.resolve(Path::new(path))
            .map(CPointer::new)
            .map(Option::Some)
    })
}

fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, Error> {
    if path.is_null() {
        bail!("path argument cannot be NULL");
    }
    let path = unsafe { CStr::from_ptr(path) }.to_str()?;
    let path = Path::new(path);
    Ok(path)
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each inroot_* corresponds to the matching syscall.

// TODO: Replace all the inroot_* stuff with macros. It's quite repetitive.

#[no_mangle]
pub extern "C" fn inroot_creat(
    root: &CRoot,
    path: *const c_char,
    mode: c_uint,
) -> Option<&'static mut CHandle> {
    let mode = mode & !libc::S_IFMT;
    let perm = Permissions::from_mode(mode);

    error::ffi_wrap(None, move || {
        let path = parse_path(path)?;
        root.create_file(path, &perm)
            .map(CPointer::new)
            .map(Option::Some)
    })
}

#[no_mangle]
pub extern "C" fn inroot_mkdir(root: &CRoot, path: *const c_char, mode: c_uint) -> c_int {
    let mode = mode & !libc::S_IFMT;

    inroot_mknod(root, path, libc::S_IFDIR | mode, 0)
}

#[no_mangle]
pub extern "C" fn inroot_mknod(
    root: &CRoot,
    path: *const c_char,
    mode: c_uint,
    dev: dev_t,
) -> c_int {
    let fmt = mode & libc::S_IFMT;
    let perms = Permissions::from_mode(mode & !libc::S_IFMT);

    error::ffi_wrap(-1, move || {
        let path = parse_path(path)?;
        let inode_type = match fmt {
            libc::S_IFREG => InodeType::File(&perms),
            libc::S_IFDIR => InodeType::Directory(&perms),
            libc::S_IFBLK => InodeType::BlockDevice(&perms, dev),
            libc::S_IFCHR => InodeType::CharacterDevice(&perms, dev),
            libc::S_IFIFO => InodeType::Fifo(&perms),
            libc::S_IFSOCK => bail!("S_IFSOCK unsupported"),
            _ => bail!("invalid mode: {:?}", fmt),
        };

        root.create(path, &inode_type)?;
        Ok(0)
    })
}

#[no_mangle]
pub extern "C" fn inroot_symlink(
    root: &CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    error::ffi_wrap(-1, move || {
        let path = parse_path(path)?;
        let target = parse_path(target)?;

        root.create(path, &InodeType::Symlink(target))?;
        Ok(0)
    })
}

#[no_mangle]
pub extern "C" fn inroot_hardlink(
    root: &CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    error::ffi_wrap(-1, move || {
        let path = parse_path(path)?;
        let target = parse_path(target)?;

        root.create(path, &InodeType::Hardlink(target))?;
        Ok(0)
    })
}

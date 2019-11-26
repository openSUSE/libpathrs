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
use libpathrs::{ffi::error, syscalls};
use libpathrs::{Error, Handle, InodeType, OpenFlags, RenameFlags, Resolver, Root};

use std::ffi::{CStr, OsStr};
use std::fs::Permissions;
use std::ops::{Deref, DerefMut};
use std::os::unix::{
    ffi::OsStrExt,
    fs::PermissionsExt,
    io::{AsRawFd, IntoRawFd, RawFd},
};
use std::path::Path;

use failure::Error as FailureError;
use libc::{c_char, c_int, c_uint, c_void, dev_t};

/// This is only exported to work around a Rust compiler restriction. Consider
/// it an implementation detail and don't make use of it.
// Wrapping struct which we can given C a pointer to. &T isn't an option,
// because DSTs (fat pointers) like dyn T (and thus &dyn T) have no FFI-safe
// representation. So we need to hide it within an FFI-safe pointer (such as a
// trivial struct).
pub struct CPointer<T>(T);

// Private trait necessary to work around the "orphan trait" restriction.
trait Pointer<T: ?Sized>: Deref + DerefMut {
    fn new(inner: T) -> &'static mut Self;
    fn free(&mut self);
}

impl<T> Deref for CPointer<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CPointer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// A basic way of having consistent and simple errors when passing NULL
// incorrectly to a libpathrs API call, and freeing it later.
impl<T> Pointer<T> for CPointer<T> {
    // Heap-allocate a new CPointer, but then leak it for C FFI usage.
    fn new(inner: T) -> &'static mut Self {
        Box::leak(Box::new(CPointer(inner)))
    }

    // Take an already-leaked CPointer and un-leak it so we can drop it in Rust.
    fn free(&mut self) {
        unsafe { Box::from_raw(self as *mut Self) }.0;
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
pub type CRoot = CPointer<Root>;

/// A handle to a path within a given Root. This handle references an
/// already-resolved path which can be used for only one purpose -- to "re-open"
/// the handle and get an actual fs::File which can be used for ordinary
/// operations.
///
/// It is critical for the safety of users of this library that *at no point* do
/// you use interfaces like libc::openat directly on file descriptors you get
/// from using this library (or extract the RawFd from a fs::File). You must
/// always use operations through a Root.
pub type CHandle = CPointer<Handle>;

fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, FailureError> {
    if path.is_null() {
        Err(Error::InvalidArgument("path", "cannot be NULL"))?;
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    Ok(OsStr::from_bytes(bytes).as_ref())
}

/// Open a root handle.
///
/// The default resolver is automatically chosen based on the running kernel.
/// You can switch the resolver used with pathrs_set_resolver() -- though this
/// is not strictly recommended unless you have a good reason to do it.
///
/// The provided path must be an existing directory. If using the emulated
/// driver, it also must be the fully-expanded path to a real directory (with no
/// symlink components) because the given path is used to double-check that the
/// open operation was not affected by an attacker.
#[no_mangle]
pub extern "C" fn pathrs_open(path: *const c_char) -> Option<&'static mut CRoot> {
    error::ffi_wrap(None, move || {
        // Leak the box so we can return the pointer to the caller.
        Root::open(parse_path(path)?)
            .map(CPointer::new)
            .map(Option::Some)
    })
}

/// The backend used for path resolution within a pathrs_root_t to get a
/// pathrs_handle_t.
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
pub enum CResolver {
    /// Use the native openat2(2) backend (requires kernel support).
    PATHRS_KERNEL_RESOLVER,
    /// Use the userspace "emulated" backend.
    PATHRS_EMULATED_RESOLVER,
}

impl Into<Resolver> for CResolver {
    fn into(self) -> Resolver {
        match self {
            CResolver::PATHRS_KERNEL_RESOLVER => Resolver::Kernel,
            CResolver::PATHRS_EMULATED_RESOLVER => Resolver::Emulated,
        }
    }
}

/// Switch the resolver for the given root handle.
#[no_mangle]
pub extern "C" fn pathrs_set_resolver(root: &mut CRoot, resolver: CResolver) {
    root.with_resolver(resolver.into());
}

/// The type of object being passed to "object agnostic" libpathrs functions.
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
pub enum CPointerType {
    /// `pathrs_root_t`
    PATHRS_ROOT,
    /// `pathrs_handle_t`
    PATHRS_HANDLE,
}

/// Free a libpathrs object. It is critical that users pass the correct @type --
/// not doing so will certainly trigger memory unsafety bugs.
#[no_mangle]
pub extern "C" fn pathrs_free(ptr_type: CPointerType, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // Both of these casts and dereferences are safe because the C caller has
    // assured us that the type passed is correct.
    match ptr_type {
        CPointerType::PATHRS_ROOT => unsafe { &mut *(ptr as *mut CRoot) }.free(),
        CPointerType::PATHRS_HANDLE => unsafe { &mut *(ptr as *mut CHandle) }.free(),
    }
}

/// "Upgrade" the handle to a usable fd, suitable for reading and writing. This
/// does not consume the original handle (allowing for it to be used many
/// times).
///
/// It should be noted that the use of O_CREAT *is not* supported (and will
/// result in an error). Handles only refer to *existing* files. Instead you
/// need to use inroot_creat().
///
/// In addition, O_NOCTTY is automatically set when opening the path. If you
/// want to use the path as a controlling terminal, you will have to do
/// ioctl(fd, TIOCSCTTY, 0) yourself.
#[no_mangle]
pub extern "C" fn pathrs_reopen(handle: &CHandle, flags: c_int) -> RawFd {
    let flags = OpenFlags(flags);

    error::ffi_wrap(-1, move || {
        let file = handle.0.reopen(flags)?;
        // Rust sets O_CLOEXEC by default, without an opt-out. We need to
        // disable it if we weren't asked to do O_CLOEXEC.
        if flags.0 & libc::O_CLOEXEC == 0 {
            syscalls::fcntl_unset_cloexec(file.as_raw_fd())?;
        }
        Ok(file.into_raw_fd())
    })
}

/// Within the given root's tree, resolve the given path (with all symlinks
/// being scoped to the root) and return a handle to that path. The path *must
/// already exist*, otherwise an error will occur.
#[no_mangle]
pub extern "C" fn pathrs_inroot_resolve(
    root: &CRoot,
    path: *const c_char,
) -> Option<&'static mut CHandle> {
    error::ffi_wrap(None, move || {
        root.resolve(parse_path(path)?)
            .map(CPointer::new)
            .map(Option::Some)
    })
}

/// Within the given root's tree, perform the rename (with all symlinks being
/// scoped to the root). The flags argument is identical to the renameat2(2)
/// flags that are supported on the system.
#[no_mangle]
pub extern "C" fn pathrs_inroot_rename(
    root: &CRoot,
    src: *const c_char,
    dst: *const c_char,
    flags: c_int,
) -> c_int {
    let flags = RenameFlags(flags);

    error::ffi_wrap(-1, move || {
        root.rename(parse_path(src)?, parse_path(dst)?, flags)
            .and(Ok(0))
    })
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each inroot_* corresponds to the matching syscall.

// TODO: Replace all the inroot_* stuff with macros. It's quite repetitive.

#[no_mangle]
pub extern "C" fn pathrs_inroot_creat(
    root: &CRoot,
    path: *const c_char,
    mode: c_uint,
) -> Option<&'static mut CHandle> {
    let mode = mode & !libc::S_IFMT;
    let perm = Permissions::from_mode(mode);

    error::ffi_wrap(None, move || {
        root.create_file(parse_path(path)?, &perm)
            .map(CPointer::new)
            .map(Option::Some)
    })
}

#[no_mangle]
pub extern "C" fn pathrs_inroot_mkdir(root: &CRoot, path: *const c_char, mode: c_uint) -> c_int {
    let mode = mode & !libc::S_IFMT;

    pathrs_inroot_mknod(root, path, libc::S_IFDIR | mode, 0)
}

#[no_mangle]
pub extern "C" fn pathrs_inroot_mknod(
    root: &CRoot,
    path: *const c_char,
    mode: c_uint,
    dev: dev_t,
) -> c_int {
    let fmt = mode & libc::S_IFMT;
    let perms = Permissions::from_mode(mode ^ fmt);

    error::ffi_wrap(-1, move || {
        let path = parse_path(path)?;
        let inode_type = match fmt {
            libc::S_IFREG => InodeType::File(&perms),
            libc::S_IFDIR => InodeType::Directory(&perms),
            libc::S_IFBLK => InodeType::BlockDevice(&perms, dev),
            libc::S_IFCHR => InodeType::CharacterDevice(&perms, dev),
            libc::S_IFIFO => InodeType::Fifo(&perms),
            libc::S_IFSOCK => Err(Error::NotImplemented("mknod(S_IFSOCK)"))?,
            _ => Err(Error::InvalidArgument("mode", "invalid S_IFMT mask"))?,
        };

        root.create(path, &inode_type).and(Ok(0))
    })
}

#[no_mangle]
pub extern "C" fn pathrs_inroot_symlink(
    root: &CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    error::ffi_wrap(-1, move || {
        let path = parse_path(path)?;
        let target = parse_path(target)?;

        root.create(path, &InodeType::Symlink(target)).and(Ok(0))
    })
}

#[no_mangle]
pub extern "C" fn pathrs_inroot_hardlink(
    root: &CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    error::ffi_wrap(-1, move || {
        let path = parse_path(path)?;
        let target = parse_path(target)?;

        root.create(path, &InodeType::Hardlink(target)).and(Ok(0))
    })
}

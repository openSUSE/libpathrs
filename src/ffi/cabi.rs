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
use libpathrs::{CreateOpts, Handle, InoType, Root};
use libpathrs::ffi::error;

use std::fs::{OpenOptions, Permissions};
use std::os::unix::{io::AsRawFd, fs::{OpenOptionsExt, PermissionsExt}};
use std::ffi::CStr;
use std::path::Path;

use failure::Error;
use libc::{c_char, c_int, c_uint, dev_t};

/// A variation of *mut T which is more usable than dealing with ptr::null_mut()
/// which appears to really hate trait objects. By using an Option<&mut T>, Rust
/// makes None be equivalent to C's NULL -- with the ref value just being an
/// opaque pointer value.
type CPtr<T> = Option<&'static mut T>;

// Private trait necessary to work around the "orphan trait" restriction.
trait Check<T: ?Sized> {
    type Inner;
    fn check(self) -> Result<Self::Inner, Error>;
}


// A basic way of having consistent and simple errors when passing NULL
// incorrectly to a libpathrs API call.
impl<T: ?Sized> Check<T> for CPtr<T> {
    type Inner = &'static mut T;

    fn check(self) -> Result<Self::Inner, Error> {
        self.ok_or(format_err!("invalid libpathrs handle -- must not be NULL"))
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
pub type CRoot = CPtr<dyn Root>;

/// A handle to a path within a given Root. This handle references an
/// already-resolved path which can be used for only one purpose -- to "re-open"
/// the handle and get an actual fs::File which can be used for ordinary
/// operations.
///
/// It is critical for the safety of users of this library that *at no point* do
/// you use interfaces like libc::openat directly on file descriptors you get
/// from using this library (or extract the RawFd from a fs::File). You must
/// always use operations through a Root.
pub type CHandle = CPtr<dyn Handle>;

/// Open a root handle. The correct backend (native/kernel or emulated) to use
/// is auto-detected based on whether the kernel supports openat2(2).
///
/// The provided path must be an existing directory. If using the emulated
/// driver, it also must be the fully-expanded path to a real directory (with no
/// symlink components) because the given path is used to double-check that the
/// open operation was not affected by an attacker.
#[no_mangle]
pub extern "C" fn pathrs_open(path: *const c_char) -> CRoot {
    error::ffi_wrap(None, move || {
        if path.is_null() {
            bail!("pathrs_open got NULL path");
        }
        let path = unsafe { CStr::from_ptr(path) }.to_str()?;

        // Leak the box so we can return the pointer to the caller.
        libpathrs::open(Path::new(path)).map(Box::leak).map(|h| Some(h))
    })
}

/// Free a root handle.
#[no_mangle]
pub extern "C" fn pathrs_rfree(root: CRoot) {
    root.map(|r| unsafe { Box::from_raw(r as *mut dyn Root) });
    // drop the handle
}


/// "Upgrade" the handle to a usable fd, suitable for reading and writing. This
/// does not consume the original handle (allowing for it to be used many
/// times).
///
/// It should be noted that the use of O_CREAT *is not* supported (and will
/// result in an error). Handles only refer to *existing* files. Instead you
/// need to use inroot_creat().
#[no_mangle]
pub extern "C" fn handle_reopen(handle: CHandle, flags: c_int, mode: c_uint) -> c_int {
    error::ffi_wrap(-1, move || {
        let handle = handle.check()?;

        // Construct options from the C-style flags. Due to weird restrictions
        // with OpenOptions we need to manually set the O_ACCMODE bits.
        let mut options = OpenOptions::new();
        handle.reopen(match flags & libc::O_ACCMODE {
            libc::O_RDONLY => options.read(true),
            libc::O_WRONLY => options.write(true),
            libc::O_RDWR   => options.read(true).write(true),
            _              => bail!("invalid flags to reopen: {:?}", flags),
        }.custom_flags(flags).mode(mode)).map(|f| f.as_raw_fd())
    })
}

/// Free a handle.
#[no_mangle]
pub extern "C" fn pathrs_hfree(handle: CHandle) {
    handle.map(|h| unsafe { Box::from_raw(h as *mut dyn Handle) });
    // drop the handle
}

/// Within the given root's tree, resolve the given path (with all symlinks
/// being scoped to the root) and return a handle to that path. The path *must
/// already exist*, otherwise an error will occur.
#[no_mangle]
pub extern "C" fn inroot_resolve(root: CRoot, path: *const c_char) -> CHandle {
    error::ffi_wrap(None, move || {
        let root = root.check()?;

        if path.is_null() {
            bail!("inroot_subpath got NULL path");
        }
        let path = unsafe { CStr::from_ptr(path) }.to_str()?;
        root.resolve(Path::new(path)).map(|h| Some(Box::leak(h)))
    })
}

fn _inroot_create(root: CRoot, path: *const c_char, opts: &CreateOpts) -> Result<CHandle, Error> {
    let root = root.check()?;

    if path.is_null() {
        bail!("inroot_subpath got NULL path");
    }
    let path = unsafe { CStr::from_ptr(path) }.to_str()?;

    root.create(Path::new(path), opts).map(|h| Some(Box::leak(h)))
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each inroot_* corresponds to the matching syscall.

// TODO: Replace all the inroot_* stuff with macros. It's quite repetitive.

#[no_mangle]
pub extern "C" fn inroot_creat(root: CRoot, path: *const c_char, mode: c_uint)
    -> CHandle {
    error::ffi_wrap(None, move || {
        _inroot_create(root, path, &CreateOpts{
            typ: InoType::File(),
            mode: Permissions::from_mode(mode),
        })
    })
}

#[no_mangle]
pub extern "C" fn inroot_mkdir(root: CRoot, path: *const c_char, mode: c_uint)
    -> CHandle {
    error::ffi_wrap(None, move || {
        _inroot_create(root, path, &CreateOpts{
            typ: InoType::Directory(),
            mode: Permissions::from_mode(mode),
        })
    })
}

#[no_mangle]
pub extern "C" fn inroot_mknod(root: CRoot, path: *const c_char, mode: c_uint,
                           dev: dev_t) -> CHandle {
    error::ffi_wrap(None, move || {
        let typ = match mode & libc::S_IFMT {
            libc::S_IFREG  => InoType::File(),
            libc::S_IFDIR  => InoType::Directory(),
            libc::S_IFBLK  => InoType::Block(dev),
            libc::S_IFCHR  => InoType::Character(dev),
            libc::S_IFSOCK => bail!("S_IFSOCK unsupported"),
            libc::S_IFIFO  => InoType::Fifo(),
            fmt @ _        => bail!("invalid mode: {:?}", fmt),
        };
        _inroot_create(root, path, &CreateOpts{
            typ: typ,
            mode: Permissions::from_mode(mode),
        })
    })
}

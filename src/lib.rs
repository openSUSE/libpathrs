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

//! libpathrs provides a series of primitives for GNU/Linux programs to safely
//! handle the opening of paths inside an untrusted directory tree. The idea is
//! that a libpathrs::Root handle is like a handle for resolution inside a
//! chroot(2), with libpathrs::Handle being an O_PATH descriptor which you can
//! "upgrade" to a proper std::fs::File. However this library acts far more
//! efficiently than spawning a new process and doing a full chroot(2) for every
//! operation.
//!
//! In order to ensure the maximum possible number of people can make us of this
//! library to increase the overall security of Linux tooling, it is written in
//! Rust (to be memory-safe) and produces C dylibs for usage with any language
//! that supports C-based FFI.
//!
//! The recommended usage of libpathrs looks something like this (in Rust):
//!
//! ```
//! use std::fs::OpenOptions;
//! use std::path::Path;
//!
//! // Get a root handle for resolution.
//! let root = libpathrs::open(Path::new("/path/to/root"))?;
//! // Resolve the path.
//! let handle = root.resolve(Path::new("/etc/passwd"))?;
//! // Upgrade the handle to a full std::fs::File.
//! let file = handle.reopen(OpenOptions::new().read(true))?;
//!
//! // Or, in one line:
//! let file = root.resolve(Path::new("/etc/passwd"))?
//!                .reopen(OpenOptions::new().read(true))?;
//!
//! ```

#[macro_use] extern crate lazy_static;
extern crate errno;
#[macro_use] extern crate failure;
extern crate libc;

mod ffi;
mod user;
mod kernel;

use std::fs::{File, Permissions, OpenOptions};
use std::path::Path;

use libc::dev_t;
use failure::Error;

lazy_static! {
    static ref KERNEL_SUPPORT: bool = kernel::supported();
}

/// Represents a "thing" being created through Handle::create(). This is mainly
/// to aid in usability, since almost all of the operations required to actually
/// create each type are fundamentally different when it comes to kernel APIs.
pub enum InoType<'a> {
    /// File.
    File(),

    /// Directory.
    Directory(),

    /// Symlink with the given str contents (symlinks don't have special
    /// resolution properties, so the string provided here is just passed
    /// directly to symlinkat(2) without any cleaning or sanitisation).
    Symlink(&'a str),

    /// Hard-link to the given Path (which will be internally resolved inside
    /// the handle). If you wish to hardlink a file inside the Handle's tree to
    /// a file outside the Handle's tree, this is currently unsupported.
    // XXX: Should we ever support that?
    Hardlink(&'a Path),

    /// FIFO.
    Fifo(),

    /// Character device.
    Character(dev_t),

    /// Block device.
    Block(dev_t),

    //// Unix socket. Note that this will be a "detached" socket and not
    //// bound to by anyone. This purely exists to provide a safe mknod(S_IFSOCK)
    //// implementation.
    // TODO: See if we can even do bind(2) safely for a Socket() type.
    //DetachedSocket(),
}

/// Encapsulates all of the generic options required to create a file.
pub struct CreateOpts<'a> {
    pub typ: InoType<'a>,
    pub mode: Permissions,
}

/// A handle to a path within a given Root. This handle references an
/// already-resolved path which can be used for only one purpose -- to "re-open"
/// the handle and get an actual fs::File which can be used for ordinary
/// operations.
///
/// It is critical for the safety of users of this library that *at no point* do
/// you use interfaces like libc::openat directly on file descriptors you get
/// from using this library (or extract the RawFd from a fs::File). You must
/// always use operations through a Root.
pub trait Handle: Drop {
    /// "Upgrade" the handle to a usable std::fs::File handle suitable for
    /// reading and writing. This does not consume the original handle (allowing
    /// for it to be used many times).
    ///
    /// It should be noted that the use of O_CREAT *is not* supported (and will
    /// result in an error). Handles only refer to *existing* files. Instead you
    /// need to use Root::create().
    ///
    /// It is recommended to `use` std::os::unix::fs::OpenOptionsExt and
    /// std::os::unix::fs::PermissionsExt.
    fn reopen(&self, opts: &OpenOptions) -> Result<File, Error>;
}

/// A handle to the root of a directory tree to resolve within. The only purpose
/// of this "root handle" is to get Handles to inodes within the directory tree.
///
/// At the time of writing, it is considered a *VERY BAD IDEA* to open a Root
/// inside a possibly-attacker-controlled directory tree. While we do have
/// protections that should defend against it (for both drivers), it's far more
/// dangerous than just opening a directory tree which is not inside a
/// potentially-untrusted directory.
pub trait Root: Drop {
    /// Within the given Root's tree, resolve the given Path (with all symlinks
    /// being scoped to the Root) and return a handle to that path. The path
    /// *must already exist*, otherwise an error will occur.
    fn resolve(&self, path: &Path) -> Result<Box<dyn Handle>, Error>;

    /// Within the Root's tree, create an inode at the Path as specified by
    /// CreateOpts. If the path already exists, an error is returned
    /// (effectively acting as though O_EXCL is always set).
    fn create(&self, path: &Path, opts: &CreateOpts) -> Result<Box<dyn Handle>, Error>;
}

/// Open a Root handle. The correct backend (native/kernel or emulated) to use
/// is auto-detected based on whether the kernel supports openat2(2).
///
/// The provided Path must be an existing directory. If using the emulated
/// driver, it also must be the fully-expanded path to a real directory (with no
/// symlink components) because the given Path is used to double-check that the
/// open operation was not affected by an attacker.
// TODO: We really need to provide a dirfd as a source, though the main problem
//       here is that it's unclear what the "correct" path is for the emulated
//       backend to check against. We could just read the dirfd but now we have
//       more races to deal with. We could ask the user to provide a backup
//       path to check against, but then why not just use that path in the
//       first place?
pub fn open(path: &Path) -> Result<Box<dyn Root>, Error> {
    if path.is_relative() {
        bail!("libpathrs: cannot open non-absolute root path: {}", path.to_str().unwrap());
    }
    match *KERNEL_SUPPORT {
        true  => kernel::open(path),
        false => user::open(path),
    }
}

impl Root {
    // TODO: mkdir_all()
}

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

//! libpathrs provides a series of primitives for Linux programs to safely
//! handle path operations inside an untrusted directory tree.
//!
//! The idea is that a [`Root`] handle is like a handle for resolution inside a
//! [`chroot(2)`], with [`Handle`] being an `O_PATH` descriptor which you can
//! "upgrade" to a proper [`File`]. However this library acts far more
//! efficiently than spawning a new process and doing a full [`chroot(2)`] for
//! every operation.
//!
//! In order to ensure the maximum possible number of people can make us of this
//! library to increase the overall security of Linux tooling, it is written in
//! Rust (to be memory-safe) and produces C dylibs for usage with any language
//! that supports C-based FFI.
//!
//! # Assumptions
//!
//! This library assumes that the kernel supports all of the needed features for
//! at least one libpathrs backend. At time of writing, those are:
//!
//! * `renameat2` support, or privileges to do `pivot_root`.
//! * Native Backend:
//!   - `openat2` support.
//! * Emulated Backend:
//!   - A working `/proc` mount, such that `/proc/self/fd/` operates correctly.
//!
//! # Examples
//!
//! The recommended usage of libpathrs looks something like this:
//!
//! ```
//! # use std::error::Error;
//! use std::fs::OpenOptions;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), FailureError> {
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
//! # Ok(())
//! # }
//! ```
//!
//! The corresponding C example would be:
//!
//! ```c
//! int get_my_fd(void)
//! {
//!     int fd = -1, errlen;
//!     char *error = NULL;
//!     pathrs_root_t *root = NULL;
//!     pathrs_handle_t *handle = NULL;
//!
//!     root = pathrs_open("/path/to/root");
//!     if (!root)
//!         goto err;
//!
//!     handle = inroot_resolve(root, "/etc/passwd");
//!     if (!handle)
//!         goto err;
//!
//!     fd = handle_reopen(handle, O_RDONLY);
//!     if (fd < 0)
//!         goto err;
//!
//!     goto out;
//!
//! err:
//!     errlen = pathrs_error_length();
//!     error = malloc(errlen);
//!     if (!error)
//!         abort();
//!     pathrs_error(error, errlen);
//!     fprintf(stderr, "got error: %s\n", error);
//!     free(error);
//!
//! out:
//!     pathrs_hfree(handle);
//!     pathrs_rfree(root);
//!     return fd;
//! }
//! ```
//!
//! [`Root`]: trait.Root.html
//! [`Handle`]: trait.Handle.html
//! [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
//! [`chroot(2)`]: http://man7.org/linux/man-pages/man2/chroot.2.html

#[macro_use]
extern crate lazy_static;
extern crate errno;
#[macro_use]
extern crate failure;
extern crate libc;

mod handle;
pub use handle::Handle;

mod ffi;
// TODO: We should expose user::open and kernel::open so that people can
//       explicitly decide to use a different backend if they *really* want to.
mod kernel;
mod user;

use core::convert::TryFrom;
use std::ffi::CString;
use std::fs::Permissions;
use std::io::Error as IOError;
use std::os::unix::{
    fs::PermissionsExt,
    io::{AsRawFd, RawFd},
};
use std::path::Path;

use failure::{Error as FailureError, ResultExt};
use libc::dev_t;

lazy_static! {
    static ref KERNEL_SUPPORT: bool = kernel::supported();
}

/// The underlying [`cause`] of the [`failure::Error`] type returned by
/// libpathrs.
///
/// [`cause`]: https://docs.rs/failure/*/failure/struct.Error.html#method.cause
/// [`failure::Error`]: https://docs.rs/failure/*/failure/struct.Error.html
#[derive(Fail, Debug)]
pub enum Error {
    /// The requested feature is not yet implemented.
    #[fail(display = "feature not yet implemented: {}", _0)]
    NotImplemented(&'static str),

    /// One of the provided arguments in invalid. The returned tuple is
    /// (argument name, description of error).
    #[fail(display = "invalid {} argument: {}", _0, _1)]
    InvalidArgument(&'static str, &'static str),

    /// Returned whenever libpathrs has detected some form of safety requirement
    /// violation. This might be an attempted breakout by an attacker or even a
    /// bug internal to libpathrs.
    #[fail(display = "violation of safety requirement: {}", _0)]
    SafetyViolation(&'static str),

    /// An [`io::Error`] was encountered during the operation.
    ///
    /// [`io::Error`]: https://doc.rust-lang.org/std/io/struct.Error.html
    #[fail(display = "os error: {}", _0)]
    OsError(#[fail(cause)] IOError),
}

/// An inode type to be created with [`Root::create`].
///
/// [`Root::create`]: trait.Root.html#method.create
pub enum InodeType<'a> {
    /// Ordinary file, as in [`creat(2)`].
    ///
    /// [`creat(2)`]: http://man7.org/linux/man-pages/man2/creat.2.html
    // XXX: It is possible to support non-O_EXCL O_CREAT with the native
    //      backend. But it's unclear whether we should expose it given it's
    //      only supported on native-kernel systems.
    File(&'a Permissions),

    /// Directory, as in [`mkdir(2)`].
    ///
    /// [`mkdir(2)`]: http://man7.org/linux/man-pages/man2/mkdir.2.html
    Directory(&'a Permissions),

    /// Symlink with the given [`Path`], as in [`symlinkat(2)`].
    ///
    /// Note that symlinks can contain any arbitrary [`CStr`]-style string (it
    /// doesn't need to be a real pathname). We don't do any verification of the
    /// target name.
    ///
    /// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
    /// [`symlinkat(2)`]: http://man7.org/linux/man-pages/man2/symlinkat.2.html
    Symlink(&'a Path),

    /// Hard-link to the given [`Path`], as in [`linkat(2)`].
    ///
    /// The provided [`Path`] is resolved within the [`Root`]. It is currently
    /// not supported to hardlink a file inside the [`Root`]'s tree to a file
    /// outside the [`Root`]'s tree.
    ///
    /// [`linkat(2)`]: http://man7.org/linux/man-pages/man2/linkat.2.html
    /// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
    /// [`Root`]: trait.Root.html
    // XXX: Should we ever support that?
    Hardlink(&'a Path),

    /// Named pipe (aka FIFO), as in [`mkfifo(3)`].
    ///
    /// [`mkfifo(3)`]: http://man7.org/linux/man-pages/man3/mkfifo.3.html
    Fifo(&'a Permissions),

    /// Character device, as in [`mknod(2)`] with `S_IFCHR`.
    ///
    /// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    CharacterDevice(&'a Permissions, dev_t),

    /// Block device, as in [`mknod(2)`] with `S_IFBLK`.
    ///
    /// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    BlockDevice(&'a Permissions, dev_t),
    //// "Detached" unix socket, as in [`mknod(2)`] with `S_IFSOCK`.
    ////
    //// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    // TODO: In principle we could do this safely by doing the `mknod` and then See if we can even do bind(2) safely for a Socket() type.
    //DetachedSocket(),
}

/// Helper to split a Path into its parent directory and trailing path. The
/// trailing component is guaranteed to not contain a directory separator.
fn path_split<'p>(path: &'p Path) -> Result<(&'p Path, &'p str), FailureError> {
    let parent = path.parent().unwrap_or("/".as_ref());

    // Now construct the trailing portion of the target.
    let name = path
        .file_name()
        .ok_or(Error::InvalidArgument("path", "no trailing component"))?
        .to_str()
        .ok_or(Error::InvalidArgument("path", "not a valid Rust string"))?;

    // It's critical we are only touching the final component in the path.
    // If there are any other path components we must bail.
    if name.contains(std::path::MAIN_SEPARATOR) {
        return Err(Error::SafetyViolation(
            "trailing component of pathname contains '/'",
        ))?;
    }
    Ok((parent, name))
}

/// A handle to the root of a directory tree.
///
/// # Safety
///
/// At the time of writing, it is considered a **very bad idea** to open a
/// [`Root`] inside a possibly-attacker-controlled directory tree. While we do
/// have protections that should defend against it (for both drivers), it's far
/// more dangerous than just opening a directory tree which is not inside a
/// potentially-untrusted directory.
///
/// # Errors
///
/// If at any point an attack is detected during the execution of a [`Root`]
/// method, an error will be returned. The method of attack detection is
/// multi-layered and operates through explicit `/proc/self/fd` checks as well
/// as (in the case of the native backend) kernel-space checks that will trigger
/// `-EXDEV` in certain attack scenarios.
///
/// [`Root`]: trait.Root.html
pub trait Root: Drop {
    /// Within the given [`Root`]'s tree, resolve `path` and return a
    /// [`Handle`]. All symlink path components are scoped to [`Root`].
    ///
    /// # Errors
    ///
    /// If `path` doesn't exist, or an attack was detected during resolution, a
    /// corresponding Error will be returned. If no error is returned, then the
    /// path is guaranteed to have been reachable from the root of the directory
    /// tree and thus have been inside the root at one point in the resolution.
    ///
    /// [`Root`]: trait.Root.html
    /// [`Handle`]: trait.Handle.html
    fn resolve(&self, path: &Path) -> Result<Handle, FailureError>;
}

impl Root {
    /// Within the [`Root`]'s tree, create an inode at `path` as specified by
    /// `inode_type`.
    ///
    /// # Errors
    ///
    /// If the path already exists (regardless of the type of the existing
    /// inode), an error is returned.
    ///
    /// [`Root`]: trait.Root.html
    pub fn create<P: AsRef<Path>>(
        &self,
        path: P,
        inode_type: &InodeType,
    ) -> Result<(), FailureError> {
        // Use create_file if that's the inode_type. We drop the File returned
        // (it was free to create anyway because we used openat(2)).
        if let InodeType::File(perm) = inode_type {
            return self.create_file(path, perm).map(|_| ());
        }

        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) = path_split(path.as_ref())
            .context("split path into (parent, name) for inode creation")?;
        let dirfd = self
            .resolve(parent)
            .context("resolve parent directory for inode creation")?
            .as_raw_fd();
        let name = CString::new(name)
            .context("convert name into CString for FFI")?
            .as_ptr();

        let ret = match inode_type {
            InodeType::File(_) => unreachable!(), /* we dealt with this above */
            InodeType::Directory(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mkdirat(dirfd, name, mode) }
            }
            InodeType::Symlink(target) => {
                let target = target
                    .to_str()
                    .ok_or(Error::InvalidArgument("target", "not a valid Rust string"))?;
                let target = CString::new(target)?.as_ptr();
                unsafe { libc::symlinkat(target, dirfd, name) }
            }
            InodeType::Hardlink(target) => {
                let oldfd = self
                    .resolve(target)
                    .context("resolve target path for hardlink")?
                    .as_raw_fd();
                let empty_path = CString::new("")?.as_ptr();
                unsafe { libc::linkat(oldfd, empty_path, dirfd, name, libc::AT_EMPTY_PATH) }
            }
            InodeType::Fifo(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mknodat(dirfd, name, libc::S_IFIFO | mode, 0) }
            }
            InodeType::CharacterDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mknodat(dirfd, name, libc::S_IFCHR | mode, *dev) }
            }
            InodeType::BlockDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mknodat(dirfd, name, libc::S_IFBLK | mode, *dev) }
            }
        };
        let err = errno::errno().into();

        if ret.is_negative() {
            return Err(Error::OsError(err)).context("root inode create failed")?;
        }
        Ok(())
    }

    /// Create an [`InodeType::File`] within the [`Root`]'s tree at `path` with
    /// the mode given by `perm`, and return a [`Handle`] to the newly-created
    /// file.
    ///
    /// However, unlike the trivial way of doing the above:
    ///
    /// ```
    /// root.create(path, inode_type)?;
    /// // What happens if the file is replaced here!?
    /// let handle = root.resolve(path, perm)?;
    /// ```
    ///
    /// [`Root::create_file`] guarantees that the returned [`Handle`] is the
    /// same as the file created by the operation. This is only possible to
    /// guarantee for ordinary files because there is no [`O_CREAT`]-equivalent
    /// for other inode types.
    ///
    /// # Errors
    ///
    /// Identical to [`Root::create`].
    ///
    /// [`Root`]: trait.Root.html
    /// [`Handle`]: trait.Handle.html
    /// [`Root::create`]: trait.Root.html#method.create
    /// [`Root::create_file`]: trait.Root.html#method.create_file
    /// [`InodeType::File`]: enum.InodeType.html#variant.File
    /// [`O_CREAT`]: http://man7.org/linux/man-pages/man2/open.2.html
    pub fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Handle, FailureError> {
        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) = path_split(path.as_ref())
            .context("split path into (parent, name) for inode creation")?;
        let dirfd = self
            .resolve(parent)
            .context("resolve parent directory for inode creation")?
            .as_raw_fd();
        let name = CString::new(name)
            .context("convert name into CString for FFI")?
            .as_ptr();

        let fd: RawFd = unsafe {
            libc::openat(
                dirfd,
                name,
                libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                perm.mode(),
            )
        };
        let err = errno::errno().into();

        if fd.is_negative() {
            return Err(Error::OsError(err)).context("root file create failed")?;
        }
        Ok(Handle::try_from(fd).context("convert O_CREAT fd to Handle")?)
    }

    /// Within the [`Root`]'s tree, remove the inode at `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist or is a non-empty directory, an error will be
    /// returned. In order to remove a non-empty directory, please use
    /// [`Root::remove_all`].
    ///
    /// [`Root`]: trait.Root.html
    /// [`Handle`]: trait.Handle.html
    /// [`Root::remove_all`]: trait.Root.html#method.remove_all
    pub fn remove<P: AsRef<Path>>(&self, path: P) -> Result<(), FailureError> {
        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) = path_split(path.as_ref())?;
        let dirfd = self.resolve(parent)?.as_raw_fd();
        let name = CString::new(name)?.as_ptr();

        // TODO: Handle the lovely "is it a directory or file" problem.
        let ret = unsafe { libc::unlinkat(dirfd, name, 0) };
        let err = errno::errno().into();

        if ret.is_negative() {
            return Err(Error::OsError(err)).context("root inode remove failed")?;
        }
        Ok(())
    }

    // TODO: mkdir_all()
    // TODO: remove_all()
}

/// Open a [`Root`] handle using the best backend available.
///
/// The correct backend (native or emulated) to use is auto-detected based on
/// whether the kernel supports `openat2(2)`.
///
/// # Errors
///
/// `path` must be an existing directory inside the [`Root`].
///
/// If using the emulated driver, `path` must also be the fully-expanded path to
/// a real directory (in order words, not contain any symlink components). The
/// reason for this is because `path` is used to double-check that the open
/// operation was not affected by an attacker.
///
/// [`Root`]: trait.Root.html
// TODO: We really need to provide a dirfd as a source, though the main problem
//       here is that it's unclear what the "correct" path is for the emulated
//       backend to check against. We could just read the dirfd but now we have
//       more races to deal with. We could ask the user to provide a backup
//       path to check against, but then why not just use that path in the
//       first place?
pub fn open(path: &Path) -> Result<Box<dyn Root>, FailureError> {
    if path.is_relative() {
        return Err(Error::InvalidArgument("path", "must be an absolute path"))
            .context("open root handle")?;
    }
    Ok(match *KERNEL_SUPPORT {
        true => kernel::open(path)?,
        false => user::open(path)?,
    })
}

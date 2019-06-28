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
//! # fn main() -> Result<(), Error> {
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
//!     int fd = -1;
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
//!     error = malloc(pathrs_error_length());
//!     if (!error)
//!         abort();
//!     pathrs_error(error, sizeof(error));
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

mod ffi;
// TODO: We should expose user::open and kernel::open so that people can
//       explicitly decide to use a different backend if they *really* want to.
mod kernel;
mod user;

use std::fs::{File, OpenOptions, Permissions};
use std::path::Path;

use failure::Error;
use libc::dev_t;

lazy_static! {
    static ref KERNEL_SUPPORT: bool = kernel::supported();
}

/// An inode type to be created with [`Root::create`].
///
/// [`Root::create`]: trait.Root.html#tymethod.create
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

/// A handle to an existing inode within a [`Root`].
///
/// This handle references an already-resolved path which can be used for the
/// purpose of "re-opening" the handle and get an actual [`File`] which can be
/// used for ordinary operations.
///
/// # Safety
///
/// It is critical for the safety of this library that **at no point** do you
/// use interfaces like [`libc::openat`] directly on any [`RawFd`]s you might
/// extract from the [`File`] you get from this [`Handle`]. **You must always do
/// operations through a valid [`Root`].**
///
/// [`Root`]: trait.Root.html
/// [`Handle`]: trait.Handle.html
/// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
/// [`RawFd`]: https://doc.rust-lang.org/std/os/unix/io/type.RawFd.html
/// [`libc::openat`]: https://docs.rs/libc/latest/libc/fn.openat.html
pub trait Handle: Drop {
    /// "Upgrade" the handle to a usable [`File`] handle suitable for reading
    /// and writing, as though the file was opened with `OpenOptions`.
    ///
    /// This does not consume the original handle (allowing for it to be used
    /// many times). It is recommended to `use` [`OpenOptionsExt`].
    ///
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    /// [`OpenOptions`]: https://doc.rust-lang.org/std/fs/struct.OpenOptions.html
    /// [`Root::create`]: trait.Root.html#tymethod.create
    /// [`OpenOptionsExt`]: https://doc.rust-lang.org/std/os/unix/fs/trait.OpenOptionsExt.html
    fn reopen(&self, options: &OpenOptions) -> Result<File, Error>;
}

impl Handle {
    // TODO: bind(). This might be safe to do (set the socket path to
    //       /proc/self/fd/...) but I'm a bit sad it'd be separate from
    //       Handle::reopen().
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
    fn resolve(&self, path: &Path) -> Result<Box<dyn Handle>, Error>;

    /// Within the [`Root`]'s tree, create an inode at `path` as specified by
    /// `inode_type`.
    ///
    /// # Errors
    ///
    /// If the path already exists (regardless of the type of the existing
    /// inode), an error is returned.
    ///
    /// [`Root`]: trait.Root.html
    fn create(&self, path: &Path, inode_type: &InodeType) -> Result<(), Error>;

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
    /// [`Root::create`]: trait.Root.html#tymethod.create
    /// [`Root::create_file`]: trait.Root.html#tymethod.create_file
    /// [`InodeType::File`]: enum.InodeType.html#variant.File
    /// [`O_CREAT`]: http://man7.org/linux/man-pages/man2/open.2.html
    fn create_file(&self, path: &Path, perm: &Permissions) -> Result<Box<dyn Handle>, Error>;

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
    /// [`Root::remove_all`]: trait.Root.html#tymethod.remove_all
    fn remove(&self, path: &Path) -> Result<(), Error>;
}

impl Root {
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
pub fn open(path: &Path) -> Result<Box<dyn Root>, Error> {
    if path.is_relative() {
        bail!(
            "libpathrs: cannot open non-absolute root path: {}",
            path.to_str().unwrap()
        );
    }
    match *KERNEL_SUPPORT {
        true => kernel::open(path),
        false => user::open(path),
    }
}

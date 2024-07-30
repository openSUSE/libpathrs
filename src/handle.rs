/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

#![forbid(unsafe_code)]

use crate::{
    error::{Error, ErrorExt},
    flags::OpenFlags,
    procfs::PROCFS_HANDLE,
    utils::RawFdExt,
};

use std::fs::File;

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
/// [`Root`]: struct.Root.html
/// [`Handle`]: trait.Handle.html
/// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
/// [`RawFd`]: https://doc.rust-lang.org/std/os/unix/io/type.RawFd.html
/// [`libc::openat`]: https://docs.rs/libc/latest/libc/fn.openat.html
#[derive(Debug)]
pub struct Handle {
    inner: File,
}

impl Handle {
    /// "Upgrade" the handle to a usable [`File`] handle.
    ///
    /// This new [`File`] handle is suitable for reading and writing. This does
    /// not consume the original handle (allowing for it to be used many times).
    ///
    /// The [`File`] handle will be opened with `O_NOCTTY` and `O_CLOEXEC` set,
    /// regardless of whether those flags are present in the `flags` argument.
    /// You can correct these yourself if these defaults are not ideal for you:
    ///
    /// 1. `fcntl(fd, F_SETFD, 0)` will let you unset `O_CLOEXEC`.
    /// 2. `ioctl(fd, TIOCSCTTY, 0)` will set the fd as the controlling
    ///    terminal (if you don't have one already, and the fd references a
    ///    TTY).
    ///
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    /// [`Root::create`]: struct.Root.html#method.create
    pub fn reopen<F: Into<OpenFlags>>(&self, flags: F) -> Result<File, Error> {
        self.inner.reopen(&PROCFS_HANDLE, flags.into())
    }

    /// Create a copy of an existing [`Handle`].
    ///
    /// The new handle is completely independent from the original, but
    /// references the same underlying file.
    ///
    /// [`Handle`]: struct.Handle.html
    pub fn try_clone(&self) -> Result<Self, Error> {
        self.inner
            .try_clone_hotfix()
            .map(Self::from_file_unchecked)
            .wrap("clone underlying handle file")
    }

    /// Unwrap a [`Handle`] to reveal the underlying [`File`].
    ///
    /// **Note**: This method is primarily intended to allow for file descriptor
    /// passing or otherwise transmitting file descriptor information. If you
    /// want to get a [`File`] handle for general use, please use
    /// [`Handle::reopen`] instead.
    ///
    /// [`Handle`]: struct.Handle.html
    /// [`Handle::reopen`]: struct.Handle.html#method.reopen
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    pub fn into_file(self) -> File {
        self.inner
    }

    /// Access the underlying [`File`] for a [`Handle`].
    ///
    /// **Note**: This method is primarily intended to allow for tests and other
    /// code to check the status of the underlying [`File`] without having to
    /// use [`Handle::into_file`]. If you want to get a [`File`] handle for
    /// general use, please use [`Handle::reopen`] instead.
    ///
    /// [`Handle`]: struct.Handle.html
    /// [`Handle::into_file`]: struct.Handle.html#method.into_file
    /// [`Handle::reopen`]: struct.Handle.html#method.reopen
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    pub fn as_file(&self) -> &File {
        &self.inner
    }

    /// Wrap a [`File`] into a [`Handle`].
    ///
    /// # Safety
    ///
    /// The caller guarantees that the provided file is an `O_PATH` file
    /// descriptor with exactly the same semantics as one created through
    /// [`Root::resolve`]. This means that this function should usually be used
    /// to convert a [`File`] returned from [`Handle::into_file`] (possibly from
    /// another process) into a [`Handle`].
    ///
    /// While this function is not marked as `unsafe` (because the safety
    /// guarantee required is not related to memory-safety), users should still
    /// take great care when using this method because it can cause other kinds
    /// of unsafety.
    ///
    /// [`Handle`]: struct.Handle.html
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    /// [`Root::resolve`]: struct.Root.html#method.resolve
    /// [`Handle::into_file`]: struct.Handle.html#method.into_file
    pub fn from_file_unchecked(inner: File) -> Self {
        Self { inner }
    }

    // TODO: All the different stat* interfaces?

    // TODO: bind(). This might be safe to do (set the socket path to
    //       /proc/self/fd/...) but I'm a bit sad it'd be separate from
    //       Handle::reopen().
}

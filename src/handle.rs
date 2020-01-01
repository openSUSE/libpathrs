/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019, 2020 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019, 2020 SUSE LLC
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
    error::Error,
    utils::{FileExt, RawFdExt},
};

use std::fs::File;

use libc::c_int;

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
    pub(crate) inner: File,
}

/// Wrapper for the underlying `libc`'s `O_*` flags.
///
/// The flag values and their meaning is identical to the description in the
/// `open(2)` man page.
///
/// # Caveats
///
/// For historical reasons, the first three bits of `open(2)`'s flags are for
/// the access mode and are actually treated as a 2-bit number. So, it is
/// incorrect to attempt to do any checks on the access mode without masking it
/// correctly. So some helpers were added to make usage more ergonomic.
// TODO: Should probably be a u64, and use a constructor...
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFlags(pub c_int);

impl From<c_int> for OpenFlags {
    fn from(flags: c_int) -> Self {
        Self(flags)
    }
}

impl OpenFlags {
    /// Grab the access mode bits from the flags.
    #[inline]
    pub fn access_mode(&self) -> c_int {
        self.0 & libc::O_ACCMODE
    }

    /// Does the access mode imply read access?
    #[inline]
    pub fn wants_read(&self) -> bool {
        let acc = self.access_mode();
        acc == libc::O_RDONLY || acc == libc::O_RDWR
    }

    /// Does the access mode imply write access? Note that there are several
    /// other bits (such as `O_TRUNC`) which imply write access but are not part
    /// of the access mode, and thus a `false` value from `.wants_write()` does
    /// not guarantee that the kernel will not do a `MAY_WRITE` check.
    #[inline]
    pub fn wants_write(&self) -> bool {
        let acc = self.access_mode();
        acc == libc::O_WRONLY || acc == libc::O_RDWR
    }
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
        self.inner.reopen(flags.into())
    }

    /// Create a copy of an existing [`Handle`].
    ///
    /// The new handle is completely independent from the original, but
    /// references the same underlying file.
    ///
    /// [`Handle`]: struct.Handle.html
    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(Self {
            inner: self.inner.try_clone_hotfix()?,
        })
    }

    /// Unwrap a [`Handle`] to reveal the underlying [`File`].
    ///
    /// [`Handle`]: struct.Handle.html
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    pub fn into_file(self) -> File {
        self.inner
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
        Self { inner: inner }
    }

    // TODO: All the different stat* interfaces?

    // TODO: bind(). This might be safe to do (set the socket path to
    //       /proc/self/fd/...) but I'm a bit sad it'd be separate from
    //       Handle::reopen().
}

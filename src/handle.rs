/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

#![forbid(unsafe_code)]

use crate::{
    error::{Error, ErrorImpl},
    flags::OpenFlags,
    procfs::GLOBAL_PROCFS_HANDLE,
    utils::FdExt,
};

use std::{
    fs::File,
    os::unix::io::{AsFd, BorrowedFd, OwnedFd},
};

/// A handle to an existing inode within a [`Root`].
///
/// This handle references an already-resolved path which can be used for the
/// purpose of "re-opening" the handle and get an actual [`File`] which can be
/// used for ordinary operations.
///
/// # Safety
///
/// It is critical for the safety of this library that **at no point** do you
/// use interfaces like [`libc::openat`] directly on the [`OwnedFd`] you can
/// extract from this [`Handle`]. **You must always do operations through a
/// valid [`Root`].**
///
/// [`RawFd`]: std::os::unix::io::RawFd
/// [`Root`]: crate::Root
#[derive(Debug)]
pub struct Handle {
    inner: OwnedFd,
}

impl Handle {
    /// Wrap an [`OwnedFd`] into a [`Handle`].
    #[inline]
    pub fn from_fd<Fd: Into<OwnedFd>>(fd: Fd) -> Self {
        Self { inner: fd.into() }
    }

    /// Borrow this [`Handle`] as a [`HandleRef`].
    // XXX: We can't use Borrow/Deref for this because HandleRef takes a
    //      lifetime rather than being a pure reference. Ideally we would use
    //      Deref but it seems that won't be possible in standard Rust for a
    //      long time, if ever...
    #[inline]
    pub fn as_ref(&self) -> HandleRef<'_> {
        HandleRef {
            inner: self.as_fd(),
        }
    }

    /// Create a copy of an existing [`Handle`].
    ///
    /// The new handle is completely independent from the original, but
    /// references the same underlying file.
    #[inline]
    pub fn try_clone(&self) -> Result<Self, Error> {
        self.as_ref().try_clone()
    }

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
    /// 2. `ioctl(fd, TIOCSCTTY, 0)` will set the fd as the controlling terminal
    ///    (if you don't have one already, and the fd references a TTY).
    ///
    /// [`Root::create`]: crate::Root::create
    #[doc(alias = "pathrs_reopen")]
    #[inline]
    pub fn reopen<F: Into<OpenFlags>>(&self, flags: F) -> Result<File, Error> {
        self.as_ref().reopen(flags)
    }
}

impl From<OwnedFd> for Handle {
    /// Shorthand for [`Handle::from_fd`].
    fn from(fd: OwnedFd) -> Self {
        Self::from_fd(fd)
    }
}

impl From<Handle> for OwnedFd {
    /// Unwrap a [`Handle`] to reveal the underlying [`OwnedFd`].
    ///
    /// **Note**: This method is primarily intended to allow for file descriptor
    /// passing or otherwise transmitting file descriptor information. If you
    /// want to get a [`File`] handle for general use, please use
    /// [`Handle::reopen`] instead.
    #[inline]
    fn from(handle: Handle) -> Self {
        handle.inner
    }
}

impl AsFd for Handle {
    /// Access the underlying file descriptor for a [`Handle`].
    ///
    /// **Note**: This method is primarily intended to allow for tests and other
    /// code to check the status of the underlying [`OwnedFd`] without having to
    /// use [`OwnedFd::from`]. It is not safe to use this [`BorrowedFd`]
    /// directly to do filesystem operations. Please use the provided
    /// [`HandleRef`] methods.
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Borrowed version of [`Handle`].
///
/// Unlike [`Handle`], when [`HandleRef`] is dropped the underlying file
/// descriptor is *not* closed. This is mainly useful for programs and libraries
/// that have to do operations on [`&File`][File]s and [`BorrowedFd`]s passed
/// from elsewhere.
///
/// [File]: std::fs::File
// TODO: Is there any way we can restructure this to use Deref so that we don't
//       need to copy all of the methods into Handle? Probably not... Maybe GATs
//       will eventually support this but we'd still need a GAT-friendly Deref.
#[derive(Copy, Clone, Debug)]
pub struct HandleRef<'fd> {
    inner: BorrowedFd<'fd>,
}

impl HandleRef<'_> {
    /// Wrap a [`BorrowedFd`] into a [`HandleRef`].
    pub fn from_fd(inner: BorrowedFd<'_>) -> HandleRef<'_> {
        HandleRef { inner }
    }

    /// Create a copy of a [`HandleRef`].
    ///
    /// Note that (unlike [`BorrowedFd::clone`]) this method creates a full copy
    /// of the underlying file descriptor and thus is more equivalent to
    /// [`BorrowedFd::try_clone_to_owned`].
    ///
    /// To create a shallow copy of a [`HandleRef`], you can use
    /// [`Clone::clone`] (or just [`Copy`]).
    // TODO: We might need to call this something other than try_clone(), since
    //       it's a little too easy to confuse with Clone::clone() but we also
    //       really want to have Copy.
    pub fn try_clone(&self) -> Result<Handle, Error> {
        self.as_fd()
            .try_clone_to_owned()
            .map_err(|err| {
                ErrorImpl::OsError {
                    operation: "clone underlying handle file".into(),
                    source: err,
                }
                .into()
            })
            .map(Handle::from_fd)
    }

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
    /// 2. `ioctl(fd, TIOCSCTTY, 0)` will set the fd as the controlling terminal
    ///    (if you don't have one already, and the fd references a TTY).
    ///
    /// [`Root::create`]: crate::Root::create
    #[doc(alias = "pathrs_reopen")]
    pub fn reopen<F: Into<OpenFlags>>(&self, flags: F) -> Result<File, Error> {
        self.inner
            .reopen(&GLOBAL_PROCFS_HANDLE, flags.into())
            .map(File::from)
    }

    // TODO: All the different stat* interfaces?

    // TODO: bind(). This might be safe to do (set the socket path to
    //       /proc/self/fd/...) but I'm a bit sad it'd be separate from
    //       Handle::reopen().
}

impl<'fd> From<BorrowedFd<'fd>> for HandleRef<'fd> {
    /// Shorthand for [`HandleRef::from_fd`].
    fn from(fd: BorrowedFd<'fd>) -> Self {
        Self::from_fd(fd)
    }
}

impl AsFd for HandleRef<'_> {
    /// Access the underlying file descriptor for a [`HandleRef`].
    ///
    /// **Note**: This method is primarily intended to allow for tests and other
    /// code to check the status of the underlying file descriptor. It is not
    /// safe to use this [`BorrowedFd`] directly to do filesystem operations.
    /// Please use the provided [`HandleRef`] methods.
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Handle, HandleRef, Root};

    use std::os::unix::io::{AsFd, AsRawFd, OwnedFd};

    use anyhow::Error;
    use pretty_assertions::assert_eq;

    #[test]
    fn from_fd() -> Result<(), Error> {
        let handle = Root::open(".")?.resolve(".")?;
        let handle_ref1 = handle.as_ref();
        let handle_ref2 = HandleRef::from_fd(handle.as_fd());

        assert_eq!(
            handle.as_fd().as_raw_fd(),
            handle_ref1.as_fd().as_raw_fd(),
            "Handle::as_ref should have the same underlying fd"
        );
        assert_eq!(
            handle.as_fd().as_raw_fd(),
            handle_ref2.as_fd().as_raw_fd(),
            "HandleRef::from_fd should have the same underlying fd"
        );

        Ok(())
    }

    #[test]
    fn into_from_ownedfd() -> Result<(), Error> {
        let handle = Root::open(".")?.resolve(".")?;
        let handle_fd = handle.as_fd().as_raw_fd();

        let owned: OwnedFd = handle.into();
        let owned_fd = owned.as_fd().as_raw_fd();

        let handle2: Handle = owned.into();
        let handle2_fd = handle2.as_fd().as_raw_fd();

        assert_eq!(
            handle_fd, owned_fd,
            "OwnedFd::from(handle) should have same underlying fd",
        );
        assert_eq!(
            handle_fd, handle2_fd,
            "Handle -> OwnedFd -> Handle roundtrip should have same underlying fd",
        );

        Ok(())
    }
}

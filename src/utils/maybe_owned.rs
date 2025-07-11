/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
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

use std::os::unix::io::{AsFd, BorrowedFd};

/// Like [`std::borrow::Cow`] but without the [`ToOwned`] requirement, and only
/// for file descriptors.
///
/// This is mainly useful when you need to write a function that takes something
/// equivalent to `Option<BorrowedFd<'_>>` and opens an alternative [`OwnedFd`]
/// (or any other `Fd: AsFd`) if passed [`None`]. Normally you cannot really do
/// this smoothly.
///
/// Note that due to Rust's temporaries handling and restrictions of the
/// [`AsFd`] trait, you need to do something like the following:
///
/// ```ignore
/// fn procfs_foobar(fd: Option<BorrowedFd<'_>>) -> Result<(), Error> {
///     let fd = match fd {
///         None => MaybeOwnedFd::OwnedFd(File::open("/proc")?),
///         Some(fd) => MaybeOwnedFd::BorrowedFd(fd),
///     };
///     let fd = fd.as_fd(); // BorrowedFd<'_>
///     // do something with fd
/// }
/// ```
///
/// This will give you a [`BorrowedFd`] with minimal fuss.
///
/// [`OwnedFd`]: std::os::unix::io::OwnedFd
/// [`ToOwned`]: std::borrow::ToOwned
#[derive(Debug)]
pub(crate) enum MaybeOwnedFd<'fd, Fd>
where
    Fd: 'fd + AsFd,
{
    OwnedFd(Fd),
    BorrowedFd(BorrowedFd<'fd>),
}

// I wish we could make this "impl AsFd for MaybeOwnedFd" but the lifetimes
// don't match, even though it really feels like it should be possible.
impl<'fd, Fd> MaybeOwnedFd<'fd, Fd>
where
    Fd: AsFd,
{
    /// Very similar in concept to [`AsFd::as_fd`] but with some additional
    /// lifetime restrictions that make it incompatible with [`AsFd`].
    pub(crate) fn as_fd<'a>(&'a self) -> BorrowedFd<'a>
    where
        'a: 'fd,
    {
        match self {
            MaybeOwnedFd::OwnedFd(fd) => fd.as_fd(),
            MaybeOwnedFd::BorrowedFd(fd) => fd.as_fd(),
        }
    }
}

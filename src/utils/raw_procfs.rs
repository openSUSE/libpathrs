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

use crate::{
    error::{Error, ErrorImpl},
    flags::OpenFlags,
    procfs, syscalls,
    utils::MaybeOwnedFd,
};

use std::{
    os::unix::io::{BorrowedFd, OwnedFd},
    path::Path,
};

use rustix::fs::{Access, AtFlags};

/// "We have [`ProcfsHandle`] at home."
///
/// One of the core issues when implementing [`ProcfsHandle`] is that a lot of
/// helper functions used by [`ProcfsHandle`] would really like to be able to
/// use [`ProcfsHandle`] in a re-entrant way to get some extra safety against
/// attacks, while also supporting callers that don't even have a `/proc` handle
/// ready or callers that are not within the [`ProcfsHandle`] implementation and
/// thus can get full safety from [`ProcfsHandle`] itself.
///
/// The main purpose of this type is to allow us to easily indicate this (as
/// opposed to `Option<BorrowedFd<'_>>` everywhere) and provide some helpers to
/// help reduce the complexity of the helper functions.
///
/// In general, you should only be using this for core helper functions used by
/// [`ProcfsHandle`] which need to take a reference to the *root* of `/proc`.
/// Make sure to always use the same [`RawProcfsRoot`] consistently, lest you
/// end up with very weird coherency problems.
///
/// [`ProcfsHandle`]: crate::procfs::ProcfsHandle
#[derive(Copy, Clone, Debug)]
pub(crate) enum RawProcfsRoot<'fd> {
    /// Use the global `/proc`. This is unsafe against most attacks, and should
    /// only ever really be used for debugging purposes only, such as in
    /// [`FdExt::as_unsafe_path_unchecked`].
    ///
    /// [`FdExt::as_unsafe_path_unchecked`]: crate::utils::FdExt::as_unsafe_path_unchecked
    UnsafeGlobal,

    /// Use this [`BorrowedFd`] as the rootfs of a proc and operate relative to
    /// it. This is still somewhat unsafe, depending on what kernel features are
    /// available.
    UnsafeFd(BorrowedFd<'fd>),
}

impl<'fd> RawProcfsRoot<'fd> {
    /// Convert this to a [`MaybeOwnedFd`].
    ///
    /// For [`RawProcfsRoot::UnsafeGlobal`], this requires opening `/proc` and
    /// thus allocating a new file handle. For all other variants this should be
    /// a very cheap reference conversion.
    pub(crate) fn try_into_maybe_owned_fd<'a>(&'a self) -> Result<MaybeOwnedFd<'a, OwnedFd>, Error>
    where
        'a: 'fd,
    {
        let fd = match self {
            Self::UnsafeGlobal => MaybeOwnedFd::OwnedFd(
                syscalls::openat(
                    syscalls::BADFD,
                    "/proc",
                    OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
                    0,
                )
                .map_err(|err| ErrorImpl::RawOsError {
                    operation: "open /proc handle".into(),
                    source: err,
                })?,
            ),
            Self::UnsafeFd(fd) => MaybeOwnedFd::BorrowedFd(*fd),
        };
        procfs::verify_is_procfs_root(fd.as_fd())?;
        Ok(fd)
    }

    /// `accessat(procfs_root, path, Access:EXISTS, AtFlags::SYMLINK_NOFOLLOW)`
    ///
    /// Should only be used as an indicative check (namely to see if
    /// `/proc/thread-self` exists), and this has no protections against
    /// malicious components regardless of what kind of handle it is.
    ///
    /// The only user of this is [`ProcfsBase::into_path`] which only uses it to
    /// decide whether `/proc/thread-self` exists.
    ///
    /// [`ProcfsBase::into_path`]: crate::procfs::ProcfsBase::into_path
    pub(crate) fn exists_unchecked(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        syscalls::accessat(
            self.try_into_maybe_owned_fd()?.as_fd(),
            path,
            Access::EXISTS,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "check if subpath exists in raw procfs".into(),
                source: err,
            }
            .into()
        })
    }
}

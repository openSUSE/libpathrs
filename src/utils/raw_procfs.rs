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
    procfs,
    syscalls::{self, OpenHow, ResolveFlags},
    utils::{fd::proc_threadself_subpath, FdExt, MaybeOwnedFd},
};

use std::{
    os::unix::{
        fs::MetadataExt,
        io::{AsRawFd, BorrowedFd, OwnedFd},
    },
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

    /// Open a subpath within this [`RawProcfsRoot`] using `openat2`.
    ///
    /// `RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV | RESOLVE_BENEATH` are all
    /// auto-applied.
    fn openat2_beneath(&self, path: impl AsRef<Path>, oflags: OpenFlags) -> Result<OwnedFd, Error> {
        let path = path.as_ref();

        syscalls::openat2(
            self.try_into_maybe_owned_fd()?.as_fd(),
            path,
            OpenHow {
                flags: oflags.bits() as _,
                mode: 0,
                resolve: (ResolveFlags::RESOLVE_NO_MAGICLINKS
                    | ResolveFlags::RESOLVE_NO_XDEV
                    | ResolveFlags::RESOLVE_BENEATH)
                    .bits(),
            },
        )
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "open raw procfs subpath".into(),
                source: err,
            }
            .into()
        })
    }

    /// Open a subpath within this [`RawProcfsRoot`] using `openat`.
    ///
    /// A best-effort attempt is made to try to avoid getting tricked by
    /// overmounts, but this method does not guarantee protection against
    /// bind-mount overmounts.
    fn opath_beneath_unchecked(
        &self,
        path: impl AsRef<Path>,
        oflags: OpenFlags,
    ) -> Result<OwnedFd, Error> {
        let path = path.as_ref();
        let proc_rootfd = self.try_into_maybe_owned_fd()?;
        let proc_rootfd = proc_rootfd.as_fd();

        // This is technically not safe, but there really is not much we can do
        // in practice -- we would need to have a separate copy of the procfs
        // resolver code without any mount-id-related protections (or add an
        // unsafe_disable_mnt_id_checks argument), and even then it would not
        // practically protect against attacks.
        //
        // An attacker could still bind-mount their own /proc/thread-self/fdinfo
        // (after opening hundreds of handles to /proc) on top of our
        // /proc/thread-self/fdinfo, at which point they could trivially fake
        // fdinfo without the need for symlinks or tmpfs.
        //
        // At this point, we are just trying to minimise the damage a trivial
        // attack on top of a static procfs path can do. An attacker that can
        // actively bind-mount on top of /proc/thread-self/fdinfo cannot be
        // protected against without openat2(2) or STATX_MNT_ID.

        // In order to avoid being tricked into following a trivial symlink or
        // bind-mount to a filesystem object that could DoS us when we try to
        // O_RDONLY open it below (such as a stale NFS handle), first open it
        // with O_PATH then double-check that it is a procfs inode.
        let opath = syscalls::openat(proc_rootfd, path, OpenFlags::O_PATH, 0).map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "preliminary open raw procfs subpath to check fstype".into(),
                source: err,
            }
        })?;
        // As below, we can't use verify_same_procfs_mnt.
        procfs::verify_is_procfs(&opath)?;

        // We can't do FdExt::reopen() here because this code is potentially
        // called within ProcfsHandle. However, we can just re-open through
        // /proc/thread-self/fd/$n directly -- this is not entirely safe
        // against bind-mounts but this will make it harder for an attacker
        // (they would need to predict the fd number of the transient file
        // we just opened, and have the ability to bind-mount over
        // magic-links -- which is something that a lot of tools do not
        // support).
        let file = syscalls::openat_follow(
            proc_rootfd,
            proc_threadself_subpath(*self, &format!("fd/{}", opath.as_raw_fd())),
            oflags,
            0,
        )
        .map_err(|err| ErrorImpl::RawOsError {
            operation: "re-open raw procfs subpath".into(),
            source: err,
        })?;
        // As below, we can't use verify_same_procfs_mnt.
        procfs::verify_is_procfs(&file)?;

        // Finally, verify that the inode numbers match. This is not
        // strictly "necessary" (since the opath could be an
        // attacker-controlled procfs file), but this could at least detect
        // sloppy /proc/self/fd/* overmounts.
        if opath.metadata()?.ino() != file.metadata()?.ino() {
            Err(ErrorImpl::SafetyViolation {
                    description: "fd has an inconsistent inode number after re-opening -- probably a manipulated procfs".into(),
                })?;
        }
        Ok(file)
    }

    /// Open a subpath within this [`RawProcfsRoot`].
    pub(crate) fn open_beneath(
        &self,
        path: impl AsRef<Path>,
        oflags: OpenFlags,
    ) -> Result<OwnedFd, Error> {
        let fd = if *syscalls::OPENAT2_IS_SUPPORTED {
            self.openat2_beneath(path, oflags)?
        } else {
            self.opath_beneath_unchecked(path, oflags)?
        };
        // As this is called from within fetch_mnt_id as a fallback, the only
        // thing we can do here is verify that it is actually procfs. However,
        // in practice it will be quite difficult for an attacker to over-mount
        // every fdinfo file for a process.
        procfs::verify_is_procfs(&fd)?;
        Ok(fd)
    }
}

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
    procfs::{ProcfsBase, ProcfsHandle},
    syscalls,
};

use std::{
    fs,
    os::unix::io::{AsFd, AsRawFd, OwnedFd},
    path::{Path, PathBuf},
};

pub(crate) struct Metadata(libc::stat);

// TODO: Maybe we should just implement MetadataExt?
impl Metadata {
    pub(crate) fn mode(&self) -> u32 {
        self.0.st_mode
    }

    #[cfg(test)]
    pub(crate) fn rdev(&self) -> u64 {
        self.0.st_rdev
    }

    #[cfg(test)]
    pub(crate) fn ino(&self) -> u64 {
        self.0.st_ino
    }

    #[cfg(test)]
    pub(crate) fn nlink(&self) -> u64 {
        self.0.st_nlink
    }

    pub(crate) fn is_symlink(&self) -> bool {
        self.mode() & libc::S_IFMT == libc::S_IFLNK
    }
}

pub(crate) trait FdExt {
    /// Equivalent to [`File::metadata`].
    ///
    /// [`File::metadata`]: std::fs::File::metadata
    fn metadata(&self) -> Result<Metadata, Error>;

    /// Re-open a file descriptor.
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<OwnedFd, Error>;

    /// Get the path this RawFd is referencing.
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy
    /// (hence the name "unsafe"), so it's important to only use this with the
    /// understanding that it only provides the guarantee that "at some point
    /// during execution this was the path the fd pointed to" and
    /// no more.
    ///
    /// NOTE: This method uses the [`ProcfsHandle`] to resolve the path. This
    /// means that it is UNSAFE to use this method within any of our `procfs`
    /// code!
    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error>;

    /// Like [`FdExt::as_unsafe_path`], except that the lookup is done using the
    /// basic host `/proc` mount. This is not safe against various races, and
    /// thus MUST ONLY be used in codepaths that are not susceptible to those
    /// kinds of attacks.
    ///
    /// Currently this should only be used by the `syscall::FrozenFd` logic
    /// which saves the path a file descriptor references.
    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error>;

    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_magiclink_filesystem(&self) -> Result<bool, Error>;
}

fn proc_subpath<Fd: AsRawFd>(fd: Fd) -> Result<String, Error> {
    let fd = fd.as_raw_fd();
    if fd == libc::AT_FDCWD {
        Ok("cwd".to_string())
    } else if fd.is_positive() {
        Ok(format!("fd/{}", fd))
    } else {
        Err(ErrorImpl::InvalidArgument {
            name: "fd".into(),
            description: "must be positive or AT_FDCWD".into(),
        })?
    }
}

/// Set of filesystems' magic numbers that are considered "dangerous" (in that
/// they can contain magic-links). This list should hopefully be exhaustive, but
/// there's no real way of being sure since `nd_jump_link()` can be used by any
/// non-mainline filesystem.
///
/// This list is correct from the [introduction of `nd_jump_link()` in Linux
/// 3.6][kcommit-b5fb63c18315] up to Linux 6.11. Before Linux 3.6, the logic
/// that became `nd_jump_link()` only existed in procfs. AppArmor [started using
/// it in Linux 4.13 with the introduction of
/// apparmorfs][kcommit-a481f4d917835].
///
/// [kcommit-b5fb63c18315]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b5fb63c18315c5510c1d0636179c057e0c761c77
/// [kcommit-a481f4d91783]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a481f4d917835cad86701fc0d1e620c74bb5cd5f
// TODO: Remove the explicit size once generic_arg_infer is stable.
//       <https://github.com/rust-lang/rust/issues/85077>
const DANGEROUS_FILESYSTEMS: [i64; 2] = [
    libc::PROC_SUPER_MAGIC, // procfs
    0x5a3c_69f0,            // apparmorfs
];

impl<T: AsFd> FdExt for T {
    fn metadata(&self) -> Result<Metadata, Error> {
        let stat = syscalls::fstatat(self.as_fd(), "").map_err(|err| ErrorImpl::RawOsError {
            operation: "get fd metadata".into(),
            source: err,
        })?;
        Ok(Metadata(stat))
    }

    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<OwnedFd, Error> {
        let fd = self.as_fd();
        // TODO: We should look into using O_EMPTYPATH if it's available to
        //       avoid the /proc dependency -- though then again, as_unsafe_path
        //       necessarily requires /proc.
        procfs
            .open_follow(ProcfsBase::ProcThreadSelf, proc_subpath(fd)?, flags)
            .map(OwnedFd::from)
    }

    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error> {
        let fd = self.as_fd();
        procfs.readlink(ProcfsBase::ProcThreadSelf, proc_subpath(fd)?)
    }

    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error> {
        let fd = self.as_fd();
        // "/proc/thread-self/fd/$n"
        let fd_path = PathBuf::from("/proc")
            .join(ProcfsBase::ProcThreadSelf.into_path(None))
            .join(proc_subpath(fd)?);

        // Because this code is used within syscalls, we can't even check the
        // filesystem type of /proc (unless we were to copy the logic here).
        fs::read_link(&fd_path).map_err(|err| {
            ErrorImpl::OsError {
                operation: format!("readlink fd magic-link {fd_path:?}").into(),
                source: err,
            }
            .into()
        })
    }

    fn is_magiclink_filesystem(&self) -> Result<bool, Error> {
        // There isn't a marker on a filesystem level to indicate whether
        // nd_jump_link() is used internally. So, we just have to make an
        // educated guess based on which mainline filesystems expose
        // magic-links.
        let stat = syscalls::fstatfs(self).map_err(|err| ErrorImpl::RawOsError {
            operation: "check fstype of fd".into(),
            source: err,
        })?;
        Ok(DANGEROUS_FILESYSTEMS.contains(&stat.f_type))
    }
}

pub(crate) fn fetch_mnt_id<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
) -> Result<Option<u64>, Error> {
    // NOTE: stx.stx_mnt_id is fairly new (added in Linux 5.8[1]) so this check
    // might not work on quite a few kernels and so we have to fallback to not
    // checking the mount ID (removing some protections).
    //
    // In theory, name_to_handle_at(2) also lets us get the mount of a
    // handle in a race-free way (and would be a useful fallback for pre-statx
    // kernels -- name_to_handle_at(2) was added in Linux 2.6.39[2]).
    //
    // Unfortunately, before AT_HANDLE_FID (added in Linux 6.7[3]) procfs did
    // not permit the export of file handles. name_to_handle_at(2) does return
    // the mount ID in most error cases, but for -EOPNOTSUPP it doesn't and so
    // we can't use it for pre-statx kernels.
    //
    // The only other alternative would be to scan /proc/self/mountinfo, but
    // since we are worried about procfs attacks there isn't much point (an
    // attacker could bind-mount /proc/self/environ over /proc/$pid/mountinfo
    // and simply change their environment to make the mountinfo look
    // reasonable.
    //
    // So we have to live with limited protection for pre-5.8 kernels.
    //
    // [1]: Linux commit fa2fcf4f1df1 ("statx: add mount ID")
    // [2]: Linux commit 990d6c2d7aee ("vfs: Add name to file handle conversion support")
    // [3]: Linux commit 64343119d7b8 ("exportfs: support encoding non-decodeable file handles by default")

    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
    let want_mask = libc::STATX_MNT_ID | STATX_MNT_ID_UNIQUE;

    match syscalls::statx(dirfd, path, want_mask) {
        Ok(stx) => Ok(if stx.stx_mask & want_mask != 0 {
            Some(stx.stx_mnt_id)
        } else {
            None
        }),
        Err(err) => match err.root_cause().raw_os_error() {
            // We have to handle STATX_MNT_ID not being supported on pre-5.8
            // kernels, so treat an ENOSYS or EINVAL the same so that we can
            // work on pre-4.11 (pre-statx) kernels as well.
            Some(libc::ENOSYS) | Some(libc::EINVAL) => Ok(None),
            _ => Err(ErrorImpl::RawOsError {
                operation: "check mnt_id of filesystem".into(),
                source: err,
            })?,
        },
    }
}

/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
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

use crate::{
    error::{self, Error},
    flags::OpenFlags,
    procfs::{ProcfsBase, ProcfsHandle},
    syscalls,
};

use std::{
    fs::{self, File},
    os::unix::io::{AsRawFd, RawFd},
    path::{Path, PathBuf},
};

use snafu::ResultExt;

pub(crate) trait RawFdExt {
    /// Re-open a file descriptor.
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<File, Error>;

    /// Get the path this RawFd is referencing.
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy
    /// (hence the name "unsafe"), so it's important to only use this with the
    /// understanding that it only provides the guarantee that "at some point
    /// during execution this was the path the fd pointed to" and
    /// no more.
    ///
    /// NOTE: This method uses a [`procfs::ProcfsHandle`] to
    ///
    /// [`procfs::ProcfsHandle`]: procfs/struct.ProcfsHandle.html
    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error>;

    /// Like [`as_unsafe_path`], except that the lookup is done using the basic
    /// host `/proc` mount. This is not safe against various races, and thus
    /// MUST ONLY be used in codepaths that
    ///
    /// Currently this should only be used by the `syscall::FrozenFd` logic
    /// which saves the path a file descriptor references.
    ///
    /// [`as_unsafe_path`]: #method.as_unsafe_path
    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error>;

    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_magiclink_filesystem(&self) -> Result<bool, Error>;
}

fn proc_subpath(fd: RawFd) -> Result<String, Error> {
    if fd == libc::AT_FDCWD {
        Ok("cwd".to_string())
    } else if fd.is_positive() {
        Ok(format!("fd/{}", fd))
    } else {
        error::InvalidArgumentSnafu {
            name: "fd",
            description: "must be positive or AT_FDCWD",
        }
        .fail()
    }
}

/// Set of filesystems' magic numbers that are considered "dangerous" (in that
/// they can contain magic-links). This list should hopefully be exhaustive, but
/// there's no real way of being sure since `nd_jump_link()` can be used by any
/// non-mainline filesystem.
///
/// This list is correct from the [introduction of `nd_jump_link()` in Linux 3.6][kcommit-b5fb63c18315]
/// up to Linux 6.11. Before Linux 3.6, the logic that became `nd_jump_link()`
/// only existed in procfs. AppArmor [started using it in Linux 4.13 with the
/// introduction of apparmorfs][kcommit-a481f4d917835].
///
/// [kcommit-b5fb63c18315]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b5fb63c18315c5510c1d0636179c057e0c761c77
/// [kcommit-a481f4d91783]; https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a481f4d917835cad86701fc0d1e620c74bb5cd5f
// TODO: Remove the explicit size once generic_arg_infer is stable.
//       <https://github.com/rust-lang/rust/issues/85077>
const DANGEROUS_FILESYSTEMS: [i64; 2] = [
    libc::PROC_SUPER_MAGIC, // procfs
    0x5a3c_69f0,            // apparmorfs
];

impl RawFdExt for RawFd {
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<File, Error> {
        // TODO: We should look into using O_EMPTYPATH if it's available to
        //       avoid the /proc dependency -- though then again, as_unsafe_path
        //       necessarily requires /proc.
        procfs.open_follow(ProcfsBase::ProcThreadSelf, proc_subpath(*self)?, flags)
    }

    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error> {
        procfs.readlink(ProcfsBase::ProcThreadSelf, proc_subpath(*self)?)
    }

    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error> {
        // "/proc/thread-self/fd/$n"
        let fd_path = PathBuf::from("/proc")
            .join(ProcfsBase::ProcThreadSelf.into_path(None))
            .join(proc_subpath(*self)?);

        // Because this code is used within syscalls, we can't even check the
        // filesystem type of /proc (unless we were to copy the logic here).
        fs::read_link(&fd_path).context(error::OsSnafu {
            operation: format!("readlink fd magic-link {:?}", fd_path),
        })
    }

    fn is_magiclink_filesystem(&self) -> Result<bool, Error> {
        // There isn't a marker on a filesystem level to indicate whether
        // nd_jump_link() is used internally. So, we just have to make an
        // educated guess based on which mainline filesystems expose
        // magic-links.
        let stat = syscalls::fstatfs(*self).context(error::RawOsSnafu {
            operation: "check fstype of fd",
        })?;
        Ok(DANGEROUS_FILESYSTEMS.contains(&stat.f_type))
    }
}

// XXX: We can't use <T: AsRawFd> here, because Rust tells us that RawFd might
//      have an AsRawFd in the future (and thus produce a conflicting
//      implementations error) and so we have to manually define it for the
//      types we are going to be using.

impl RawFdExt for File {
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<File, Error> {
        self.as_raw_fd().reopen(procfs, flags)
    }

    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error> {
        // SAFETY: Caller guarantees that as_unsafe_path usage is safe.
        self.as_raw_fd().as_unsafe_path(procfs)
    }

    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error> {
        // SAFETY: Caller guarantees that as_unsafe_path usage is safe.
        self.as_raw_fd().as_unsafe_path_unchecked()
    }

    fn is_magiclink_filesystem(&self) -> Result<bool, Error> {
        self.as_raw_fd().is_magiclink_filesystem()
    }
}

pub(crate) fn fetch_mnt_id<P: AsRef<Path>>(dirfd: &File, path: P) -> Result<Option<u64>, Error> {
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

    match syscalls::statx(dirfd.as_raw_fd(), path, want_mask) {
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
            _ => Err(err).context(error::RawOsSnafu {
                operation: "check mnt_id of filesystem",
            })?,
        },
    }
}

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
    error::{Error, ErrorExt, ErrorImpl},
    flags::OpenFlags,
    procfs::{ProcfsBase, ProcfsHandle},
    syscalls,
};

use std::{
    fs,
    io::Error as IOError,
    os::unix::{
        fs::MetadataExt,
        io::{AsFd, AsRawFd, OwnedFd},
    },
    path::{Path, PathBuf},
};

use rustix::fs::{self as rustix_fs, StatExt, StatxFlags};

pub(crate) struct Metadata(rustix_fs::Stat);

impl Metadata {
    pub(crate) fn is_symlink(&self) -> bool {
        self.mode() & libc::S_IFMT == libc::S_IFLNK
    }
}

#[allow(clippy::useless_conversion)] // 32-bit arches
impl MetadataExt for Metadata {
    fn dev(&self) -> u64 {
        self.0.st_dev.into()
    }

    fn ino(&self) -> u64 {
        self.0.st_ino.into()
    }

    fn mode(&self) -> u32 {
        self.0.st_mode
    }

    fn nlink(&self) -> u64 {
        self.0.st_nlink.into()
    }

    fn uid(&self) -> u32 {
        self.0.st_uid
    }

    fn gid(&self) -> u32 {
        self.0.st_gid
    }

    fn rdev(&self) -> u64 {
        self.0.st_rdev.into()
    }

    fn size(&self) -> u64 {
        self.0.st_size as u64
    }

    fn atime(&self) -> i64 {
        self.0.atime()
    }

    fn atime_nsec(&self) -> i64 {
        self.0.st_atime_nsec as i64
    }

    fn mtime(&self) -> i64 {
        self.0.mtime()
    }

    fn mtime_nsec(&self) -> i64 {
        self.0.st_mtime_nsec as i64
    }

    fn ctime(&self) -> i64 {
        self.0.ctime()
    }

    fn ctime_nsec(&self) -> i64 {
        self.0.st_ctime_nsec as i64
    }

    fn blksize(&self) -> u64 {
        self.0.st_blksize as u64
    }

    fn blocks(&self) -> u64 {
        self.0.st_blocks as u64
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
const DANGEROUS_FILESYSTEMS: [rustix_fs::FsWord; 2] = [
    rustix_fs::PROC_SUPER_MAGIC, // procfs
    0x5a3c_69f0,                 // apparmorfs
];

impl<Fd: AsFd> FdExt for Fd {
    fn metadata(&self) -> Result<Metadata, Error> {
        let stat = syscalls::fstatat(self.as_fd(), "").map_err(|err| ErrorImpl::RawOsError {
            operation: "get fd metadata".into(),
            source: err,
        })?;
        Ok(Metadata(stat))
    }

    fn reopen(&self, procfs: &ProcfsHandle, mut flags: OpenFlags) -> Result<OwnedFd, Error> {
        let fd = self.as_fd();

        // For file descriptors referencing a symlink (i.e. opened with
        // O_PATH|O_NOFOLLOW) there is no logic behind trying to do a "reopen"
        // operation, and you just get confusing results because the reopen
        // itself is done through a symlink. Even with O_EMPTYPATH you probably
        // wouldn't ever want to re-open it (all you can get is another
        // O_PATH|O_EMPTYPATH).
        if self.metadata()?.is_symlink() {
            Err(Error::from(ErrorImpl::OsError {
                operation: "reopen".into(),
                source: IOError::from_raw_os_error(libc::ELOOP),
            }))
            .wrap("symlink file handles cannot be reopened")?
        }

        // Now that we are sure the file descriptor is not a symlink, we can
        // clear O_NOFOLLOW since it is a no-op (but due to the procfs reopening
        // implementation, O_NOFOLLOW will cause strange behaviour).
        flags.remove(OpenFlags::O_NOFOLLOW);

        // TODO: Add support for O_EMPTYPATH once that exists...
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

    const STATX_MNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
    let want_mask = StatxFlags::MNT_ID | STATX_MNT_ID_UNIQUE;

    match syscalls::statx(dirfd, path, want_mask) {
        Ok(stx) => {
            let got_mask = StatxFlags::from_bits_retain(stx.stx_mask);
            Ok(if got_mask.intersects(want_mask) {
                Some(stx.stx_mnt_id)
            } else {
                None
            })
        }
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

#[cfg(test)]
mod tests {
    use crate::{flags::OpenFlags, procfs::GLOBAL_PROCFS_HANDLE, syscalls, utils::FdExt};

    use std::{
        fs::File,
        os::unix::{fs::MetadataExt, io::AsFd},
        path::Path,
    };

    use anyhow::{Context, Error};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    fn check_as_unsafe_path<Fd: AsFd, P: AsRef<Path>>(fd: Fd, want_path: P) -> Result<(), Error> {
        let want_path = want_path.as_ref();

        // Plain /proc/... lookup.
        let got_path = fd.as_unsafe_path_unchecked()?;
        assert_eq!(
            got_path, want_path,
            "expected as_unsafe_path_unchecked to give the correct path"
        );
        // ProcfsHandle-based lookup.
        let got_path = fd.as_unsafe_path(&GLOBAL_PROCFS_HANDLE)?;
        assert_eq!(
            got_path, want_path,
            "expected as_unsafe_path to give the correct path"
        );
        Ok(())
    }

    #[test]
    fn as_unsafe_path_cwd() -> Result<(), Error> {
        let real_cwd = syscalls::getcwd()?;
        check_as_unsafe_path(syscalls::AT_FDCWD, real_cwd)
    }

    #[test]
    fn as_unsafe_path_fd() -> Result<(), Error> {
        let real_tmpdir = TempDir::new()?;
        let file = File::open(&real_tmpdir)?;
        check_as_unsafe_path(&file, real_tmpdir)
    }

    #[test]
    fn as_unsafe_path_badfd() {
        assert!(
            syscalls::BADFD.as_unsafe_path_unchecked().is_err(),
            "as_unsafe_path_unchecked should fail for bad file descriptor"
        );
        assert!(
            syscalls::BADFD
                .as_unsafe_path(&GLOBAL_PROCFS_HANDLE)
                .is_err(),
            "as_unsafe_path should fail for bad file descriptor"
        );
    }

    #[test]
    fn reopen_badfd() {
        assert!(
            syscalls::BADFD
                .reopen(&GLOBAL_PROCFS_HANDLE, OpenFlags::O_PATH)
                .is_err(),
            "reopen should fail for bad file descriptor"
        );
    }

    #[test]
    fn is_magiclink_filesystem() {
        assert!(
            !File::open("/")
                .expect("should be able to open handle to /")
                .is_magiclink_filesystem()
                .expect("is_magiclink_filesystem should work on regular file"),
            "/ is not a magic-link filesystem"
        );
    }

    #[test]
    fn is_magiclink_filesystem_badfd() {
        assert!(
            syscalls::BADFD.is_magiclink_filesystem().is_err(),
            "is_magiclink_filesystem should fail for bad file descriptor"
        );
    }

    #[test]
    fn metadata_badfd() {
        assert!(
            syscalls::BADFD.metadata().is_err(),
            "metadata should fail for bad file descriptor"
        );
    }

    #[test]
    fn metadata() -> Result<(), Error> {
        let file = File::open("/").context("open dummy file")?;

        let file_meta = file.metadata().context("fstat file")?;
        let fd_meta = file.as_fd().metadata().context("fstat fd")?;

        assert_eq!(file_meta.dev(), fd_meta.dev(), "dev must match");
        assert_eq!(file_meta.ino(), fd_meta.ino(), "ino must match");
        assert_eq!(file_meta.mode(), fd_meta.mode(), "mode must match");
        assert_eq!(file_meta.nlink(), fd_meta.nlink(), "nlink must match");
        assert_eq!(file_meta.uid(), fd_meta.uid(), "uid must match");
        assert_eq!(file_meta.gid(), fd_meta.gid(), "gid must match");
        assert_eq!(file_meta.rdev(), fd_meta.rdev(), "rdev must match");
        assert_eq!(file_meta.size(), fd_meta.size(), "size must match");
        assert_eq!(file_meta.atime(), fd_meta.atime(), "atime must match");
        assert_eq!(
            file_meta.atime_nsec(),
            fd_meta.atime_nsec(),
            "atime_nsec must match"
        );
        assert_eq!(file_meta.mtime(), fd_meta.mtime(), "mtime must match");
        assert_eq!(
            file_meta.mtime_nsec(),
            fd_meta.mtime_nsec(),
            "mtime_nsec must match"
        );
        assert_eq!(file_meta.ctime(), fd_meta.ctime(), "ctime must match");
        assert_eq!(
            file_meta.ctime_nsec(),
            fd_meta.ctime_nsec(),
            "ctime_nsec must match"
        );
        assert_eq!(file_meta.blksize(), fd_meta.blksize(), "blksize must match");
        assert_eq!(file_meta.blocks(), fd_meta.blocks(), "blocks must match");

        Ok(())
    }
}

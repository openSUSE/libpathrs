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
    error::{Error, ErrorExt, ErrorImpl, ErrorKind},
    flags::OpenFlags,
    procfs::{self, ProcfsBase, ProcfsHandle},
    syscalls,
    utils::{self, MaybeOwnedFd, RawProcfsRoot},
};

use std::{
    fs::{self, File},
    io::Error as IOError,
    os::unix::{
        fs::MetadataExt,
        io::{AsFd, AsRawFd, OwnedFd, RawFd},
    },
    path::{Path, PathBuf},
    str::FromStr,
};

use rustix::fs::{self as rustix_fs, StatxFlags};

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
        self.0.st_atime
    }

    fn atime_nsec(&self) -> i64 {
        self.0.st_atime_nsec as i64
    }

    fn mtime(&self) -> i64 {
        self.0.st_mtime
    }

    fn mtime_nsec(&self) -> i64 {
        self.0.st_mtime_nsec as i64
    }

    fn ctime(&self) -> i64 {
        self.0.st_ctime
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

pub(crate) trait FdExt: AsFd {
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
    /// which saves the path a file descriptor references for error messages, as
    /// well as in some test code.
    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error>;

    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_magiclink_filesystem(&self) -> Result<bool, Error>;

    /// Get information about the file descriptor from `fdinfo`.
    ///
    /// This parses the given `field` (**case-sensitive**) from
    /// `/proc/thread-self/fdinfo/$fd` and returns a parsed version of the
    /// value. If the field was not present in `fdinfo`, we return `Ok(None)`.
    ///
    /// Note that this method is not safe against an attacker that can modify
    /// the mount table arbitrarily, though in practice it would be quite
    /// difficult for an attacker to be able to consistently overmount every
    /// `fdinfo` file for a process. This is mainly intended to be used within
    /// [`fetch_mnt_id`] as a final fallback in the procfs resolver (hence no
    /// [`ProcfsHandle`] argument) for pre-5.8 kernels.
    fn get_fdinfo_field<T: FromStr>(
        &self,
        proc_rootfd: RawProcfsRoot<'_>,
        want_field_name: &str,
    ) -> Result<Option<T>, Error>
    where
        T::Err: Into<ErrorImpl> + Into<Error>;

    // TODO: Add get_fdinfo which uses ProcfsHandle, for when we add
    // RESOLVE_NO_XDEV support to Root::resolve.
}

/// Shorthand for reusing [`ProcfsBase::ProcThreadSelf`]'s compatibility checks
/// to get a global-`/proc`-friendly subpath. Should only ever be used for
/// `*_unchecked` functions -- [`ProcfsBase::ProcThreadSelf`] is the right thing
/// to use in general.
pub(in crate::utils) fn proc_threadself_subpath(
    proc_rootfd: RawProcfsRoot<'_>,
    subpath: &str,
) -> PathBuf {
    PathBuf::from(".")
        .join(ProcfsBase::ProcThreadSelf.into_path(proc_rootfd))
        .join(subpath.trim_start_matches('/'))
}

/// Get the right subpath in `/proc/self` for the given file descriptor
/// (including those with "special" values, like `AT_FDCWD`).
fn proc_subpath<Fd: AsRawFd>(fd: Fd) -> Result<String, Error> {
    let fd = fd.as_raw_fd();
    if fd == libc::AT_FDCWD {
        Ok("cwd".to_string())
    } else if fd.is_positive() {
        Ok(format!("fd/{fd}"))
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
        // "/proc/thread-self/fd/$n"
        let fd_path = PathBuf::from("/proc").join(proc_threadself_subpath(
            RawProcfsRoot::UnsafeGlobal,
            &proc_subpath(self.as_fd())?,
        ));

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

    fn get_fdinfo_field<T: FromStr>(
        &self,
        proc_rootfd: RawProcfsRoot<'_>,
        want_field_name: &str,
    ) -> Result<Option<T>, Error>
    where
        T::Err: Into<ErrorImpl> + Into<Error>,
    {
        let fd = self.as_fd();
        let fdinfo_path = match fd.as_raw_fd() {
            // MSRV(1.66): Use ..=0 (half_open_range_patterns).
            // MSRV(1.80): Use ..0 (exclusive_range_pattern).
            fd @ libc::AT_FDCWD | fd @ RawFd::MIN..=0 => Err(ErrorImpl::OsError {
                operation: format!("get relative procfs fdinfo path for fd {fd}").into(),
                source: IOError::from_raw_os_error(libc::EBADF),
            })?,
            fd => proc_threadself_subpath(proc_rootfd, &format!("fdinfo/{fd}")),
        };

        let mut fdinfo_file: File = proc_rootfd
            .open_beneath(fdinfo_path, OpenFlags::O_RDONLY)
            .with_wrap(|| format!("open fd {} fdinfo", fd.as_raw_fd()))?
            .into();

        // As this is called from within fetch_mnt_id as a fallback, the only
        // thing we can do here is verify that it is actually procfs. However,
        // in practice it will be quite difficult for an attacker to over-mount
        // every fdinfo file for a process.
        procfs::verify_is_procfs(&fdinfo_file)?;

        // Get the requested field -- this will also verify that the fdinfo
        // contains an inode number that matches the original fd.
        utils::fd_get_verify_fdinfo(&mut fdinfo_file, fd, want_field_name)
    }
}

pub(crate) fn fetch_mnt_id(
    proc_rootfd: RawProcfsRoot<'_>,
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
) -> Result<u64, Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();

    // The most ideal method of fetching mount IDs for a file descriptor (or
    // subpath) is statx(2) with STATX_MNT_ID_UNIQUE, as it provides a globally
    // unique 64-bit identifier for a mount that cannot be recycled without
    // having to interact with procfs (which is important since this code is
    // called within procfs, so we cannot use ProcfsHandle to protect against
    // attacks).
    //
    // Unfortunately, STATX_MNT_ID_UNIQUE was added in Linux 6.8, so we need to
    // have some fallbacks. STATX_MNT_ID is (for the most part) just as good for
    // our usecase (since we operate relative to a file descriptor, the mount ID
    // shouldn't be recycled while we keep the file descriptor open). This helps
    // a fair bit, but STATX_MNT_ID was still only added in Linux 5.8, and so
    // even some post-openat2(2) systems would be insecure if we just left it at
    // that.
    //
    // As a fallback, we can use the "mnt_id" field from /proc/self/fdinfo/<fd>
    // to get the mount ID -- unlike statx(2), this functionality has existed on
    // Linux since time immemorial and thus we can error out if this operation
    // fails. This does require us to operate on procfs in a less-safe way
    // (unlike the alternative approaches), however note that:
    //
    //  * For openat2(2) systems, this is completely safe (fdinfo files are regular
    //    files, and thus -- unlike magic-links -- RESOLVE_NO_XDEV can be used to
    //    safely protect against bind-mounts).
    //
    //  * For non-openat2(2) systems, an attacker can theoretically attack this by
    //    overmounting fdinfo with something like /proc/self/environ and fill it
    //    with a fake fdinfo file.
    //
    //    However, get_fdinfo_field and fd_get_verify_fdinfo have enough extra
    //    protections that would probably make it infeasible for an attacker to
    //    easily bypass it in practice. You can see the comments there for more
    //    details, but in short an attacker would probably need to be able to
    //    predict the file descriptor numbers for several transient files as
    //    well as the inode number of the target file, and be able to create
    //    overmounts while racing against libpathrs -- it seems unlikely that
    //    this would be trivial to do (especially compared to how trivial
    //    attacks are without these protections).
    //
    // NOTE: A very old trick for getting mount IDs in a race-free way was to
    //       (ab)use name_to_handle_at(2) -- if you request a file handle with
    //       too small a buffer, name_to_handle_at(2) will return -EOVERFLOW but
    //       will still give you the mount ID. Sadly, name_to_handle_at(2) did
    //       not work on procfs (or any other pseudofilesystem) until
    //       AT_HANDLE_FID supported was added in Linux 6.7 (at which point
    //       there's no real benefit to using it).
    //
    //       Maybe we could use this for RESOLVE_NO_XDEV emulation in the
    //       EmulatedOpath resolver, but for procfs this approach is not useful.
    //
    // NOTE: Obvious alternatives like parsing /proc/self/mountinfo can be
    //       dismissed out-of-hand as not being useful (mountinfo is trivially
    //       bypassable by an attacker with mount privileges, is generally awful
    //       to parse, and doesn't work with open_tree(2)-style detached
    //       mounts).

    const STATX_MNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
    let want_mask = StatxFlags::MNT_ID | STATX_MNT_ID_UNIQUE;

    let mnt_id = match syscalls::statx(dirfd, path, want_mask) {
        Ok(stx) => {
            let got_mask = StatxFlags::from_bits_retain(stx.stx_mask);
            if got_mask.intersects(want_mask) {
                Some(stx.stx_mnt_id)
            } else {
                None
            }
        }
        Err(err) => match err.root_cause().raw_os_error() {
            // We have to handle STATX_MNT_ID not being supported on pre-5.8
            // kernels, so treat an ENOSYS or EINVAL the same so that we can
            // work on pre-4.11 (pre-statx) kernels as well.
            Some(libc::ENOSYS) | Some(libc::EINVAL) => None,
            _ => Err(ErrorImpl::RawOsError {
                operation: "check mnt_id of filesystem".into(),
                source: err,
            })?,
        },
    }
    // Kind of silly intermediate Result<_, Error> type so that we can use
    // Result::or_else.
    // TODO: In principle we could remove this once result_flattening is
    // stabilised...
    .ok_or_else(|| {
        ErrorImpl::NotSupported {
            feature: "STATX_MNT_ID".into(),
        }
        .into()
    })
    .or_else(|_: Error| -> Result<_, Error> {
        // openat doesn't support O_EMPTYPATH, so if we are operating on "" we
        // should reuse the dirfd directly.
        let file = if path.as_os_str().is_empty() {
            MaybeOwnedFd::BorrowedFd(dirfd)
        } else {
            MaybeOwnedFd::OwnedFd(syscalls::openat(dirfd, path, OpenFlags::O_PATH, 0).map_err(
                |err| ErrorImpl::RawOsError {
                    operation: "open target file for mnt_id check".into(),
                    source: err,
                },
            )?)
        };
        let file = file.as_fd();

        match file
            .get_fdinfo_field(proc_rootfd, "mnt_id")
            .map_err(|err| (err.kind(), err))
        {
            Ok(Some(mnt_id)) => Ok(mnt_id),
            // "mnt_id" *must* exist as a field -- make sure we return a
            // SafetyViolation here if it is missing or an invalid value
            // (InternalError), otherwise an attacker could silence this check
            // by creating a "mnt_id"-less fdinfo.
            // TODO: Should we actually match for ErrorImpl::ParseIntError here?
            Ok(None) | Err((ErrorKind::InternalError, _)) => Err(ErrorImpl::SafetyViolation {
                description: format!(
                    r#"fd {:?} has a fake fdinfo: invalid or missing "mnt_id" field"#,
                    file.as_raw_fd(),
                )
                .into(),
            }
            .into()),
            // Pass through any other errors.
            Err((_, err)) => Err(err),
        }
    })?;

    Ok(mnt_id)
}

#[cfg(test)]
mod tests {
    use crate::{
        flags::OpenFlags,
        procfs::ProcfsHandle,
        syscalls,
        utils::{FdExt, RawProcfsRoot},
    };

    use std::{
        fs::File,
        os::unix::{fs::MetadataExt, io::AsFd},
        path::Path,
    };

    use anyhow::{Context, Error};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    fn check_as_unsafe_path(fd: impl AsFd, want_path: impl AsRef<Path>) -> Result<(), Error> {
        let want_path = want_path.as_ref();

        // Plain /proc/... lookup.
        let got_path = fd.as_unsafe_path_unchecked()?;
        assert_eq!(
            got_path, want_path,
            "expected as_unsafe_path_unchecked to give the correct path"
        );
        // ProcfsHandle-based lookup.
        let got_path = fd.as_unsafe_path(&ProcfsHandle::new()?)?;
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
    fn as_unsafe_path_badfd() -> Result<(), Error> {
        assert!(
            syscalls::BADFD.as_unsafe_path_unchecked().is_err(),
            "as_unsafe_path_unchecked should fail for bad file descriptor"
        );
        assert!(
            syscalls::BADFD
                .as_unsafe_path(&ProcfsHandle::new()?)
                .is_err(),
            "as_unsafe_path should fail for bad file descriptor"
        );
        Ok(())
    }

    #[test]
    fn reopen_badfd() -> Result<(), Error> {
        assert!(
            syscalls::BADFD
                .reopen(&ProcfsHandle::new()?, OpenFlags::O_PATH)
                .is_err(),
            "reopen should fail for bad file descriptor"
        );
        Ok(())
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

    #[test]
    fn get_fdinfo_field() -> Result<(), Error> {
        let file = File::open("/").context("open dummy file")?;

        assert_eq!(
            file.get_fdinfo_field::<u64>(RawProcfsRoot::UnsafeGlobal, "pos")?,
            Some(0),
            "pos should be parsed and zero for new file"
        );

        assert_eq!(
            file.get_fdinfo_field::<String>(RawProcfsRoot::UnsafeGlobal, "flags")?,
            Some("02100000".to_string()),
            "flags should be parsed for new file"
        );

        assert_ne!(
            file.get_fdinfo_field::<u64>(RawProcfsRoot::UnsafeGlobal, "mnt_id")?
                .expect("should find mnt_id in fdinfo"),
            0,
            "mnt_id should be parsed and non-nil for any real file"
        );

        assert_eq!(
            file.get_fdinfo_field::<u64>(RawProcfsRoot::UnsafeGlobal, "non_exist")?,
            None,
            "non_exist should not be present in fdinfo"
        );

        Ok(())
    }

    #[test]
    fn get_fdinfo_field_proc_rootfd() -> Result<(), Error> {
        let procfs = ProcfsHandle::new().context("open procfs handle")?;
        let file = File::open("/").context("open dummy file")?;

        assert_eq!(
            file.get_fdinfo_field::<u64>(procfs.as_raw_procfs(), "pos")?,
            Some(0),
            "pos should be parsed and zero for new file"
        );

        assert_eq!(
            file.get_fdinfo_field::<String>(procfs.as_raw_procfs(), "flags")?,
            Some("02100000".to_string()),
            "flags should be parsed for new file"
        );

        assert_ne!(
            file.get_fdinfo_field::<u64>(procfs.as_raw_procfs(), "mnt_id")?
                .expect("should find mnt_id in fdinfo"),
            0,
            "mnt_id should be parsed and non-nil for any real file"
        );

        assert_eq!(
            file.get_fdinfo_field::<u64>(procfs.as_raw_procfs(), "non_exist")?,
            None,
            "non_exist should not be present in fdinfo"
        );

        Ok(())
    }
}

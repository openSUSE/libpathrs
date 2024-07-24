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

#![forbid(unsafe_code)]

use crate::{
    error::{self, Error},
    syscalls, utils, OpenFlags,
};

use std::{
    convert::TryFrom,
    fs::File,
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use snafu::{OptionExt, ResultExt};

lazy_static! {
    /// A `procfs` handle to which is used globally by libpathrs.
    pub(crate) static ref PROCFS_HANDLE: ProcfsHandle =
        ProcfsHandle::new().expect("should be able to get some /proc handle");
}

/// Indicate what base directory should be used when doing `/proc/...`
/// operations with [`ProcfsHandle`]. This is necessary because
/// `/proc/thread-self` is not present on pre-3.17 kernels and so it may be
/// necessary to emulate `/proc/thread-self` access on those older kernels.
///
/// [`ProcfsHandle`]: struct.ProcfsHandle.html
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // TODO: Remove when we export this properly.
pub(crate) enum ProcfsBase {
    /// Use `/proc/self`. For most programs, this is the standard choice.
    ProcSelf,
    /// Use `/proc/thread-self`. In multi-threaded programs where one thread has
    /// a different `CLONE_FS`, it is possible for `/proc/self` to point the
    /// wrong thread and so `/proc/thread-self` may be necessary.
    ProcThreadSelf,
}

impl ProcfsBase {
    pub(crate) fn into_path(self) -> PathBuf {
        match self {
            Self::ProcSelf => PathBuf::from("self"),
            // TODO: Add fallback handling for pre-3.17 kernels.
            Self::ProcThreadSelf => PathBuf::from("thread-self"),
        }
    }
    // TODO: Add into_raw_path() that doesn't use symlinks?
}

/// A wrapper around a handle to `/proc` that is designed to be safe against
/// various attacks.
///
/// Unlike most regular filesystems, `/proc` serves several important purposes
/// for system administration programs:
///
///  1. As a mechanism for doing certain filesystem operations through
///     `/proc/self/fd/...` (and other similar magic-links) that cannot be done
///     by other means.
///  2. As a source of true information about processes and the general system.
///  3. As an administrative tool for managing other processes (such as setting
///     LSM labels).
///
/// libpathrs uses `/proc` internally for the first purpose and many libpathrs
/// users use `/proc` for all three. As such, it is not sufficient that
/// operations on `/proc` paths do not escape the `/proc` filesystem -- it is
/// absolutely critical that operations through `/proc` operate on the path that
/// the caller expected.
///
/// This might seem like an esoteric concern, but there have been several
/// security vulnerabilities where a maliciously configured `/proc` could be
/// used to trick administrative processes into doing unexpected operations (for
/// example, [CVE-2019-16884][] and [CVE-2019-19921][]). See [this
/// video][lca2020] for a longer explanation of the many other issues that
/// `/proc`-based checking is needed to protect against and [this other
/// video][lpc2022] for some other procfs challenges libpathrs has to contend
/// with.
///
/// NOTE: At the moment, `ProcfsHandle` only supports doing operations within
/// `/proc/self` and `/proc/thread-self/`. This is because there are tools like
/// [lxcfs] which intentionally mask parts of `/proc` in order to fix issues
///
/// [cve-2019-16884]: https://nvd.nist.gov/vuln/detail/CVE-2019-16884
/// [cve-2019-19921]: https://nvd.nist.gov/vuln/detail/CVE-2019-19921
/// [lca2020]: https://youtu.be/tGseJW_uBB8
/// [lpc2022]: https://youtu.be/y1PaBzxwRWQ
/// [lxcfs]: https://github.com/lxc/lxcfs
#[derive(Debug)]
pub(crate) struct ProcfsHandle {
    inner: File,
}

// TODO: Add mnt_id hardening.

// TODO: Use a restricted resolver for doing subpath lookups.

impl ProcfsHandle {
    // This is part of Linux's ABI.
    const PROC_ROOT_INO: u64 = 1;

    pub fn new() -> Result<Self, Error> {
        // TODO: Add support for fsopen(2) and open_tree(2) based proc handles,
        // which are safe against racing mounts (for the privileged users that
        // can create them).
        syscalls::openat(libc::AT_FDCWD, "/proc", libc::O_PATH | libc::O_DIRECTORY, 0)
            .context(error::RawOsSnafu {
                operation: "open /proc handle",
            })
            // NOTE: try_from checks this is an actual procfs root.
            .and_then(Self::try_from)
    }

    fn check_is_procfs(file: &File) -> Result<(), Error> {
        let fs_type = syscalls::fstatfs(file.as_raw_fd())
            .context(error::RawOsSnafu {
                operation: "fstatfs proc handle",
            })?
            .f_type;
        ensure!(
            fs_type == libc::PROC_SUPER_MAGIC,
            error::SafetyViolationSnafu {
                description: format!(
                    "/proc is not procfs (f_type is 0x{:X}, not 0x{:X})",
                    fs_type,
                    libc::PROC_SUPER_MAGIC
                ),
            }
        );
        Ok(())
    }

    fn open_base(&self, base: ProcfsBase) -> Result<File, Error> {
        // TODO: Switch this with a proper resolver.
        let file = syscalls::openat_follow(
            self.inner.as_raw_fd(),
            base.into_path(),
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )
        .context(error::RawOsSnafu {
            operation: "open procfs base path",
        })?;
        // TODO: Until we add STATX_MNT_ID checks, the best we can do is check
        // the fs_type to avoid mounts non-procfs filesystems. Unfortunately,
        // attackers can bind-mount procfs files and still cause damage so this
        // protection is marginal at best.
        Self::check_is_procfs(&file)?;
        Ok(file)
    }

    pub fn open_follow<P: AsRef<Path>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        mut flags: OpenFlags,
    ) -> Result<File, Error> {
        let subpath = subpath.as_ref();

        // Drop any trailing /-es.
        let (subpath, trailing_slash) = utils::path_strip_trailing_slash(subpath);
        if trailing_slash {
            // A trailing / implies we want O_DIRECTORY.
            flags.insert(OpenFlags::O_DIRECTORY);
        }

        // If the target is not a symlink, use an O_NOFOLLOW open. This defends
        // against C users forgetting to set O_NOFOLLOW for files that aren't
        // magic-links and thus shouldn't be followed.
        //
        // We could do this after splitting the path and getting the directory
        // components (to reduce the amount of work on non-openat2 systems), but
        // that would be more work for openat2 systems so let's give preference
        // to openat2.
        if self.readlink(base, subpath).is_err() {
            return self.open(base, subpath, flags);
        }

        // Get a no-follow handle to the parent of the magic-link.
        let (parent, trailing) = utils::path_split(subpath)?;
        let trailing = trailing.context(error::InvalidArgumentSnafu {
            name: "path",
            description: "proc_open_follow path has trailing slash",
        })?;

        let parent = self.open(base, parent, OpenFlags::O_PATH | OpenFlags::O_DIRECTORY)?;

        // TODO: Until we add STATX_MNT_ID checks, the best we can do is check
        // the fs_type to avoid mounts non-procfs filesystems. Unfortunately,
        // attackers can bind-mount procfs files and still cause damage so this
        // protection is marginal at best.
        Self::check_is_procfs(&parent)?;

        syscalls::openat_follow(parent.as_raw_fd(), trailing, flags.bits(), 0).context(
            error::RawOsSnafu {
                operation: "open final magiclink component",
            },
        )
    }

    pub fn open<P: AsRef<Path>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        flags: OpenFlags,
    ) -> Result<File, Error> {
        let base = self.open_base(base)?;

        // TODO: Switch this with a proper resolver.
        let file = syscalls::openat(
            base.as_raw_fd(),
            subpath,
            flags.bits() | libc::O_PATH | libc::O_NOFOLLOW,
            0,
        )
        .context(error::RawOsSnafu {
            operation: "open procfs path",
        })?;
        // TODO: Until we add STATX_MNT_ID checks, the best we can do is check
        // the fs_type to avoid mounts non-procfs filesystems. Unfortunately,
        // attackers can bind-mount procfs files and still cause damage so this
        // protection is marginal at best.
        Self::check_is_procfs(&file)?;
        Ok(file)
    }

    pub fn readlink<P: AsRef<Path>>(&self, base: ProcfsBase, subpath: P) -> Result<PathBuf, Error> {
        let link = self.open(base, subpath, OpenFlags::O_PATH | OpenFlags::O_NOFOLLOW)?;
        syscalls::readlinkat(link.as_raw_fd(), "").context(error::RawOsSnafu {
            operation: "read procfs magiclink",
        })
    }
}

impl TryFrom<File> for ProcfsHandle {
    type Error = Error;

    fn try_from(inner: File) -> Result<Self, Self::Error> {
        // Make sure the file is actually a procfs handle.
        Self::check_is_procfs(&inner)?;

        // And make sure it's the root of procfs. The root directory is
        // guaranteed to have an inode number of PROC_ROOT_INO. If this check
        // ever stops working, it's a kernel regression.
        let ino = inner.metadata().expect("fstat(/proc) should work").ino();
        ensure!(
            ino == Self::PROC_ROOT_INO,
            error::SafetyViolationSnafu {
                description: format!(
                    "/proc is not root of a procfs mount (ino is 0x{:X}, not 0x{:X})",
                    ino,
                    Self::PROC_ROOT_INO,
                )
            }
        );

        Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    #[test]
    fn bad_root() {
        let file = File::open("/").expect("open root");
        let procfs = ProcfsHandle::try_from(file);

        assert!(
            procfs.is_err(),
            "creating a procfs handle from the wrong filesystem should return an error"
        );
    }

    #[test]
    fn bad_tmpfs() {
        let file = File::open("/tmp").expect("open tmpfs");
        let procfs = ProcfsHandle::try_from(file);

        assert!(
            procfs.is_err(),
            "creating a procfs handle from the wrong filesystem should return an error"
        );
    }

    #[test]
    fn bad_proc_nonroot() {
        let file = File::open("/proc/tty").expect("open tmpfs");
        let procfs = ProcfsHandle::try_from(file);

        assert!(
            procfs.is_err(),
            "creating a procfs handle from non-root of procfs should return an error"
        );
    }

    #[test]
    fn new() {
        let procfs = ProcfsHandle::new();
        assert!(
            procfs.is_ok(),
            "new procfs handle should succeed, got {:?}",
            procfs
        );
    }
}

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
    resolvers::{procfs::ProcfsResolver, ResolverFlags},
    syscalls::{self, FsmountFlags, FsopenFlags, OpenTreeFlags},
    utils, OpenFlags,
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
/// operations with a [`ProcfsHandle`].
///
/// This is necessary because `/proc/thread-self` is not present on pre-3.17
/// kernels and so it may be necessary to emulate `/proc/thread-self` access on
/// those older kernels.
///
/// Most users should use `ProcfsBase::ProcSelf`, but certain users (such as
/// multi-threaded programs where you really want thread-specific information)
/// may want to use `ProcSelf::ProcThreadSelf`. Note that on systems that use
/// green threads (such as Go), you must take care to ensure the thread stays
/// alive until you stop using the handle (if the thread dies the handle may
/// start returning invalid data or errors because it refers to a specific
/// thread that no longer exists).
///
/// [`ProcfsHandle`]: struct.ProcfsHandle.html
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum ProcfsBase {
    /// Use `/proc/self`. For most programs, this is the standard choice.
    ProcSelf,
    /// Use `/proc/thread-self`. In multi-threaded programs where one thread has
    /// a different `CLONE_FS`, it is possible for `/proc/self` to point the
    /// wrong thread and so `/proc/thread-self` may be necessary.
    ProcThreadSelf,
}

impl ProcfsBase {
    pub(crate) fn into_path(self, proc_root: Option<&File>) -> PathBuf {
        match self {
            Self::ProcSelf => PathBuf::from("self"),
            Self::ProcThreadSelf => vec![
                // /proc/thread-self was added in Linux 3.17.
                "thread-self".into(),
                // For pre-3.17 kernels we use the fully-expanded version.
                format!("self/task/{}", syscalls::gettid()).into(),
                // However, if the proc root is not using our pid namespace, the
                // tid in /proc/self/task/... will be wrong and we need to fall
                // back to /proc/self. This is technically incorrect but we have
                // no other choice.
                "self".into(),
            ]
            .into_iter()
            // Return the first option that exists in proc_root.
            .find(|base| {
                match proc_root {
                    Some(root) => syscalls::fstatat(root.as_raw_fd(), base),
                    None => syscalls::fstatat(libc::AT_FDCWD, PathBuf::from("/proc").join(base)),
                }
                .is_ok()
            })
            .expect("at least one candidate /proc/thread-self path should work"),
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
/// `/proc/self` and `/proc/thread-self`. This is because there are tools like
/// [lxcfs] which intentionally mask parts of `/proc` in order to fix issues
/// like `/proc/meminfo` and `/proc/cpuinfo` not being cgroup-aware.
/// `ProcfsHandle` will refuse to open files that have these overmounts, which
/// could lead to application errors that users may not expect. However, no such
/// tool masks paths inside `/proc/$pid` directories because such masking would
/// be expensive (because of FUSE limitations, you would need to emulate every
/// file within `/proc` to do this properly) and would cause application-visible
/// issues (magic-link lookups would not work as they normally do). So we can
/// safely provide handlers for `/proc/self` and `/proc/thread-self` (which are
/// the main things a lot of libpathrs users care about).
///
/// [cve-2019-16884]: https://nvd.nist.gov/vuln/detail/CVE-2019-16884
/// [cve-2019-19921]: https://nvd.nist.gov/vuln/detail/CVE-2019-19921
/// [lca2020]: https://youtu.be/tGseJW_uBB8
/// [lpc2022]: https://youtu.be/y1PaBzxwRWQ
/// [lxcfs]: https://github.com/lxc/lxcfs
#[derive(Debug)]
pub struct ProcfsHandle {
    inner: File,
    mnt_id: Option<u64>,
    pub(crate) resolver: ProcfsResolver,
}

impl ProcfsHandle {
    // This is part of Linux's ABI.
    const PROC_ROOT_INO: u64 = 1;

    /// Create a new `fsopen(2)`-based [`ProcfsHandle`]. This handle is safe
    /// against racing attackers changing the mount table and is guaranteed to
    /// have no overmounts because it is a brand-new procfs.
    ///
    /// [`ProcfsHandle`]: struct.ProcfsHandle.html
    pub(crate) fn new_fsopen() -> Result<Self, Error> {
        let sfd =
            syscalls::fsopen("proc", FsopenFlags::FSOPEN_CLOEXEC).context(error::RawOsSnafu {
                operation: "create procfs suberblock",
            })?;

        // Try to configure hidepid=ptraceable,subset=pid if possible, but
        // ignore errors.
        let _ = syscalls::fsconfig_set_string(sfd.as_raw_fd(), "hidepid", "ptraceable");
        let _ = syscalls::fsconfig_set_string(sfd.as_raw_fd(), "subset", "pid");

        syscalls::fsconfig_create(sfd.as_raw_fd()).context(error::RawOsSnafu {
            operation: "instantiate procfs superblock",
        })?;

        syscalls::fsmount(
            sfd.as_raw_fd(),
            FsmountFlags::FSMOUNT_CLOEXEC,
            libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
        )
        .context(error::RawOsSnafu {
            operation: "mount new private procfs",
        })
        // NOTE: try_from checks this is an actual procfs root.
        .and_then(Self::try_from)
    }

    /// Create a new `open_tree(2)`-based [`ProcfsHandle`]. This handle is
    /// guaranteed to be safe against racing attackers, and will not have
    /// overmounts unless `flags` contains `OpenTreeFlags::AT_RECURSIVE`.
    ///
    /// [`ProcfsHandle`]: struct.ProcfsHandle.html
    pub(crate) fn new_open_tree(flags: OpenTreeFlags) -> Result<Self, Error> {
        syscalls::open_tree(
            -libc::EBADF,
            "/proc",
            OpenTreeFlags::OPEN_TREE_CLONE | flags,
        )
        .context(error::RawOsSnafu {
            operation: "create private /proc bind-mount",
        })
        // NOTE: try_from checks this is an actual procfs root.
        .and_then(Self::try_from)
    }

    /// Create a plain `open(2)`-style [`ProcfsHandle`].
    ///
    /// This handle is NOT safe against racing attackers and overmounts.
    ///
    /// [`ProcfsHandle`]: struct.ProcfsHandle.html
    pub(crate) fn new_unsafe_open() -> Result<Self, Error> {
        syscalls::openat(libc::AT_FDCWD, "/proc", libc::O_PATH | libc::O_DIRECTORY, 0)
            .context(error::RawOsSnafu {
                operation: "open /proc handle",
            })
            // NOTE: try_from checks this is an actual procfs root.
            .and_then(Self::try_from)
    }

    /// Create a new handle that references a safe `/proc`.
    ///
    /// For privileged users (those that have the ability to create mounts) on
    /// new enough kernels (Linux 5.1 or later), this created handle will be
    /// safe racing attackers that . If your `/proc` does not have locked
    /// overmounts (which is the case for most users except those running inside
    /// a nested container with user namespaces) then the handle will also be
    /// completely safe against overmounts.
    ///
    /// For the userns-with-locked-overmounts case, on slightly newer kernels
    /// (those with `STATX_MNT_ID` support -- Linux 5.8 or later)
    /// [`ProcfsHandle::open`] and [`ProcfsHandle::open_follow`] this handle
    /// will be safe against overmounts.
    ///
    /// For unprivileged users, this handle will not be safe against a racing
    /// attacker that can modify the mount table while doing operations.
    /// However, the Linux 5.8-or-later `STATX_MNT_ID` protections will protect
    /// against static overmounts created by an attacker that cannot modify the
    /// mount table while these operations are running.
    ///
    /// [`ProcfsHandle`]: struct.ProcfsHandle.html
    /// [`ProcfsHandle::open`]: struct.ProcfsHandle.html#method.open
    /// [`ProcfsHandle::open_follow`]: struct.ProcfsHandle.html#method.open_follow
    pub fn new() -> Result<Self, Error> {
        Self::new_fsopen()
            .or_else(|_| Self::new_open_tree(OpenTreeFlags::empty()))
            .or_else(|_| Self::new_open_tree(OpenTreeFlags::AT_RECURSIVE))
            .or_else(|_| Self::new_unsafe_open())
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

    fn check_mnt_id<P: AsRef<Path>>(&self, dir: &File, path: P) -> Result<(), Error> {
        let mnt_id = utils::fetch_mnt_id(dir, path)?;
        ensure!(
            self.mnt_id == mnt_id,
            error::SafetyViolationSnafu {
                // TODO: Include the full path in the error.
                description: format!(
                    "mount id mismatch for procfs subpath (mnt_id is {:?}, not procfs {:?})",
                    mnt_id, self.mnt_id
                ),
            }
        );
        Ok(())
    }

    fn open_base(&self, base: ProcfsBase) -> Result<File, Error> {
        let file = self.resolver.resolve(
            &self.inner,
            base.into_path(Some(&self.inner)),
            OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
            ResolverFlags::empty(),
        )?;
        // Detect if the file we landed is in a bind-mount.
        self.check_mnt_id(&file, "")?;
        // For pre-5.8 kernels there is no STATX_MNT_ID, so the best we can
        // do is check the fs_type to avoid mounts non-procfs filesystems.
        // Unfortunately, attackers can bind-mount procfs files and still
        // cause damage so this protection is marginal at best.
        Self::check_is_procfs(&file)?;
        Ok(file)
    }

    /// Safely open a magic-link inside `procfs`.
    ///
    /// The semantics of this method are very similar to [`ProcfsHandle::open`],
    /// with the following differences:
    ///
    ///  - The final component of the path will be opened with very minimal
    ///    protections. This is necessary because magic-links by design involve
    ///    mountpoint crossings and cannot be confined. This method does verify
    ///    that the symlink itself doesn't have any overmounts, but this
    ///    verification is only safe against races for [`ProcfsHandle`]s created
    ///    by privileged users.
    ///
    ///  - A trailing `/` at the end of `subpath` implies `O_DIRECTORY`.
    ///
    /// Most users should use [`ProcfsHandle::open`]. This method should only be
    /// used to open magic-links like `/proc/self/exe` or `/proc/self/fd/$n`.
    ///
    /// In addition (like [`ProcfsHandle::open`]), `open_follow` will not permit
    /// a magic-link to be a path component (ie. `/proc/self/root/etc/passwd`).
    /// This method *only* permits *trailing* symlinks.
    ///
    /// [`ProcfsHandle`]: struct.ProcfsHandle.html
    /// [`ProcfsHandle::open`]: struct.ProcfsHandle.html#method.open
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
        //
        // NOTE: There is technically a race here, but it relies the target path
        //       being a magic-link and then another thing being mounted on top.
        //       This is the same race as below.
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

        // Detect if the magic-link we are about to open is actually a
        // bind-mount.
        // NOTE: This check is only safe if there are no racing mounts, so only
        // for the ProcfsHandle::{new_fsopen,new_open_tree} cases.
        self.check_mnt_id(&parent, trailing)?;

        syscalls::openat_follow(parent.as_raw_fd(), trailing, flags.bits(), 0).context(
            error::RawOsSnafu {
                operation: "open final magiclink component",
            },
        )
    }

    /// Safely open a path inside `procfs`.
    ///
    /// The provided `subpath` is relative to the [`ProcfsBase`] (and must not
    /// contain `..` components -- [`openat2(2)`] permits `..` in some cases but
    /// the restricted `O_PATH` resolver for older kernels doesn't and thus
    /// using `..` could result in application errors when running on pre-5.6
    /// kernels).
    ///
    /// The provided `OpenFlags` apply to the returned [`File`]. However, note
    /// that the following flags are not allowed and using them will result in
    /// an error:
    ///
    ///  - `O_CREAT`
    ///  - `O_EXCL`
    ///  - `O_TMPFILE`
    ///
    /// # Symlinks
    ///
    /// This method *will not follow any magic links*, and also implies
    /// `O_NOFOLLOW` so *trailing symlinks will also not be followed*
    /// (regardless of type). Regular symlink path components are followed
    /// however (though lookups are forced to stay inside the `procfs`
    /// referenced by `ProcfsHandle`).
    ///
    /// If you wish to open a magic-link (such as `/proc/self/fd/$n` or
    /// `/proc/self/exe`), use [`ProcfsHandle::open_follow`] instead.
    ///
    /// # Mountpoint Crossings
    ///
    /// All mount point crossings are also forbidden (including bind-mounts),
    /// meaning that this method implies [`RESOLVE_NO_XDEV`][`openat2(2)`].
    ///
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    /// [`ProcfsBase`]: enum.ProcfsBase.html
    /// [`ProcfsHandle`]: struct.ProcfsHandle.html
    /// [`openat2(2)`]: https://www.man7.org/linux/man-pages/man2/openat2.2.html
    pub fn open<P: AsRef<Path>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        mut flags: OpenFlags,
    ) -> Result<File, Error> {
        // Force-set O_NOFOLLOW, though NO_FOLLOW_TRAILING should be sufficient.
        flags.insert(OpenFlags::O_NOFOLLOW);

        // Do a basic lookup.
        let base = self.open_base(base)?;
        let file = self
            .resolver
            .resolve(&base, subpath, flags, ResolverFlags::empty())?;

        // Detect if the file we landed is in a bind-mount.
        self.check_mnt_id(&file, "")?;
        // For pre-5.8 kernels there is no STATX_MNT_ID, so the best we can
        // do is check the fs_type to avoid mounts non-procfs filesystems.
        // Unfortunately, attackers can bind-mount procfs files and still
        // cause damage so this protection is marginal at best.
        Self::check_is_procfs(&file)?;

        Ok(file)
    }

    /// Safely read the contents of a symlink inside `procfs`.
    ///
    /// This method is effectively shorthand for doing [`readlinkat(2)`] on the
    /// handle you'd get from `ProcfsHandle::open(..., OpenFlags::O_PATH)`. So
    /// all of the caveats from [`ProcfsHandle::open`] apply to this method as
    /// well.
    ///
    /// [`readlinkat(2)`]: https://www.man7.org/linux/man-pages/man2/readlinkat.2.html
    /// [`ProcfsHandle::open`]: struct.ProcfsHandle.html#method.open
    pub fn readlink<P: AsRef<Path>>(&self, base: ProcfsBase, subpath: P) -> Result<PathBuf, Error> {
        let link = self.open(base, subpath, OpenFlags::O_PATH)?;
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

        let mnt_id = utils::fetch_mnt_id(&inner, "")?;
        let resolver = ProcfsResolver::default();

        Ok(Self {
            inner,
            mnt_id,
            resolver,
        })
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

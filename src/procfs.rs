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

#![forbid(unsafe_code)]

//! Helpers to operate on `procfs` safely.

use crate::{
    error::{Error, ErrorExt, ErrorImpl, ErrorKind},
    flags::{OpenFlags, ResolverFlags},
    resolvers::procfs::ProcfsResolver,
    syscalls,
    utils::{self, FdExt},
};

use std::{
    fs::File,
    io::Error as IOError,
    os::unix::{
        fs::MetadataExt,
        io::{AsFd, BorrowedFd, OwnedFd},
    },
    path::{Path, PathBuf},
};

use rustix::{
    fs::{self as rustix_fs, Access, AtFlags},
    mount::{FsMountFlags, FsOpenFlags, MountAttrFlags, OpenTreeFlags},
};

/// Indicate what base directory should be used when doing `/proc/...`
/// operations with a [`ProcfsHandle`].
///
/// Most users should use [`ProcSelf`], but certain users (such as
/// multi-threaded programs where you really want thread-specific information)
/// may want to use [`ProcThreadSelf`].
///
/// [`ProcSelf`]: Self::ProcSelf
/// [`ProcThreadSelf`]: Self::ProcThreadSelf
#[doc(alias = "pathrs_proc_base_t")]
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ProcfsBase {
    /// Use `/proc`. As this requires us to disable any masking of our internal
    /// procfs mount, any file handles returned from [`ProcfsHandle::open`]
    /// using `ProcRoot` should be treated with extra care to ensure you do not
    /// leak them into containers. Ideally users should use [`ProcSelf`] if
    /// possible.
    ///
    /// [`ProcSelf`]: Self::ProcSelf
    ProcRoot,

    /// Use `/proc/<pid>`. This is useful shorthand when looking up information
    /// about other processes (the alternative being passing the PID as a string
    /// component with [`ProcRoot`][`Self::ProcRoot`] manually).
    ///
    /// Note that this operation is inherently racy -- the process referenced by
    /// this PID may have died and the PID recycled with a different process. In
    /// principle, this means that it is only really safe to use this with:
    ///
    ///  * PID 1 (the init process), as that PID cannot ever get recycled.
    ///  * Your current PID (though you should just use [`ProcSelf`]).
    ///  * Your current TID (though you should just use [`ProcThreadSelf`]), or
    ///    _possibly_ other TIDs in your thread-group if you are absolutely sure
    ///    they have not been reaped (typically with [`JoinHandle::join`],
    ///    though there are other ways).
    ///  * PIDs of child processes (as long as you are sure that no other part
    ///    of your program incorrectly catches or ignores `SIGCHLD`, and that
    ///    you do it *before* you call [`wait(2)`] or any equivalent method that
    ///    could reap zombies).
    ///
    /// Outside of those specific uses, users should probably avoid using this.
    // TODO: Add support for pidfds, to resolve the race issue.
    ///
    /// [`ProcRoot`]: Self::ProcRoot
    /// [`ProcSelf`]: Self::ProcSelf
    /// [`ProcThreadSelf`]: Self::ProcThreadSelf
    /// [`JoinHandle::join`]: https://doc.rust-lang.org/std/thread/struct.JoinHandle.html#method.join
    /// [`pthread_join(3)`]: https://man7.org/linux/man-pages/man3/pthread_join.3.html
    /// [`wait(2)`]: https://man7.org/linux/man-pages/man2/wait.2.html
    // NOTE: It seems incredibly unlikely that this will ever need to be
    //       expanded beyond u32. glibc has always used u16 for pid_t, and the
    //       kernel itself (even at time of writing) only supports a maximum of
    //       2^22 PIDs internally. Even the newest pid-related APIs
    //       (PIDFD_GET_INFO for instance) only allocate a u32 for pids. By
    //       making this a u32 we can easily pack it inside a u64 for the C API.
    ProcPid(u32),

    /// Use `/proc/self`. For most programs, this is the standard choice.
    ProcSelf,

    /// Use `/proc/thread-self`. In multi-threaded programs, it is possible for
    /// `/proc/self` to point a different thread than the currently-executing
    /// thread. For programs which make use of [`unshare(2)`] or are interacting
    /// with strictly thread-specific structures (such as `/proc/self/stack`)
    /// may prefer to use `ProcThreadSelf` to avoid strange behaviour.
    ///
    /// However, if you pass a handle returned or derived from
    /// [`ProcfsHandle::open`] between threads (this can happen implicitly when
    /// using green-thread systems such as Go), you must take care to ensure the
    /// original thread stays alive until you stop using the handle. If the
    /// thread dies, the handle may start returning invalid data or errors
    /// because it refers to a specific thread that no longer exists. For
    /// correctness reasons you probably want to also actually lock execution to
    /// the thread while using the handle. This drawback does not apply to
    /// [`ProcSelf`].
    ///
    /// # Compatibility
    /// `/proc/thread-self` was added in Linux 3.17 (in 2014), so all modern
    /// systems -- with the notable exception of RHEL 7 -- have support for it.
    /// For older kernels, `ProcThreadSelf` will emulate `/proc/thread-self`
    /// support via other means (namely `/proc/self/task/$tid`), which should
    /// work in almost all cases. As a final fallback (for the very few programs
    /// that interact heavily with PID namespaces), we will silently fallback to
    /// [`ProcSelf`] (this may become an error in future versions).
    ///
    /// [`unshare(2)`]: https://www.man7.org/linux/man-pages/man2/unshare.2.html
    /// [`ProcSelf`]: Self::ProcSelf
    /// [runc]: https://github.com/opencontainers/runc
    ProcThreadSelf,
}

impl ProcfsBase {
    pub(crate) fn into_path(self, proc_root: Option<BorrowedFd<'_>>) -> PathBuf {
        match self {
            Self::ProcRoot => PathBuf::from("."),
            Self::ProcSelf => PathBuf::from("self"),
            Self::ProcPid(pid) => PathBuf::from(pid.to_string()),
            Self::ProcThreadSelf => [
                // /proc/thread-self was added in Linux 3.17.
                "thread-self".into(),
                // For pre-3.17 kernels we use the fully-expanded version.
                format!("self/task/{}", syscalls::gettid()).into(),
                // However, if the proc root is not using our pid namespace, the
                // tid in /proc/self/task/... will be wrong and we need to fall
                // back to /proc/self. This is technically incorrect but we have
                // no other choice -- and this is needed for runc (mainly
                // because of RHEL 7 which has a 3.10 kernel).
                // TODO: Remove this and just return an error so callers can
                //       make their own fallback decisions...
                "self".into(),
            ]
            .into_iter()
            // Return the first option that exists in proc_root.
            .find(|base| {
                match proc_root {
                    Some(root) => {
                        syscalls::accessat(root, base, Access::EXISTS, AtFlags::SYMLINK_NOFOLLOW)
                    }
                    None => syscalls::accessat(
                        syscalls::BADFD,
                        PathBuf::from("/proc").join(base),
                        Access::EXISTS,
                        AtFlags::SYMLINK_NOFOLLOW,
                    ),
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
/// absolutely critical that operations through `/proc` operate **on the exact
/// subpath that the caller requested**.
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
/// It should be noted that there is interest in Linux upstream to block certain
/// classes of procfs overmounts entirely. Linux 6.12 notably introduced
/// [several restrictions on such mounts][linux612-procfs-overmounts], [with
/// plans to eventually block most-if-not-all overmounts inside
/// `/proc/self`][lwn-procfs-overmounts]. `ProcfsHandle` is still useful for
/// older kernels, as well as verifying that there aren't any tricky overmounts
/// anywhere else in the procfs path (such as on top of `/proc/self`).
///
/// NOTE: Users of `ProcfsHandle` should be aware that sometimes `/proc`
/// overmounting is a feature -- tools like [lxcfs] provide better compatibility
/// for system tools by overmounting global procfs files (notably
/// `/proc/meminfo` and `/proc/cpuinfo` to emulate cgroup-aware support for
/// containerisation in procfs). This means that using [`ProcfsBase::ProcRoot`]
/// may result in errors on such systems for non-privileged users, even in the
/// absence of an active attack. This is an intentional feature of libpathrs,
/// but it may be unexpected. Note that (to the best of our knowledge), there
/// are no benevolent tools which create mounts in `/proc/self` or
/// `/proc/thread-self` (mainly due to scaling and correctness issues that would
/// make production usage of such a tool impractical, even if such behaviour may
/// be desirable). As a result, we would only expect [`ProcfsBase::ProcSelf`]
/// and [`ProcfsBase::ProcThreadSelf`] operations to produce errors when you are
/// actually being attacked.
///
/// [cve-2019-16884]: https://nvd.nist.gov/vuln/detail/CVE-2019-16884
/// [cve-2019-19921]: https://nvd.nist.gov/vuln/detail/CVE-2019-19921
/// [lca2020]: https://youtu.be/tGseJW_uBB8
/// [lpc2022]: https://youtu.be/y1PaBzxwRWQ
/// [lxcfs]: https://github.com/lxc/lxcfs
/// [linux612-procfs-overmounts]: https://lore.kernel.org/all/20240806-work-procfs-v1-0-fb04e1d09f0c@kernel.org/
/// [lwn-procfs-overmounts]: https://lwn.net/Articles/934460/
#[derive(Debug)]
pub struct ProcfsHandle {
    inner: OwnedFd,
    mnt_id: Option<u64>,
    is_subset: bool,
    pub(crate) resolver: ProcfsResolver,
}

// TODO: Implement Into<OwnedFd> or AsFd? We (no longer) provide a global
// handle, so the previous concerns about someone dup2-ing over the handle fd
// are not really that relevant anymore. On the other hand, providing the
// underlying file descriptor can easily lead to attacks.

impl ProcfsHandle {
    // This is part of Linux's ABI.
    const PROC_ROOT_INO: u64 = 1;

    /// Create a new `fsopen(2)`-based [`ProcfsHandle`]. This handle is safe
    /// against racing attackers changing the mount table and is guaranteed to
    /// have no overmounts because it is a brand-new procfs.
    pub(crate) fn new_fsopen(subset: bool) -> Result<Self, Error> {
        let sfd = syscalls::fsopen("proc", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "create procfs suberblock".into(),
                source: err,
            }
        })?;

        if subset {
            // Try to configure hidepid=ptraceable,subset=pid if possible, but
            // ignore errors.
            let _ = syscalls::fsconfig_set_string(&sfd, "hidepid", "ptraceable");
            let _ = syscalls::fsconfig_set_string(&sfd, "subset", "pid");
        }

        syscalls::fsconfig_create(&sfd).map_err(|err| ErrorImpl::RawOsError {
            operation: "instantiate procfs superblock".into(),
            source: err,
        })?;

        syscalls::fsmount(
            &sfd,
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::MOUNT_ATTR_NODEV
                | MountAttrFlags::MOUNT_ATTR_NOEXEC
                | MountAttrFlags::MOUNT_ATTR_NOSUID,
        )
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "mount new private procfs".into(),
                source: err,
            }
            .into()
        })
        // NOTE: try_from_fd checks this is an actual procfs root.
        .and_then(Self::try_from_fd)
    }

    /// Create a new `open_tree(2)`-based [`ProcfsHandle`]. This handle is
    /// guaranteed to be safe against racing attackers, and will not have
    /// overmounts unless `flags` contains `OpenTreeFlags::AT_RECURSIVE`.
    pub(crate) fn new_open_tree(flags: OpenTreeFlags) -> Result<Self, Error> {
        syscalls::open_tree(
            syscalls::BADFD,
            "/proc",
            OpenTreeFlags::OPEN_TREE_CLONE | flags,
        )
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "create private /proc bind-mount".into(),
                source: err,
            }
            .into()
        })
        // NOTE: try_from_fd checks this is an actual procfs root.
        .and_then(Self::try_from_fd)
    }

    /// Create a plain `open(2)`-style [`ProcfsHandle`].
    ///
    /// This handle is NOT safe against racing attackers and overmounts.
    pub(crate) fn new_unsafe_open() -> Result<Self, Error> {
        syscalls::openat(
            syscalls::BADFD,
            "/proc",
            OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
            0,
        )
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "open /proc handle".into(),
                source: err,
            }
            .into()
        })
        // NOTE: try_from_fd checks this is an actual procfs root.
        .and_then(Self::try_from_fd)
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
    pub fn new() -> Result<Self, Error> {
        Self::new_fsopen(true)
            // TODO: Should we also try ~AT_RECURSIVE...?
            .or_else(|_| Self::new_open_tree(OpenTreeFlags::AT_RECURSIVE))
            .or_else(|_| Self::new_unsafe_open())
            .wrap("get safe procfs handle")
    }

    /// Create a new handle, trying to create a non-masked handle.
    ///
    /// This is intended to only ever be used internally, as leaking this handle
    /// into containers could lead to serious security issues (while leaking
    /// `subset=pid` is a far less worrisome).
    pub(crate) fn new_unmasked() -> Result<Self, Error> {
        Self::new_fsopen(false)
            .or_else(|_| Self::new_open_tree(OpenTreeFlags::empty()))
            .or_else(|_| Self::new_unsafe_open())
            .wrap("get safe unmasked procfs handle")
        // TODO: We should probably verify is_subset here, to avoid an infinite
        //       loop in the ProcfsHandle::open fallback...
    }

    fn open_base(&self, base: ProcfsBase) -> Result<OwnedFd, Error> {
        let proc_rootfd = self.inner.as_fd();
        let fd = self.resolver.resolve(
            proc_rootfd,
            base.into_path(Some(proc_rootfd)),
            OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
            ResolverFlags::empty(),
        )?;
        self.verify_same_procfs_mnt(&fd)?;
        Ok(fd)
        // TODO: For ProcfsBase::ProcPid, should ENOENT here be converted to
        //       ESRCH to be more "semantically correct"?
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
    #[doc(alias = "pathrs_proc_open")]
    pub fn open_follow(
        &self,
        base: ProcfsBase,
        subpath: impl AsRef<Path>,
        oflags: impl Into<OpenFlags>,
    ) -> Result<File, Error> {
        let subpath = subpath.as_ref();
        let mut oflags = oflags.into();

        // Drop any trailing /-es.
        let (subpath, trailing_slash) = utils::path_strip_trailing_slash(subpath);
        if trailing_slash {
            // A trailing / implies we want O_DIRECTORY.
            oflags.insert(OpenFlags::O_DIRECTORY);
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
            return self.open(base, subpath, oflags);
        }

        // Get a no-follow handle to the parent of the magic-link.
        let (parent, trailing) = utils::path_split(subpath)?;
        let trailing = trailing.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "proc_open_follow path has trailing slash".into(),
        })?;

        let parent = self.open(base, parent, OpenFlags::O_PATH | OpenFlags::O_DIRECTORY)?;

        // Rather than using self.mnt_id for the following check, we use the
        // mount ID from parent. This is necessary because ProcfsHandle::open
        // might create a brand-new procfs handle with a different mount ID.
        // However, ProcfsHandle::open already checks that the mount ID and
        // fstype are safe, so we can just reuse the mount ID we get without
        // issue.
        let parent_mnt_id = utils::fetch_mnt_id(&parent, "")?;

        // Detect if the magic-link we are about to open is actually a
        // bind-mount. There is no "statfsat" so we can't check that the f_type
        // is PROC_SUPER_MAGIC. However, an attacker can construct any
        // magic-link they like with procfs (as well as files that contain any
        // data they like and are no-op writeable), so it seems unlikely that
        // such a check would do anything in this case.
        //
        // NOTE: This check is only safe if there are no racing mounts, so only
        // for the ProcfsHandle::{new_fsopen,new_open_tree} cases.
        verify_same_mnt(parent_mnt_id, &parent, trailing)?;

        syscalls::openat_follow(parent, trailing, oflags, 0)
            .map(File::from)
            .map_err(|err| {
                ErrorImpl::RawOsError {
                    operation: "open final magiclink component".into(),
                    source: err,
                }
                .into()
            })
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
    /// [`openat2(2)`]: https://www.man7.org/linux/man-pages/man2/openat2.2.html
    #[doc(alias = "pathrs_proc_open")]
    pub fn open(
        &self,
        base: ProcfsBase,
        subpath: impl AsRef<Path>,
        oflags: impl Into<OpenFlags>,
    ) -> Result<File, Error> {
        let mut oflags = oflags.into();
        // Force-set O_NOFOLLOW.
        oflags.insert(OpenFlags::O_NOFOLLOW);

        // Do a basic lookup.
        let basedir = self.open_base(base)?;
        let subpath = subpath.as_ref();
        let fd = self
            .resolver
            .resolve(&basedir, subpath, oflags, ResolverFlags::empty())
            .and_then(|fd| {
                self.verify_same_procfs_mnt(&fd)?;
                Ok(fd)
            })
            .or_else(|err| {
                if self.is_subset && err.kind() == ErrorKind::OsError(Some(libc::ENOENT)) {
                    // If the lookup failed due to ENOENT, and the current
                    // procfs handle is "masked" in some way, try to create a
                    // temporary unmasked handle and retry the operation.
                    Self::new_unmasked()
                        // Use the old error if creating a new handle failed.
                        .or(Err(err))?
                        .open(base, subpath, oflags)
                        .map(OwnedFd::from)
                } else {
                    Err(err)
                }
            })?;

        Ok(fd.into())
    }

    /// Safely read the contents of a symlink inside `procfs`.
    ///
    /// This method is effectively shorthand for doing [`readlinkat(2)`] on the
    /// handle you'd get from `ProcfsHandle::open(..., OpenFlags::O_PATH)`. So
    /// all of the caveats from [`ProcfsHandle::open`] apply to this method as
    /// well.
    ///
    /// [`readlinkat(2)`]: https://www.man7.org/linux/man-pages/man2/readlinkat.2.html
    #[doc(alias = "pathrs_proc_readlink")]
    pub fn readlink(&self, base: ProcfsBase, subpath: impl AsRef<Path>) -> Result<PathBuf, Error> {
        let link = self.open(base, subpath, OpenFlags::O_PATH)?;
        syscalls::readlinkat(link, "").map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "read procfs magiclink".into(),
                source: err,
            }
            .into()
        })
    }

    fn verify_same_procfs_mnt(&self, fd: impl AsFd) -> Result<(), Error> {
        // Detect if the file we landed on is from a bind-mount.
        verify_same_mnt(self.mnt_id, &fd, "")?;
        // For pre-5.8 kernels there is no STATX_MNT_ID, so the best we can
        // do is check the fs_type to avoid mounts non-procfs filesystems.
        // Unfortunately, attackers can bind-mount procfs files and still
        // cause damage so this protection is marginal at best.
        verify_is_procfs(&fd)
    }

    /// Try to convert a regular [`File`] handle to a [`ProcfsHandle`]. This
    /// method will return an error if the file handle is not actually the root
    /// of a procfs mount.
    pub fn try_from_fd<Fd: Into<OwnedFd>>(inner: Fd) -> Result<Self, Error> {
        let inner = inner.into();

        // Make sure the file is actually a procfs root.
        verify_is_procfs_root(&inner)?;

        let mnt_id = utils::fetch_mnt_id(&inner, "")?;
        let resolver = ProcfsResolver::default();

        // Figure out if the mount we have is subset=pid or hidepid=. For
        // hidepid we check if we can resolve /proc/1 -- if we can access it
        // then hidepid is probably not relevant.
        let is_subset = [/* subset=pid */ "stat", /* hidepid=n */ "1"]
            .iter()
            .any(|&subpath| {
                syscalls::accessat(&inner, subpath, Access::EXISTS, AtFlags::SYMLINK_NOFOLLOW)
                    .is_err()
            });

        Ok(Self {
            inner,
            mnt_id,
            is_subset,
            resolver,
        })
    }
}

pub(crate) fn verify_is_procfs(fd: impl AsFd) -> Result<(), Error> {
    let fs_type = syscalls::fstatfs(fd)
        .map_err(|err| ErrorImpl::RawOsError {
            operation: "fstatfs proc handle".into(),
            source: err,
        })?
        .f_type;
    if fs_type != rustix_fs::PROC_SUPER_MAGIC {
        Err(ErrorImpl::OsError {
            operation: "verify lookup is still on a procfs mount".into(),
            source: IOError::from_raw_os_error(libc::EXDEV),
        })
        .wrap(format!(
            "fstype mismatch in restricted procfs resolver (f_type is 0x{fs_type:X}, not 0x{:X})",
            rustix_fs::PROC_SUPER_MAGIC,
        ))?
    }
    Ok(())
}

pub(crate) fn verify_is_procfs_root(fd: impl AsFd) -> Result<(), Error> {
    let fd = fd.as_fd();

    // Make sure the file is actually a procfs handle.
    verify_is_procfs(fd)?;

    // And make sure it's the root of procfs. The root directory is
    // guaranteed to have an inode number of PROC_ROOT_INO. If this check
    // ever stops working, it's a kernel regression.
    let ino = fd.metadata().expect("fstat(/proc) should work").ino();
    if ino != ProcfsHandle::PROC_ROOT_INO {
        Err(ErrorImpl::SafetyViolation {
            description: format!(
                "/proc is not root of a procfs mount (ino is 0x{ino:X}, not 0x{:X})",
                ProcfsHandle::PROC_ROOT_INO,
            )
            .into(),
        })?;
    }

    Ok(())
}

pub(crate) fn verify_same_mnt(
    root_mnt_id: Option<u64>,
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
) -> Result<(), Error> {
    let mnt_id = utils::fetch_mnt_id(dirfd, path)?;
    // We the file we landed on a bind-mount / other procfs?
    if root_mnt_id != mnt_id {
        // Emulate RESOLVE_NO_XDEV's errors so that any failure looks like an
        // openat2(2) failure, as this function is used by the emulated procfs
        // resolver as well.
        Err(ErrorImpl::OsError {
            operation: "verify lookup is still in the same mount".into(),
            source: IOError::from_raw_os_error(libc::EXDEV),
        })
        .wrap(format!(
            "mount id mismatch in restricted procfs resolver (mnt_id is {mnt_id:?}, not procfs {root_mnt_id:?})",
        ))?
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    #[test]
    fn bad_root() {
        let file = File::open("/").expect("open root");
        let procfs = ProcfsHandle::try_from_fd(file);

        assert!(
            procfs.is_err(),
            "creating a procfs handle from the wrong filesystem should return an error"
        );
    }

    #[test]
    fn bad_tmpfs() {
        let file = File::open("/tmp").expect("open tmpfs");
        let procfs = ProcfsHandle::try_from_fd(file);

        assert!(
            procfs.is_err(),
            "creating a procfs handle from the wrong filesystem should return an error"
        );
    }

    #[test]
    fn bad_proc_nonroot() {
        let file = File::open("/proc/tty").expect("open tmpfs");
        let procfs = ProcfsHandle::try_from_fd(file);

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
            "new procfs handle should succeed, got {procfs:?}",
        );
    }
}

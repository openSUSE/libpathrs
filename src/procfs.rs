// SPDX-License-Identifier: MPL-2.0 OR LGPL-3.0-or-later
/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2025 SUSE LLC
 * Copyright (C) 2026 Aleksa Sarai <cyphar@cyphar.com>
 *
 * == MPL-2.0 ==
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Alternatively, this Source Code Form may also (at your option) be used
 * under the terms of the GNU Lesser General Public License Version 3, as
 * described below:
 *
 * == LGPL-3.0-or-later ==
 *
 *  This program is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License  for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#![forbid(unsafe_code)]

//! Helpers to operate on `procfs` safely.
//!
//! The primary interface most users will interact with is [`ProcfsHandle`],
//! with most usage looking something like:
//!
//! ```rust
//! # use pathrs::flags::OpenFlags;
//! # use pathrs::procfs::{ProcfsBase, ProcfsHandle};
//! let proc = ProcfsHandle::new()?; // usually cached by libpathrs
//!
//! // Open regular procfs files (ProcfsBase indicates the base subpath of /proc
//! // the operation is acting on, effectively acting like a prefix).
//! let status = proc.open(ProcfsBase::ProcThreadSelf, "status", OpenFlags::O_RDONLY)?;
//! # let _ = status;
//!
//! // Open a magic-link safely. This even protects against bind-mounts on top
//! // of the magic-link!
//! let exe = proc.open_follow(ProcfsBase::ProcSelf, "exe", OpenFlags::O_PATH)?;
//! # let _ = exe;
//!
//! // Do a safe readlink.
//! let stdin_path = proc.readlink(ProcfsBase::ProcThreadSelf, "fd/0")?;
//! println!("stdin: {stdin_path:?}");
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::{
    error::{Error, ErrorExt, ErrorImpl, ErrorKind},
    flags::{OpenFlags, ResolverFlags},
    resolvers::procfs::ProcfsResolver,
    syscalls,
    utils::{self, kernel_version, FdExt, MaybeOwnedFd, RawProcfsRoot},
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

use once_cell::sync::{Lazy, OnceCell as OnceLock};
use rustix::{
    fs::{Access, AtFlags},
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
    pub(crate) fn into_path(self, proc_rootfd: RawProcfsRoot<'_>) -> PathBuf {
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
            // Return the first option that exists in proc_rootfd.
            .find(|base| proc_rootfd.exists_unchecked(base).is_ok())
            .expect("at least one candidate /proc/thread-self path should work"),
        }
    }
    // TODO: Add into_raw_path() that doesn't use symlinks?
}

/// Builder for [`ProcfsHandle`].
///
/// This is mainly intended for users that have specific requirements for the
/// `/proc` they need to operate on. For the most part this would be users that
/// need to frequently operate on global `/proc` files and thus need to have a
/// non-`subset=pid` [`ProcfsHandle`] to use multiple times.
///
/// ```rust
/// # use pathrs::flags::OpenFlags;
/// # use pathrs::procfs::{ProcfsBase, ProcfsHandleBuilder};
/// # use std::io::Read;
/// let procfs = ProcfsHandleBuilder::new()
///     .unmasked()
///     .build()?;
/// let mut uptime = String::new();
/// procfs.open(ProcfsBase::ProcRoot, "uptime", OpenFlags::O_RDONLY)?
///       .read_to_string(&mut uptime)?;
/// println!("uptime: {uptime}");
/// # Ok::<(), anyhow::Error>(())
/// ```
///
/// Most users should just use [`ProcfsHandle::new`] or the default
/// configuration of [`ProcfsHandleBuilder`], as it provides the safest
/// configuration without performance penalties for most users.
#[derive(Clone, Debug)]
pub struct ProcfsHandleBuilder {
    subset_pid: bool,
}

impl Default for ProcfsHandleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcfsHandleBuilder {
    /// Construct a new [`ProcfsHandleBuilder`] with the recommended
    /// configuration.
    #[inline]
    pub fn new() -> Self {
        Self { subset_pid: true }
    }

    // TODO: use_cached() -- allow users to control whether they get a cached
    // handle (if it is cacheable).

    // TODO: allow_global() -- allow users to control whether they want to allow
    // the usage of the global (non-detached) "/proc" as a final fallback.

    /// Specify whether to try to set `subset=pid` on the [`ProcfsHandle`].
    ///
    /// `subset=pid` (available since Linux 5.8) disables all global procfs
    /// files (the vast majority of which are the main causes for concern if an
    /// attacker can write to them). Only [`ProcfsHandle`] instances with
    /// `subset=pid` configured can be cached (in addition to some other
    /// requirements).
    ///
    /// As a result, leaking the file descriptor of a [`ProcfsHandle`] with
    /// `subset=pid` *disabled* is **very** dangerous and so this method should
    /// be used sparingly -- ideally only temporarily by users which need to do
    /// a series of operations on global procfs files (such as sysctls).
    ///
    /// Most users can just use [`ProcfsHandle::new`] and then do operations on
    /// [`ProcfsBase::ProcRoot`]. In this case, a no-`subset=pid`
    /// [`ProcfsHandle`] will be created internally and will only be used *for
    /// that operation*, reducing the risk of leaks.
    #[inline]
    pub fn subset_pid(mut self, subset_pid: bool) -> Self {
        self.set_subset_pid(subset_pid);
        self
    }

    /// Setter form of [`ProcfsHandleBuilder::subset_pid`].
    #[inline]
    pub fn set_subset_pid(&mut self, subset_pid: bool) -> &mut Self {
        self.subset_pid = subset_pid;
        self
    }

    /// Do not require any restrictions for the procfs handle.
    ///
    /// Unlike standalone methods for each configuration setting of
    /// [`ProcfsHandle`], this method will always clear all restrictions
    /// supported by [`ProcfsHandleBuilder`].
    #[inline]
    pub fn unmasked(mut self) -> Self {
        self.set_unmasked();
        self
    }

    /// Setter form of [`ProcfsHandleBuilder::unmasked`].
    #[inline]
    pub fn set_unmasked(&mut self) -> &mut Self {
        self.subset_pid = false;
        self
    }

    /// Returns whether this [`ProcfsHandleBuilder`] will request a cacheable
    /// [`ProcfsHandle`].
    #[inline]
    fn is_cache_friendly(&self) -> bool {
        self.subset_pid
    }

    /// Build the [`ProcfsHandle`].
    ///
    /// For privileged users (those that have the ability to create mounts) on
    /// new enough kernels (Linux 5.2 or later), this created handle will be
    /// safe against racing attackers that have the ability to configure the
    /// mount table.
    ///
    /// For unprivileged users (or those on pre-5.2 kernels), this handle will
    /// only be safe against attackers that cannot actively modify the mount
    /// table while we are operating on it (which is usually more than enough
    /// protection -- after all, most attackers cannot mount anything in the
    /// first place -- but it is a notable limitation).
    ///
    /// # Caching
    ///
    /// For some configurations (namely, with `subset=pid` enabled),
    /// [`ProcfsHandleBuilder`] will internally cache the created
    /// [`ProcfsHandle`] and future requests with the same configuration will
    /// return a copy of the cached [`ProcfsHandle`].
    ///
    /// As the cached [`ProcfsHandle`] will always have the same file
    /// descriptor, this means that you should not modify or close the
    /// underlying file descriptor for a [`ProcfsHandle`] returned by this
    /// method.
    ///
    /// To avoid negatively impacting downstream projects, as a final safety
    /// mechanism if the cached [`ProcfsHandle`] does become invalidated,
    /// [`build`][Self::build] will refuse to use it and will always create new
    /// handles. Users are still strongly recommended to not fiddle with file
    /// descriptors in that way (unless absolutely necessary).
    pub fn build(self) -> Result<ProcfsHandle, Error> {
        // MSRV(1.70): Use std::sync::OnceLock.
        static CACHED_PROCFS_HANDLE: OnceLock<OwnedFd> = OnceLock::new();
        static CACHED_HANDLE_IS_BAD: OnceLock<()> = OnceLock::new();

        // Helper to make the lower conditional a bit easier to read.
        fn is_cached_handle_bad() -> bool {
            CACHED_HANDLE_IS_BAD.get().is_some()
        }

        // MSRV(1.85): Use let chain here (Rust 2024).
        if self.is_cache_friendly() && !is_cached_handle_bad() {
            // If there is already a cached filesystem available, use that.
            if let Some(fd) = CACHED_PROCFS_HANDLE.get() {
                if let Ok(procfs) = ProcfsHandle::try_from_borrowed_fd(fd.as_fd()) {
                    debug_assert!(
                        procfs.is_subset && procfs.is_detached,
                        "cached procfs handle should be subset=pid and detached"
                    );
                    return Ok(procfs);
                }
                // If the cached procfs handle failed to validate the file
                // descriptor must have been closed or dup2'd over. Crashing
                // here would be the most correct approach, but runc
                // intentionally closes all file descriptors and so we might
                // crash runc unexpectedly (see opencontainers/runc#5438).
                //
                // So, if the handle is bad (for any reason) we fall back to the
                // creation behaviour and lock out any future attempts to use
                // the handle (if a program has gotten into this kind of state
                // it's best to not try to touch bad fds).
                //
                // TODO: We should probably log the error here, but logging in
                // libraries really sucks...
                let _ = CACHED_HANDLE_IS_BAD.set(());
                // fallthrough to creation path
            }
        }

        let procfs = ProcfsHandle::new_fsopen(self.subset_pid)
            .or_else(|_| ProcfsHandle::new_open_tree(OpenTreeFlags::empty()))
            .or_else(|_| ProcfsHandle::new_open_tree(OpenTreeFlags::AT_RECURSIVE))
            .or_else(|_| ProcfsHandle::new_unsafe_open())
            .wrap("get safe procfs handle")?;

        // TODO: Add a way to require/verify that the requested properties will
        // be set, and then check them here before returning.

        match procfs {
            ProcfsHandle {
                inner: MaybeOwnedFd::OwnedFd(inner),
                is_subset: true, // must be subset=pid to cache (risk: dangerous files)
                is_detached: true, // must be detached to cache (risk: escape to host)
                ..
            } if !is_cached_handle_bad() => {
                // Try to cache our new handle -- if another thread beat us to
                // it, just use the handle that they cached and drop the one we
                // created.
                let cached_inner = match CACHED_PROCFS_HANDLE.try_insert(inner) {
                    Ok(inner) => MaybeOwnedFd::BorrowedFd(inner.as_fd()),
                    Err((inner, _)) => MaybeOwnedFd::BorrowedFd(inner.as_fd()),
                };
                // Do not return an error here -- it should be impossible for
                // this validation to fail after we get here.
                Ok(ProcfsHandle::try_from_maybe_owned_fd(cached_inner)
                    .expect("cached procfs handle should be valid"))
            }
            procfs => Ok(procfs),
        }
    }
}

/// A borrowed version of [`ProcfsHandle`].
///
/// > NOTE: Actually, [`ProcfsHandle`] is an alias to this, but from an API
/// > perspective it's probably easier to think of [`ProcfsHandleRef`] as being
/// > derivative of [`ProcfsHandle`] -- as most users will probably use
/// > [`ProcfsHandle::new`].
#[derive(Debug)]
pub struct ProcfsHandleRef<'fd> {
    inner: MaybeOwnedFd<'fd, OwnedFd>,
    mnt_id: Option<u64>,
    is_subset: bool,
    is_detached: bool,
    pub(crate) resolver: ProcfsResolver,
}

/// > **NOTE**: Take great care when using this file descriptor -- it is very
/// > easy to get attacked with a malicious procfs mount when using the file
/// > descriptor directly. This should only be used in circumstances where you
/// > cannot achieve your goal using `libpathrs` (in which case, please open an
/// > issue to help us improve the API).
impl<'fd> AsFd for ProcfsHandleRef<'fd> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl<'fd> ProcfsHandleRef<'fd> {
    // This is part of Linux's ABI.
    const PROC_ROOT_INO: u64 = 1;

    /// Convert an owned [`ProcfsHandle`] to the underlying [`OwnedFd`].
    ///
    /// If the handle is internally a shared reference (i.e., it was constructed
    /// using [`ProcfsHandle::try_from_borrowed_fd`] or is using the global
    /// cached [`ProcfsHandle`]), this method will return `None`.
    ///
    /// > **NOTE**: Take great care when using this file descriptor -- it is
    /// > very easy to get attacked with a malicious procfs mount when using the
    /// > file descriptor directly. This should only be used in circumstances
    /// > where you cannot achieve your goal using `libpathrs` (in which case,
    /// > please open an issue to help us improve the API).
    // TODO: We probably should have a Result<OwnedFd, Self> version.
    pub fn into_owned_fd(self) -> Option<OwnedFd> {
        self.inner.into_owned()
    }

    pub(crate) fn as_raw_procfs(&self) -> RawProcfsRoot<'_> {
        RawProcfsRoot::UnsafeFd(self.as_fd())
    }

    /// Do `openat(2)` inside the procfs, but safely.
    fn openat_raw(
        &self,
        dirfd: BorrowedFd<'_>,
        subpath: &Path,
        oflags: OpenFlags,
    ) -> Result<OwnedFd, Error> {
        let fd = self.resolver.resolve(
            self.as_raw_procfs(),
            dirfd,
            subpath,
            oflags,
            ResolverFlags::empty(),
        )?;
        self.verify_same_procfs_mnt(&fd).with_wrap(|| {
            format!(
                "validate that procfs subpath fd {} is on the same procfs mount",
                syscalls::FrozenFd::from(&fd),
            )
        })?;
        Ok(fd)
    }

    /// Open `ProcfsBase` inside the procfs.
    fn open_base(&self, base: ProcfsBase) -> Result<OwnedFd, Error> {
        self.openat_raw(
            self.as_fd(),
            &base.into_path(self.as_raw_procfs()),
            OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
        )
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

        // If the target is not actually a magic-link, we are able to just use
        // the regular resolver to open the target (this even includes actual
        // symlinks) which is much safer. This also defends against C user
        // forgetting to set O_NOFOLLOW.
        //
        // This also gives us a chance to check if the target path is not
        // present because of subset=pid and retry (for magic-links we need to
        // operate on the target path more than once, which makes the retry
        // logic easier to do upfront here).
        match self.openat_raw(self.open_base(base)?.as_fd(), subpath, oflags) {
            Ok(file) => return Ok(file.into()),
            Err(err) => {
                if self.is_subset && err.kind() == ErrorKind::OsError(Some(libc::ENOENT)) {
                    // If the trial lookup failed due to ENOENT and the current
                    // procfs handle is "masked" in some way, try to create a
                    // temporary unmasked handle and retry the operation.
                    return ProcfsHandleBuilder::new()
                        .unmasked()
                        .build()
                        // Use the old error if creating a new handle failed.
                        .or(Err(err))?
                        .open_follow(base, subpath, oflags);
                }
                // If the error is ELOOP then the resolver probably hit a
                // magic-link, and so we have a reason to allow the
                // no-validation open we do later.
                // NOTE: Of course, this is not safe against races -- an
                // attacker could bind-mount a magic-link over a regular symlink
                // to trigger ELOOP and then unmount it after this point. As
                // always, fsopen(2) is needed for true safety here.
                if err.kind() != ErrorKind::OsError(Some(libc::ELOOP)) {
                    Err(err)?;
                }
            }
        }

        // Get a no-follow handle to the parent of the magic-link.
        let (parent, trailing) = utils::path_split(subpath)?;
        let trailing = trailing.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "proc_open_follow path has trailing slash".into(),
        })?;

        let parentdir = self.openat_raw(
            self.open_base(base)?.as_fd(),
            parent,
            OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
        )?;

        // Rather than using self.mnt_id for the following check, we use the
        // mount ID from parent. This is necessary because ProcfsHandle::open
        // might create a brand-new procfs handle with a different mount ID.
        // However, ProcfsHandle::open already checks that the mount ID and
        // fstype are safe, so we can just reuse the mount ID we get without
        // issue.
        let parent_mnt_id =
            utils::fetch_mnt_id(self.as_raw_procfs(), &parentdir, "").with_wrap(|| {
                format!(
                    "get mount id of procfs fd {}",
                    syscalls::FrozenFd::from(&parentdir)
                )
            })?;

        // Detect if the magic-link we are about to open is actually a
        // bind-mount. There is no "statfsat" so we can't check that the f_type
        // is PROC_SUPER_MAGIC. However, an attacker can construct any
        // magic-link they like with procfs (as well as files that contain any
        // data they like and are no-op writeable), so it seems unlikely that
        // such a check would do anything in this case.
        //
        // NOTE: This check is only safe if there are no racing mounts, so only
        // for the ProcfsHandle::{new_fsopen,new_open_tree} cases.
        verify_same_mnt(self.as_raw_procfs(), parent_mnt_id, &parentdir, trailing).with_wrap(
            || {
                format!(
                    "check that parent dir {} and {trailing:?} are on the same procfs mount",
                    syscalls::FrozenFd::from(&parentdir)
                )
            },
        )?;

        syscalls::openat_follow(parentdir, trailing, oflags, 0)
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
        let subpath = subpath.as_ref();
        let fd = self
            .openat_raw(self.open_base(base)?.as_fd(), subpath, oflags)
            .or_else(|err| {
                if self.is_subset && err.kind() == ErrorKind::OsError(Some(libc::ENOENT)) {
                    // If the lookup failed due to ENOENT, and the current
                    // procfs handle is "masked" in some way, try to create a
                    // temporary unmasked handle and retry the operation.
                    ProcfsHandleBuilder::new()
                        .unmasked()
                        .build()
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

    #[inline]
    fn verify_same_procfs_mnt(&self, fd: impl AsFd) -> Result<(), Error> {
        verify_same_procfs_mnt(self.as_raw_procfs(), self.mnt_id, fd)
    }

    /// Try to convert a [`BorrowedFd`] into a [`ProcfsHandle`] with the same
    /// lifetime. This method will return an error if the file handle is not
    /// actually the root of a procfs mount.
    pub fn try_from_borrowed_fd<Fd: Into<BorrowedFd<'fd>>>(inner: Fd) -> Result<Self, Error> {
        Self::try_from_maybe_owned_fd(inner.into().into())
    }

    fn try_from_maybe_owned_fd(inner: MaybeOwnedFd<'fd, OwnedFd>) -> Result<Self, Error> {
        let inner_fd = inner.as_fd();

        // Make sure the file is actually a procfs root.
        verify_is_procfs_root(inner_fd).with_wrap(|| {
            format!(
                "check if candidate procfs root fd {} is a procfs root",
                syscalls::FrozenFd::from(inner_fd)
            )
        })?;

        let proc_rootfd = RawProcfsRoot::UnsafeFd(inner_fd);
        let mnt_id = utils::fetch_mnt_id(proc_rootfd, inner_fd, "").with_wrap(|| {
            format!(
                "get mount id for candidate procfs root fd {}",
                syscalls::FrozenFd::from(inner_fd)
            )
        })?;
        let resolver = ProcfsResolver::default();

        // Figure out if the mount we have is subset=pid or hidepid=. For
        // hidepid we check if we can resolve /proc/1 -- if we can access it
        // then hidepid is probably not relevant.
        let is_subset = [/* subset=pid */ "stat", /* hidepid=n */ "1"]
            .iter()
            .any(|&subpath| {
                syscalls::accessat(inner_fd, subpath, Access::EXISTS, AtFlags::SYMLINK_NOFOLLOW)
                    .is_err()
            });

        // Figure out if this file descriptor is a detached mount (i.e., from
        // fsmount(2) or OPEN_TREE_CLONE) by checking if ".." lets you get out
        // the procfs mount. Detached mounts take place in an anonymous mount
        // namespace rooted at the detached mount (so ".." is a no-op), while
        // regular opens will take place in a regular host filesystem where.
        //
        // If the handle is a detached mount, then ".." should be a procfs root
        // with the same mount ID.
        let is_detached = verify_same_mnt(proc_rootfd, mnt_id, inner_fd, "..")
            .and_then(|_| {
                verify_is_procfs_root(
                    syscalls::openat(
                        inner_fd,
                        "..",
                        OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
                        0,
                    )
                    .map_err(|err| ErrorImpl::RawOsError {
                        operation: "get parent directory of procfs handle".into(),
                        source: err,
                    })?,
                )
            })
            .is_ok();

        Ok(Self {
            inner,
            mnt_id,
            is_subset,
            is_detached,
            resolver,
        })
    }
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
pub type ProcfsHandle = ProcfsHandleRef<'static>;

/// Indicates whether this kernel is new enough that it should have the
/// upstream-merged version of the new mount API. This is necessary because
/// testing in runc found that RHEL 8 appears to have a broken backport of the
/// new mount API that causes serious performance regressions -- as such, we
/// should simply refuse to even try to use any of the new mount APIs on pre-5.2
/// kernels.
// MSRV(1.80): Use LazyLock.
static HAS_UNBROKEN_MOUNT_API: Lazy<bool> = Lazy::new(|| kernel_version::is_gte!(5, 2));

impl ProcfsHandle {
    /// Create a new `fsopen(2)`-based [`ProcfsHandle`]. This handle is safe
    /// against racing attackers changing the mount table and is guaranteed to
    /// have no overmounts because it is a brand-new procfs.
    pub(crate) fn new_fsopen(subset: bool) -> Result<Self, Error> {
        if !*HAS_UNBROKEN_MOUNT_API {
            Err(ErrorImpl::NotSupported {
                feature: "fsopen".into(),
            })?
        }

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
        if !*HAS_UNBROKEN_MOUNT_API {
            Err(ErrorImpl::NotSupported {
                feature: "open_tree".into(),
            })?
        }

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
    /// This method is just short-hand for:
    ///
    /// ```rust
    /// # use pathrs::procfs::ProcfsHandleBuilder;
    /// let procfs = ProcfsHandleBuilder::new().build()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new() -> Result<Self, Error> {
        ProcfsHandleBuilder::new().subset_pid(true).build()
    }

    /// Try to convert a regular [`File`] handle to a [`ProcfsHandle`]. This
    /// method will return an error if the file handle is not actually the root
    /// of a procfs mount.
    pub fn try_from_fd<Fd: Into<OwnedFd>>(inner: Fd) -> Result<Self, Error> {
        Self::try_from_maybe_owned_fd(inner.into().into())
    }
}

/// The magic number of procfs (`PROC_SUPER_MAGIC` in `<linux/magic.h>`).
///
/// NOTE: We can't use [`rustix::fs::PROC_SUPER_MAGIC`] because its type
/// ([`rustix::fs::FsWord`]) is not always the same as the type of
/// `statfs.f_type`, so we would not be able to compare the two on every
/// target. See [`syscalls::fstatfs_type`] for more details.
pub(crate) const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;

pub(crate) fn verify_is_procfs(fd: impl AsFd) -> Result<(), Error> {
    let fs_type = syscalls::fstatfs_type(fd).map_err(|err| ErrorImpl::RawOsError {
        operation: "fstatfs proc handle".into(),
        source: err,
    })?;
    if fs_type != PROC_SUPER_MAGIC {
        Err(ErrorImpl::OsError {
            operation: "verify fd is from procfs".into(),
            source: IOError::from_raw_os_error(libc::EXDEV),
        })
        .wrap(format!(
            "fstype mismatch in restricted procfs resolver (f_type is 0x{fs_type:X}, not 0x{PROC_SUPER_MAGIC:X})",
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
    proc_rootfd: RawProcfsRoot<'_>,
    root_mnt_id: Option<u64>,
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
) -> Result<(), Error> {
    let mnt_id = utils::fetch_mnt_id(proc_rootfd, dirfd, path)?;
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

pub(crate) fn verify_same_procfs_mnt(
    proc_rootfd: RawProcfsRoot<'_>,
    root_mnt_id: Option<u64>,
    fd: impl AsFd,
) -> Result<(), Error> {
    let fd = fd.as_fd();

    // Detect if the file we landed on is from a bind-mount.
    verify_same_mnt(proc_rootfd, root_mnt_id, fd, "")?;

    // For pre-5.8 kernels there is no STATX_MNT_ID, so the protection we get
    // from verify_same_mnt() can be a little weaker (as it relies on fdinfo,
    // which needs other protections to be made safe).
    //
    // To try to frustrate attackers, we still check for the fstype here (even
    // though it is strictly weaker than the mount-id check). Unfortunately,
    // arbitrary procfs files can still easily cause damage so this protection
    // is marginal at best.
    verify_is_procfs(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{fs::File, os::unix::io::AsRawFd};

    use pretty_assertions::assert_eq;

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
    fn builder_props() {
        assert_eq!(
            ProcfsHandleBuilder::new().subset_pid,
            true,
            "ProcfsHandleBuilder::new() should have subset_pid = true"
        );
        assert_eq!(
            ProcfsHandleBuilder::default().subset_pid,
            true,
            "ProcfsHandleBuilder::default() should have subset_pid = true"
        );

        assert_eq!(
            ProcfsHandleBuilder::new().subset_pid(true).subset_pid,
            true,
            "ProcfsHandleBuilder::subset_pid(true) should give subset_pid = true"
        );
        let mut builder = ProcfsHandleBuilder::new();
        builder.set_subset_pid(true);
        assert_eq!(
            builder.subset_pid, true,
            "ProcfsHandleBuilder::set_subset_pid(true) should give subset_pid = true"
        );

        assert_eq!(
            ProcfsHandleBuilder::new().subset_pid(false).subset_pid,
            false,
            "ProcfsHandleBuilder::subset_pid(true) should give subset_pid = false"
        );
        let mut builder = ProcfsHandleBuilder::new();
        builder.set_subset_pid(false);
        assert_eq!(
            builder.subset_pid, false,
            "ProcfsHandleBuilder::set_subset_pid(false) should give subset_pid = false"
        );

        assert_eq!(
            ProcfsHandleBuilder::new().unmasked().subset_pid,
            false,
            "ProcfsHandleBuilder::unmasked() should have subset_pid = false"
        );
        let mut builder = ProcfsHandleBuilder::new();
        builder.set_unmasked();
        assert_eq!(
            builder.subset_pid, false,
            "ProcfsHandleBuilder::set_unmasked() should have subset_pid = false"
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

    #[test]
    fn builder_build() {
        let procfs = ProcfsHandleBuilder::new().build();
        assert!(
            procfs.is_ok(),
            "new procfs handle should succeed, got {procfs:?}",
        );
    }

    #[test]
    fn builder_unmasked_build() {
        let procfs = ProcfsHandleBuilder::new()
            .unmasked()
            .build()
            .expect("should be able to get unmasked procfs handle");
        assert!(
            !procfs.is_subset,
            "new unmasked procfs handle should have !subset=pid",
        );
    }

    #[test]
    fn builder_unmasked_build_not_cached() {
        let procfs1 = ProcfsHandleBuilder::new()
            .unmasked()
            .build()
            .expect("should be able to get unmasked procfs handle");
        let procfs2 = ProcfsHandleBuilder::new()
            .unmasked()
            .build()
            .expect("should be able to get unmasked procfs handle");

        assert!(
            !procfs1.is_subset,
            "new unmasked procfs handle should have !subset=pid",
        );
        assert!(
            !procfs2.is_subset,
            "new unmasked procfs handle should have !subset=pid",
        );
        assert_eq!(
            procfs1.is_detached, procfs2.is_detached,
            "is_detached should be the same for both handles"
        );
        assert_ne!(
            procfs1.as_fd().as_raw_fd(),
            procfs2.as_fd().as_raw_fd(),
            "unmasked procfs handles should NOT be cached and thus have different fds"
        );
    }

    #[test]
    fn new_fsopen() {
        if let Ok(procfs) = ProcfsHandle::new_fsopen(false) {
            assert!(
                !procfs.is_subset,
                "ProcfsHandle::new_fsopen(false) should be !subset=pid"
            );
            assert!(
                procfs.is_detached,
                "ProcfsHandle::new_fsopen(false) should be detached"
            );
        }
    }

    #[test]
    fn new_fsopen_subset() {
        if let Ok(procfs) = ProcfsHandle::new_fsopen(true) {
            assert!(
                procfs.is_subset,
                "ProcfsHandle::new_fsopen(true) should be subset=pid"
            );
            assert!(
                procfs.is_detached,
                "ProcfsHandle::new_fsopen(true) should be detached"
            );
        }
    }

    #[test]
    fn new_open_tree() {
        if let Ok(procfs) = ProcfsHandle::new_open_tree(OpenTreeFlags::empty()) {
            assert!(
                !procfs.is_subset,
                "ProcfsHandle::new_open_tree() should be !subset=pid (same as host)"
            );
            assert!(
                procfs.is_detached,
                "ProcfsHandle::new_open_tree() should be detached"
            );
        }

        if let Ok(procfs) = ProcfsHandle::new_open_tree(OpenTreeFlags::AT_RECURSIVE) {
            assert!(
                !procfs.is_subset,
                "ProcfsHandle::new_open_tree(AT_RECURSIVE) should be !subset=pid (same as host)"
            );
            assert!(
                procfs.is_detached,
                "ProcfsHandle::new_open_tree(AT_RECURSIVE) should be detached"
            );
        }
    }

    #[test]
    fn new_unsafe_open() {
        let procfs = ProcfsHandle::new_unsafe_open()
            .expect("ProcfsHandle::new_unsafe_open should always work");

        assert!(
            !procfs.is_subset,
            "ProcfsHandle::new_unsafe_open() should be !subset=pid"
        );
        assert!(
            !procfs.is_detached,
            "ProcfsHandle::new_unsafe_open() should not be detached"
        );
    }

    #[test]
    fn new_cached() {
        // Make sure the cache is filled (with nextest, each test is a separate
        // process and so gets a new fsopen(2) for the first ProcfsHandle::new
        // invocation).
        std::thread::spawn(|| {
            let _ = ProcfsHandle::new().expect("should be able to get ProcfsHandle in thread");
        })
        .join()
        .expect("ProcfsHandle::new thread should succeed");

        let procfs1 = ProcfsHandle::new().expect("get procfs handle");
        let procfs2 = ProcfsHandle::new().expect("get procfs handle");

        assert_eq!(
            procfs1.is_subset, procfs2.is_subset,
            "subset=pid should be the same for both handles"
        );
        assert_eq!(
            procfs1.is_detached, procfs2.is_detached,
            "is_detached should be the same for both handles"
        );
        if procfs1.is_subset && procfs1.is_detached {
            assert_eq!(
                procfs1.as_fd().as_raw_fd(),
                procfs2.as_fd().as_raw_fd(),
                "subset=pid handles should be cached and thus have the same fd"
            );
        } else {
            assert_ne!(
                procfs1.as_fd().as_raw_fd(),
                procfs2.as_fd().as_raw_fd(),
                "!subset=pid handles should NOT be cached and thus have different fds"
            );
        }
    }

    #[test]
    fn builder_build_cached() {
        // Make sure the cache is filled (with nextest, each test is a separate
        // process and so gets a new fsopen(2) for the first ProcfsHandle::new
        // invocation).
        std::thread::spawn(|| {
            let _ = ProcfsHandleBuilder::new()
                .build()
                .expect("should be able to get ProcfsHandle in thread");
        })
        .join()
        .expect("ProcfsHandle::new thread should succeed");

        let procfs1 = ProcfsHandleBuilder::new()
            .build()
            .expect("get procfs handle");
        let procfs2 = ProcfsHandleBuilder::new()
            .build()
            .expect("get procfs handle");

        assert_eq!(
            procfs1.is_subset, procfs2.is_subset,
            "subset=pid should be the same for both handles"
        );
        assert_eq!(
            procfs1.is_detached, procfs2.is_detached,
            "is_detached should be the same for both handles"
        );
        if procfs1.is_subset && procfs1.is_detached {
            assert_eq!(
                procfs1.as_fd().as_raw_fd(),
                procfs2.as_fd().as_raw_fd(),
                "subset=pid handles should be cached and thus have the same fd"
            );
        } else {
            assert_ne!(
                procfs1.as_fd().as_raw_fd(),
                procfs2.as_fd().as_raw_fd(),
                "!subset=pid handles should NOT be cached and thus have different fds"
            );
        }
    }
}

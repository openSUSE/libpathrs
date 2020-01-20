/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019, 2020 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019, 2020 SUSE LLC
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
    syscalls, OpenFlags,
};

use std::{
    ffi::{CString, OsStr},
    fs::File,
    os::unix::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawFd, RawFd},
    },
    path::{Path, PathBuf},
};

use snafu::ResultExt;

/// The path separator on Linux.
pub(crate) const PATH_SEPARATOR: u8 = b'/';

// This is part of Linux's ABI.
const PROC_ROOT_INO: u64 = 1;

lazy_static! {
    /// A handle to `/proc` which is used globally by libpathrs. This ensures
    /// that anyone doing funny business with the `/proc` mount on the host
    /// won't be able to impact our re-opening attempts (because this handle is
    /// checked against PROC_SUPER_MAGIC).
    // TODO TODO TODO TODO
    //
    // This "grab a handle to /proc" setup is far from ideal and will need to be
    // pretty massively reworked. The main issue is that bind-mounts could be
    // placed over subpaths of /proc, and all of the semi-obvious approaches to
    // work around this are non-starters for the following reasons:
    //
    // * Using the safe-lookup code itself will be difficult because of
    //   re-entrancy problems. These could be worked-around by adding additional
    //   restrictions to our usage of procfs (don't go through any symlinks, for
    //   instance) and being a bit more clever about procfs usage for procfs
    //   lookups. But then you run into the other issues...
    //
    // * Checking whether the target of an operation is the correct filesystem
    //   is a pointless "hardening" because there are procfs files which can be
    //   used to substitute any procfs file with a no-op one (/proc/self/sched
    //   and /proc/self/environ). So we *really* need to detect bind-mount
    //   crossings as well.
    //
    // * RESOLVE_NO_XDEV requires Linux 5.6, and in older kernels there was no
    //   trivial way to emulate it. The closest you can get is MNT_EXPIRE
    //   (umount) but that approach is incredibly fragile (a stray ".." and
    //   you've broken your check) and also requires privileges that are not
    //   accessible everywhere.
    //
    // * It's possible to mount over symlinks -- meaning that any magic-link
    //   operations (which we have to do a proper in-kernel symlink follow
    //   through) cannot be trusted. RESOLVE_NO_XDEV would work "too well" here
    //   (all magic-links would be blocked because they'd almost certainly
    //   involve a mount-point crossing).
    //
    // While this may seem like a theoretical concern, it has been exploited in
    // the past[1,2]. See [3] for a longer explanation of the many other issues
    // that /proc-based checking is needed to protect against.
    //
    // Another issue is how do we deal with "good" examples of /proc mounting
    // such as LXCFS. LXCFS doesn't touch /proc/$pid right now (and we only care
    // about /proc/$pid right now), but it's something to keep in mind --
    // especially if we end up exposing this to C callers.
    //
    // [1]: https://nvd.nist.gov/vuln/detail/CVE-2019-16884
    // [2]: https://nvd.nist.gov/vuln/detail/CVE-2019-19921
    // [3]: https://youtu.be/tGseJW_uBB8
    static ref PROCFS_HANDLE: File = {
        // Get a /proc handle for the lifetime of the process.
        let proc = syscalls::openat(
            libc::AT_FDCWD,
            "/proc",
            libc::O_PATH | libc::O_DIRECTORY,
            0
        ).expect("/proc should be available");

        // Actually check that /proc isn't a sneaky exploit.
        let fs_type = syscalls::fstatfs(proc.as_raw_fd()).expect("fstatfs(/proc) should work").f_type;
        if fs_type != libc::PROC_SUPER_MAGIC {
            panic!("/proc is not procfs (f_type is 0x{:X}, not 0x{:X})", fs_type, libc::PROC_SUPER_MAGIC)
        }

        // And make sure it's the root of procfs. The root directory is
        // guaranteed to have an inode number of PROC_ROOT_INO. If this check
        // ever stops working, it's a kernel regression.
        let ino = proc.metadata().expect("fstat(/proc) should work").ino();
        if ino != PROC_ROOT_INO {
            panic!("/proc is not root of a procfs mount (ino is 0x{:X}, not 0x{:X})", ino, PROC_ROOT_INO)
        }

        // All great -- this will be re-used by all "/proc" users.
        proc
    };
}

// Private trait necessary to work around the "orphan trait" restriction.
pub(crate) trait ToCString {
    /// Convert to a CStr.
    fn to_c_string(&self) -> CString;
}

impl ToCString for OsStr {
    fn to_c_string(&self) -> CString {
        let filtered: Vec<_> = self
            .as_bytes()
            .iter()
            .copied()
            .take_while(|&c| c != b'\0')
            .collect();
        CString::new(filtered).expect("nul bytes should've been excluded")
    }
}

impl ToCString for Path {
    fn to_c_string(&self) -> CString {
        self.as_os_str().to_c_string()
    }
}

pub(crate) trait RawFdExt {
    /// Re-open a file descriptor.
    fn reopen(&self, flags: OpenFlags) -> Result<File, Error>;

    /// Get the path this RawFd is referencing.
    ///
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy
    /// (hence the name "unsafe"), so it's important to only use this with the
    /// understanding that it only provides the guarantee that "at some point
    /// during execution this was the path the fd pointed to" and
    /// no more.
    fn as_unsafe_path(&self) -> Result<PathBuf, Error>;
}

fn proc_subpath(fd: RawFd) -> Result<String, Error> {
    if fd == libc::AT_FDCWD {
        Ok("self/cwd".to_string())
    } else if fd.is_positive() {
        Ok(format!("self/fd/{}", fd))
    } else {
        error::InvalidArgument {
            name: "fd",
            description: "must be positive or AT_FDCWD",
        }
        .fail()
    }
}

impl RawFdExt for RawFd {
    fn reopen(&self, flags: OpenFlags) -> Result<File, Error> {
        // TODO: We should look into using O_EMPTYPATH if it's available to
        //       avoid the /proc dependency -- though then again, as_unsafe_path
        //       necessarily requires /proc.
        syscalls::openat_follow(PROCFS_HANDLE.as_raw_fd(), proc_subpath(*self)?, flags.0, 0)
            .context(error::RawOsError {
                operation: "reopen fd through procfs",
            })
    }

    fn as_unsafe_path(&self) -> Result<PathBuf, Error> {
        syscalls::readlinkat(PROCFS_HANDLE.as_raw_fd(), proc_subpath(*self)?).context(
            error::RawOsError {
                operation: "get fd's path through procfs",
            },
        )
    }
}

// XXX: We can't use <T: AsRawFd> here, because Rust tells us that RawFd might
//      have an AsRawFd in the future (and thus produce a conflicting
//      implementations error) and so we have to manually define it for the
//      types we are going to be using.

impl RawFdExt for File {
    fn reopen(&self, flags: OpenFlags) -> Result<File, Error> {
        self.as_raw_fd().reopen(flags)
    }

    fn as_unsafe_path(&self) -> Result<PathBuf, Error> {
        // SAFETY: Caller guarantees that as_unsafe_path usage is safe.
        self.as_raw_fd().as_unsafe_path()
    }
}

pub(crate) trait FileExt {
    /// This is a fixed version of the Rust stdlib's `File::try_clone()` which
    /// works on `O_PATH` file descriptors, added to [work around an upstream
    /// bug][bug62314]. The [fix for this bug was merged][pr62425] and will be
    /// available in Rust 1.37.0.
    ///
    /// [bug62314]: https://github.com/rust-lang/rust/issues/62314
    /// [pr62425]: https://github.com/rust-lang/rust/pull/62425
    fn try_clone_hotfix(&self) -> Result<File, Error>;

    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_dangerous(&self) -> Result<bool, Error>;
}

lazy_static! {
    /// Set of filesystems' magic numbers that are considered "dangerous" (in
    /// that they can contain magic-links). This list should hopefully be
    /// exhaustive, but there's no real way of being sure since `nd_jump_link()`
    /// can be used by any non-mainline filesystem.
    // XXX: This list is only correct for Linux 5.4. We should go back into old
    //      kernel versions to see who else used nd_jump_link() in the past.
    static ref DANGEROUS_FILESYSTEMS: Vec<i64> = vec![
        libc::PROC_SUPER_MAGIC,             // procfs
        0x5a3c_69f0 /* libc::AAFS_MAGIC */, // apparmorfs
    ];
}

impl FileExt for File {
    fn try_clone_hotfix(&self) -> Result<File, Error> {
        syscalls::fcntl_dupfd_cloxec(self.as_raw_fd()).context(error::RawOsError {
            operation: "clone fd",
        })
    }

    fn is_dangerous(&self) -> Result<bool, Error> {
        // There isn't a marker on a filesystem level to indicate whether
        // nd_jump_link() is used internally. So, we just have to make an
        // educated guess based on which mainline filesystems expose
        // magic-links.
        let stat = syscalls::fstatfs(self.as_raw_fd()).context(error::RawOsError {
            operation: "check fstype of fd",
        })?;
        Ok(DANGEROUS_FILESYSTEMS.contains(&stat.f_type))
    }
}

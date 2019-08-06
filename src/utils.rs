/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019 SUSE LLC
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

//! Only used internally by libpathrs.
#![doc(hidden)]

use crate::{syscalls, OpenFlags};

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::os::unix::{
    ffi::OsStrExt,
    io::{AsRawFd, RawFd},
};
use std::path::{Path, PathBuf};

use failure::Error as FailureError;

/// The path separator on Linux.
pub const PATH_SEPARATOR: u8 = b'/';

lazy_static! {
    /// A handle to `/proc` which is used globally by libpathrs. This ensures
    /// that anyone doing funny business with the `/proc` mount on the host
    /// won't be able to impact our re-opening attempts (because this handle is
    /// checked against PROC_SUPER_MAGIC).
    // In future, we might need to have a separate handle for "/proc/self"
    // because there has been discussion on splitting procfs into "the process
    // bits" and "the other crap" -- but it's unclear if that will ever happen
    // so we can sit on it for now.
    static ref PROCFS_HANDLE: File = {
        // Get a /proc handle for the lifetime of the process.
        let proc = syscalls::openat(
            libc::AT_FDCWD,
            "/proc",
            libc::O_PATH | libc::O_DIRECTORY,
            0
        ).expect("/proc should be available");

        // Actually check that /proc isn't a sneaky exploit.
        let stat = syscalls::fstatfs(proc.as_raw_fd()).expect("fstatfs(/proc) should work");
        if stat.f_type != libc::PROC_SUPER_MAGIC {
            panic!("/proc is not actually procfs (f_type is 0x{:X}, but expected 0x{:X})!", stat.f_type, libc::PROC_SUPER_MAGIC)
        }

        // All great -- this will be re-used by all "/proc" users.
        proc
    };
}

pub trait ToCString {
    /// Convert to a CStr.
    fn to_c_string(&self) -> CString;
}

impl ToCString for OsStr {
    fn to_c_string(&self) -> CString {
        let filtered: Vec<_> = self
            .as_bytes()
            .iter()
            .map(|&c| c) // .copied() is in Rust >= 1.36.0
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

pub trait RawFdExt {
    /// Re-open a file descriptor.
    fn reopen(&self, flags: OpenFlags) -> Result<File, FailureError>;

    /// Get the path this RawFd is referencing.
    ///
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy
    /// (hence the name "unsafe"), so it's important to only use this with the
    /// understanding that it only provides the guarantee that "at some point
    /// during execution this was the path the fd pointed to" and
    /// no more.
    fn as_unsafe_path(&self) -> Result<PathBuf, FailureError>;
}

fn proc_subpath(fd: RawFd) -> Result<String, FailureError> {
    if fd == libc::AT_FDCWD {
        Ok(format!("self/cwd"))
    } else if fd.is_positive() {
        Ok(format!("self/fd/{}", fd))
    } else {
        bail!("invalid fd: {}", fd)
    }
}

impl RawFdExt for RawFd {
    fn reopen(&self, flags: OpenFlags) -> Result<File, FailureError> {
        // TODO: We should look into using O_EMPTYPATH if it's available to
        //       avoid the /proc dependency -- though then again,
        //       `as_unsafe_path` necessarily requires /proc.
        syscalls::openat_follow(PROCFS_HANDLE.as_raw_fd(), proc_subpath(*self)?, flags.0, 0)
    }

    fn as_unsafe_path(&self) -> Result<PathBuf, FailureError> {
        syscalls::readlinkat(PROCFS_HANDLE.as_raw_fd(), proc_subpath(*self)?)
    }
}

// XXX: We can't use <T: AsRawFd> here, because Rust tells us that RawFd might
//      have an AsRawFd in the future (and thus produce a conflicting
//      implementations error) and so we have to manually define it for the
//      types we are going to be using.

impl RawFdExt for File {
    fn reopen(&self, flags: OpenFlags) -> Result<File, FailureError> {
        self.as_raw_fd().reopen(flags)
    }

    fn as_unsafe_path(&self) -> Result<PathBuf, FailureError> {
        self.as_raw_fd().as_unsafe_path()
    }
}

pub trait FileExt {
    /// This is a fixed version of the Rust stdlib's `File::try_clone()` which
    /// works on `O_PATH` file descriptors, added to [work around an upstream
    /// bug][bug62314]. The [fix for this bug was merged][pr62425] and will be
    /// available in Rust 1.37.0.
    ///
    /// [bug62314]: https://github.com/rust-lang/rust/issues/62314
    /// [pr62425]: https://github.com/rust-lang/rust/pull/62425
    fn try_clone_hotfix(&self) -> Result<File, FailureError>;

    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_dangerous(&self) -> Result<bool, FailureError>;
}

lazy_static! {
    /// Set of filesystems' magic numbers that are considered "dangerous" (in
    /// that they can contain magic-links). This list should hopefully be
    /// exhaustive, but there's no real way of being sure since `nd_jump_link()`
    /// can be used by any non-mainline filesystem.
    // XXX: This list is only correct for Linux 5.2. We should go back into old
    //      kernel versions to see who else used nd_jump_link() in the past.
    static ref DANGEROUS_FILESYSTEMS: Vec<i64> = vec![
        libc::PROC_SUPER_MAGIC,            // procfs
        0x5a3c69f0 /* libc::AAFS_MAGIC */, // apparmorfs
    ];
}

impl FileExt for File {
    fn try_clone_hotfix(&self) -> Result<File, FailureError> {
        syscalls::fcntl_dupfd_cloxec(self.as_raw_fd())
    }

    fn is_dangerous(&self) -> Result<bool, FailureError> {
        // There isn't a marker on a filesystem level to indicate whether
        // nd_jump_link() is used internally. So, we just have to make an
        // educated guess based on which mainline filesystems expose
        // magic-links.

        let stat = syscalls::fstatfs(self.as_raw_fd())?;
        Ok(DANGEROUS_FILESYSTEMS.contains(&stat.f_type))
    }
}

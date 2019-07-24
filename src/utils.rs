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

use crate::syscalls;

use std::ffi::{CString, OsStr};
use std::os::unix::{
    ffi::OsStrExt,
    io::{AsRawFd, RawFd},
};
use std::path::{Path, PathBuf};
use std::{fs, fs::File};

use failure::{Error as FailureError, ResultExt};

/// The path separator on Linux.
pub const PATH_SEPARATOR: u8 = b'/';

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
    /// Get a /proc/self/fd/$n path for this RawFd.
    fn as_procfd_path(&self) -> Result<PathBuf, FailureError>;

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

impl RawFdExt for RawFd {
    fn as_procfd_path(&self) -> Result<PathBuf, FailureError> {
        if *self == libc::AT_FDCWD {
            Ok(format!("/proc/self/cwd").into())
        } else if self.is_positive() {
            Ok(format!("/proc/self/fd/{}", self).into())
        } else {
            bail!("invalid fd: {}", self)
        }
    }

    fn as_unsafe_path(&self) -> Result<PathBuf, FailureError> {
        if self.is_negative() {
            return Ok("<AT_FDCWD>".into());
        }
        let path = self.as_procfd_path()?;
        let path = fs::read_link(path).context("readlink /proc/self/fd")?;
        Ok(path)
    }
}

// XXX: We can't use <T: AsRawFd> here, because Rust tells us that RawFd might
//      have an AsRawFd in the future (and thus produce a conflicting
//      implementations error) and so we have to manually define it for the
//      types we are going to be using.

impl RawFdExt for File {
    fn as_procfd_path(&self) -> Result<PathBuf, FailureError> {
        self.as_raw_fd().as_procfd_path()
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

impl FileExt for File {
    fn try_clone_hotfix(&self) -> Result<File, FailureError> {
        syscalls::fcntl_dupfd_cloxec(self.as_raw_fd())
    }

    fn is_dangerous(&self) -> Result<bool, FailureError> {
        // TODO: Implement this.
        Ok(false)
    }
}

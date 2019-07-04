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

use std::ffi::{CString, OsStr};
use std::io::Error as IOError;
use std::os::unix::{
    ffi::OsStrExt,
    io::{AsRawFd, FromRawFd, RawFd},
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
    /// Get the path this RawFd is referencing.
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy, so
    /// it's important to only use this with the understanding that it only
    /// provides the guarantee that "at some point during execution this was the
    /// path the fd pointed to" and no more.
    fn as_path(&self) -> Result<PathBuf, FailureError>;

    /// Get the path this RawFd is referencing, or a stock value in case of
    /// failure.
    fn as_path_lossy(&self) -> PathBuf;
}

impl RawFdExt for RawFd {
    fn as_path(&self) -> Result<PathBuf, FailureError> {
        if self.is_negative() {
            return Ok("<AT_FDCWD>".into());
        }
        let path = format!("/proc/self/fd/{}", self);
        let path = fs::read_link(path).context("readlink /proc/self/fd")?;
        Ok(path)
    }

    // Can't make this a trait impl since that makes the interface uglier.
    fn as_path_lossy(&self) -> PathBuf {
        self.as_path().unwrap_or("<unknown>".into())
    }
}

pub trait FileExt {
    /// Get the path this File is referencing.
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy, so
    /// it's important to only use this with the understanding that it only
    /// provides the guarantee that "at some point during execution this was the
    /// path the file pointed to" and no more.
    fn as_path(&self) -> Result<PathBuf, FailureError>;

    /// Basic wrapper around `fctnl(F_DUPFD_CLOEXEC)`.
    fn dup_cloexec(&self) -> Result<File, FailureError>;

    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_dangerous(&self) -> Result<bool, FailureError>;
}

impl FileExt for File {
    fn as_path(&self) -> Result<PathBuf, FailureError> {
        self.as_raw_fd().as_path()
    }

    fn dup_cloexec(&self) -> Result<File, FailureError> {
        let fd = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        let err: IOError = errno::errno().into();
        if fd >= 0 {
            Ok(unsafe { File::from_raw_fd(fd) })
        } else {
            Err(err).context("dupfd cloexec")?
        }
    }

    fn is_dangerous(&self) -> Result<bool, FailureError> {
        // TODO: Implement this.
        Ok(false)
    }
}

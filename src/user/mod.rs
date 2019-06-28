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

//! libpathrs::user implements an emulated version of the openat(2) patchset's
//! features. The primary method by which this is done is through shameless
//! abuse of procfs and O_PATH magic-links. The basic idea is that we need to
//! perform all of the path resolution steps (walking down the set of
//! components, handling the effect of symlinks on the resolution, etc).
//!
//! In order to do this safely we need to verify after the walk is done whether
//! the path of the final file descriptor is what we expected (most importantly,
//! is it inside the root which we started the walk with?). This check is done
//! through readlink(/proc/self/fd/$n), which is a magic kernel interface which
//! gives you the kernel's view of the path -- and in cases where the kernel is
//! unsure or otherwise unhappy you get "/".
//!
//! If the check fails, we assume we are being attacked and return an error (and
//! the caller can decide to re-try if they want). The kernel implementation
//! will fail in fewer cases because it has access to in-kernel locks and other
//! measures, but the final check throgh procfs should block all attack
//! attempts.

use super::{Handle, InodeType, Root};
use std::fs::{File, OpenOptions, Permissions};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use failure::Error;

#[derive(Debug)]
struct EmulatedHandle {
    fd: RawFd,
    path: PathBuf,
}

// RawFds aren't auto-dropped in Rust so we need to do it manually. As long as
// nobody has done anything strange with the current process's fds, this will
// not fail.
impl Drop for EmulatedHandle {
    fn drop(&mut self) {
        // Cannot return errors in Drop or panic! in C FFI. So just ignore it.
        unsafe { libc::close(self.fd) };
    }
}

pub fn open(path: &Path) -> Result<Box<dyn Root>, Error> {
    bail!("not yet implemented");
}

impl Handle for EmulatedHandle {
    fn reopen(&self, options: &OpenOptions) -> Result<File, Error> {
        bail!("not yet implemented");
    }
}

impl Root for EmulatedHandle {
    fn resolve(&self, path: &Path) -> Result<Box<dyn Handle>, Error> {
        bail!("not yet implemented");
    }

    fn create(&self, path: &Path, inode_type: &InodeType) -> Result<(), Error> {
        bail!("not yet implemented");
    }

    fn create_file(&self, path: &Path, perm: &Permissions) -> Result<Box<dyn Handle>, Error> {
        bail!("not yet implemented");
    }

    fn remove(&self, path: &Path) -> Result<(), Error> {
        bail!("not yet implemented");
    }
}

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

mod syscall;
pub use syscall::supported;
use syscall::OpenHow;

use crate::{Error, Handle, Root};

use core::convert::TryFrom;
use std::os::unix::io::RawFd;
use std::path::Path;

use failure::{Error as FailureError, ResultExt};

#[derive(Debug)]
struct NativeHandle {
    fd: RawFd,
}

// RawFds aren't auto-dropped in Rust so we need to do it manually. As long as
// nobody has done anything strange with the current process's fds, this will
// not fail.
impl Drop for NativeHandle {
    fn drop(&mut self) {
        // Cannot return errors in Drop or panic! in C FFI. So just ignore it.
        unsafe { libc::close(self.fd) };
    }
}

pub fn open(path: &Path) -> Result<Box<dyn Root>, FailureError> {
    let path = path
        .to_str()
        .ok_or(Error::InvalidArgument("path", "not a valid Rust string"))?;

    let mut how = OpenHow::default();
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u32;

    let fd = syscall::openat2(libc::AT_FDCWD, path, &how).context("open root path")?;
    Ok(Box::new(NativeHandle { fd: fd }))
}

impl Root for NativeHandle {
    fn resolve(&self, path: &Path) -> Result<Handle, FailureError> {
        let path = path
            .to_str()
            .ok_or(Error::InvalidArgument("path", "not a valid Rust string"))?;

        let mut how = OpenHow::default();
        how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u32;
        how.resolve = syscall::RESOLVE_IN_ROOT;

        let fd = syscall::openat2(self.fd, path, &how).context("open subpath")?;
        Ok(Handle::try_from(fd).context("convert RESOLVE_IN_ROOT fd to Handle")?)
    }
}

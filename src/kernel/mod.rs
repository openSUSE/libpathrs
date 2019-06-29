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

use super::{Handle, Root};
use std::os::unix::io::RawFd;
use std::path::Path;

use failure::Error;

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

pub fn open(path: &Path) -> Result<Box<dyn Root>, Error> {
    bail!("not yet implemented");
}

impl Root for NativeHandle {
    fn resolve(&self, path: &Path) -> Result<Handle, Error> {
        bail!("not yet implemented");
    }
}

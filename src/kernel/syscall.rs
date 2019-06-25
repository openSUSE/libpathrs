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

//! WARNING: The ABI for this syscall is still being ironed out upstream. This
//! will almost certainly not work on your machine, and may cause other problems
//! depending on what syscall is using the syscall number this code will call.

use std::ffi::CString;
use std::io::Error as IOError;
use std::os::unix::io::RawFd;

use libc::{c_char, c_long, c_int};
use failure::Error;

/// get_errno constructs a failure::Error from the current system errno value.
pub fn get_errno() -> Error {
    Error::from_boxed_compat(Box::new(Into::<IOError>::into(errno::errno())))
}

#[repr(C)]
pub struct NewOpenatOptions {
    // TODO: Still being designed.
}

impl NewOpenatOptions {
    // TODO: Still being designed.
}

#[allow(non_upper_case_globals)]
const SYS_openat2: c_long = 435;

unsafe fn openat2_raw(dirfd: c_int, pathname: *const c_char, opts: *const NewOpenatOptions) -> c_int {
    libc::syscall(SYS_openat2, dirfd, pathname, opts) as c_int
}

/// openat2 is a nix-like wrapper of openat2.
pub fn openat2(dirfd: RawFd, pathname: &str, opts: &NewOpenatOptions) -> Result<RawFd, Error> {
    let pathname = CString::new(pathname)?;
    let fd = unsafe { openat2_raw(dirfd, pathname.into_raw(), opts) };
    if fd >= 0 {
        Ok(fd as RawFd)
    } else {
        Err(get_errno())
    }
}

/// supported checks at runtime whether the current running kernel supports
/// openat2(2) with RESOLVE_THIS_ROOT. This can be used to decide which
/// underlying interface to use.
pub fn supported() -> bool {
    let opts = NewOpenatOptions{};
    match openat2(libc::AT_FDCWD, ".", &opts) {
        Err(_) => false,
        Ok(fd) => {
            unsafe { libc::close(fd) };
            true
        }
    }
}

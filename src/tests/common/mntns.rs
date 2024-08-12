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

use std::{
    ffi::CString,
    fs::File,
    io::Error as IOError,
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    ptr,
};

use crate::syscalls;

use anyhow::Error;
use libc::c_int;

unsafe fn unshare(flags: c_int) -> Result<(), IOError> {
    // SAFETY: Caller guarantees that this unshare operation is safe.
    let ret = unsafe { libc::unshare(flags) };
    let err = IOError::last_os_error();
    if ret >= 0 {
        Ok(())
    } else {
        Err(err)
    }
}

unsafe fn setns(fd: RawFd, flags: c_int) -> Result<(), IOError> {
    // SAFETY: Caller guarantees that this setns operation is safe.
    let ret = unsafe { libc::setns(fd, flags) };
    let err = IOError::last_os_error();
    if ret >= 0 {
        Ok(())
    } else {
        Err(err)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum MountType {
    Tmpfs,
    Bind { src: PathBuf },
}

pub(crate) fn mount<P: AsRef<Path>>(dst: P, ty: MountType) -> Result<(), Error> {
    let dst = dst.as_ref();
    let dst_file = syscalls::openat(libc::AT_FDCWD, dst, libc::O_NOFOLLOW | libc::O_PATH, 0)?;
    let dst_path = CString::new(format!("/proc/self/fd/{}", dst_file.as_raw_fd()))?;

    let ret = match ty {
        MountType::Tmpfs => unsafe {
            libc::mount(
                c"".as_ptr(),
                dst_path.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                ptr::null(),
            )
        },
        MountType::Bind { src } => {
            let src_file =
                syscalls::openat(libc::AT_FDCWD, src, libc::O_NOFOLLOW | libc::O_PATH, 0)?;
            let src_path = CString::new(format!("/proc/self/fd/{}", src_file.as_raw_fd()))?;
            unsafe {
                libc::mount(
                    src_path.as_ptr(),
                    dst_path.as_ptr(),
                    ptr::null(),
                    libc::MS_BIND,
                    ptr::null(),
                )
            }
        }
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err.into())
    }
}

pub(crate) fn in_mnt_ns<F, T>(func: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
{
    let old_ns = File::open("/proc/self/ns/mnt")?;

    // TODO: Run this in a subprocess.

    unsafe { unshare(libc::CLONE_FS | libc::CLONE_NEWNS) }
        .expect("unable to create a mount namespace");

    let ret = func();

    unsafe { setns(old_ns.as_raw_fd(), libc::CLONE_NEWNS) }
        .expect("unable to rejoin old namespace");

    ret
}

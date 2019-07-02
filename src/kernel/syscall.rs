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

use libc::{c_char, c_int, c_long};

/// `OpenHow.access` field definition.
#[repr(C)]
pub union Access {
    /// O_CREAT file mode (ignored otherwise).
    pub mode: u16,
    /// Restrict how the O_PATH may be re-opened (ignored otherwise).
    pub upgrade_mask: u16,
}

/// Arguments for how `openat2` should open the target path.
///
/// If `extra` is zero, then `openat2` is identical to `openat`. Only one of the
/// members of access may be set at any given time.
#[repr(C)]
pub struct OpenHow {
    /// O_* flags (unknown flags ignored).
    pub flags: u32,
    /// Access settings (ignored otherwise).
    pub access: Access,
    /// RESOLVE_* flags (`-EINVAL` on unknown flags).
    pub resolve: u16,
    /// Reserved for future extensions, must be zeroed.
    _reserved: [u64; 7],
}

impl Default for OpenHow {
    #[inline]
    fn default() -> Self {
        // We could do std::mem::zeroed but let's avoid unsafe blocks.
        OpenHow {
            flags: 0,
            access: Access { mode: 0 },
            resolve: 0,
            _reserved: [0; 7],
        }
    }
}

/// Block mount-point crossings (including bind-mounts).
#[allow(unused)]
pub const RESOLVE_NO_XDEV: u16 = 0x01;

/// Block traversal through procfs-style "magic links".
#[allow(unused)]
pub const RESOLVE_NO_MAGICLINKS: u16 = 0x02;

/// Block traversal through all symlinks (implies RESOLVE_NO_MAGICLINKS).
#[allow(unused)]
pub const RESOLVE_NO_SYMLINKS: u16 = 0x04;

/// Block "lexical" trickery like "..", symlinks-to-"/", and absolute paths
/// which escape the dirfd.
#[allow(unused)]
pub const RESOLVE_BENEATH: u16 = 0x08;

/// Make all jumps to "/" or ".." be scoped inside the dirfd (similar to
/// `chroot`).
#[allow(unused)]
pub const RESOLVE_IN_ROOT: u16 = 0x10;

/// Block re-opening with MAY_READ.
#[allow(unused)]
pub const UPGRADE_NOWRITE: u16 = 0x02;

/// Block re-opening with MAY_READ.
#[allow(unused)]
pub const UPGRADE_NOREAD: u16 = 0x04;

#[allow(non_upper_case_globals)]
const SYS_openat2: c_long = 435;

unsafe fn openat2_raw(dirfd: c_int, pathname: *const c_char, how: *const OpenHow) -> c_int {
    libc::syscall(SYS_openat2, dirfd, pathname, how) as c_int
}

/// Basic wrapper around openat2.
pub fn openat2(dirfd: RawFd, pathname: &str, how: &OpenHow) -> Result<RawFd, IOError> {
    let pathname = CString::new(pathname)?;
    let fd = unsafe { openat2_raw(dirfd, pathname.into_raw(), how) };
    if fd >= 0 {
        Ok(fd as RawFd)
    } else {
        Err(errno::errno().into())
    }
}

/// supported checks at runtime whether the current running kernel supports
/// openat2(2) with RESOLVE_THIS_ROOT. This can be used to decide which
/// underlying interface to use.
pub fn supported() -> bool {
    let how = Default::default();
    match openat2(libc::AT_FDCWD, ".", &how) {
        Err(_) => false,
        Ok(fd) => {
            unsafe { libc::close(fd) };
            true
        }
    }
}

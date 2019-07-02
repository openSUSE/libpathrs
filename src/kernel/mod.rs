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
use syscall::OpenHow;

use crate::{Handle, Root};

use core::convert::TryFrom;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::path::Path;

use failure::{Error as FailureError, ResultExt};

pub fn resolve(root: &Root, path: &Path) -> Result<Handle, FailureError> {
    let file = OpenHow::new()
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .custom_resolve(syscall::RESOLVE_IN_ROOT)
        .open(root.as_raw_fd(), path)
        .context("open sub-path")?;

    let handle =
        Handle::try_from(file.as_raw_fd()).context("convert RESOLVE_IN_ROOT fd to Handle")?;

    // Move the file *after* we successfully created the handle.
    let _fd = file.into_raw_fd();
    Ok(handle)
}

/// supported checks at runtime whether the current running kernel supports
/// openat2(2) with RESOLVE_THIS_ROOT. This can be used to decide which
/// underlying interface to use.
pub fn supported() -> bool {
    OpenHow::new().open(libc::AT_FDCWD, ".").is_ok()
}

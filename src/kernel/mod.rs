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
use std::os::unix::io::AsRawFd;
use std::path::Path;

use failure::{Error as FailureError, ResultExt};

lazy_static! {
    #[doc(hidden)]
    pub static ref IS_SUPPORTED: bool = OpenHow::new().open(libc::AT_FDCWD, ".").is_ok();
}

/// Resolve `path` within `root` through `openat2(2)`.
pub fn resolve<P: AsRef<Path>>(root: &Root, path: P) -> Result<Handle, FailureError> {
    if !*IS_SUPPORTED {
        bail!("kernel resolution is not supported on this kernel")
    }

    let file = OpenHow::new()
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .custom_resolve(syscall::RESOLVE_IN_ROOT)
        .open(root.as_raw_fd(), path)
        .context("open sub-path")?;

    let handle = Handle::try_from(file).context("convert RESOLVE_IN_ROOT fd to Handle")?;
    Ok(handle)
}

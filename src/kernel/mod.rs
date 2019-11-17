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

use crate::syscalls::unstable;
use crate::user;
use crate::{Handle, Root};

use core::convert::TryFrom;
use std::io::Error as IOError;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use failure::{Error as FailureError, ResultExt};

lazy_static! {
    pub(crate) static ref IS_SUPPORTED: bool = {
        let how = unstable::OpenHow::new();
        unstable::openat2(libc::AT_FDCWD, ".", &how).is_ok()
    };
}

/// Resolve `path` within `root` through `openat2(2)`.
pub(crate) fn resolve<P: AsRef<Path>>(root: &Root, path: P) -> Result<Handle, FailureError> {
    if !*IS_SUPPORTED {
        bail!("kernel resolution is not supported on this kernel")
    }

    let mut how = unstable::OpenHow::new();
    how.flags = libc::O_PATH as u64;
    // RESOLVE_IN_ROOT does exactly what we want, but we also want to avoid
    // resolving magic-links. RESOLVE_IN_ROOT already blocks magic-link
    // crossings, but that may change in the future (if the magic-links are
    // considered "safe") but we should still explicitly avoid them entirely.
    how.resolve = unstable::RESOLVE_IN_ROOT | unstable::RESOLVE_NO_MAGICLINKS;

    // openat2(2) can fail with -EAGAIN if there was a racing rename or mount
    // *anywhere on the system*. This can happen pretty frequently, so what we
    // do is attempt the openat2(2) a couple of times, and then fall-back to
    // userspace emulation.
    let mut handle: Option<Handle> = None;
    for _ in 0..16 {
        let file = unstable::openat2(root.as_raw_fd(), path.as_ref(), &how);
        match file {
            Ok(file) => {
                handle =
                    Some(Handle::try_from(file).context("convert RESOLVE_IN_ROOT fd to Handle")?);
                break;
            }
            Err(err) => {
                match err
                    .find_root_cause()
                    .downcast_ref::<IOError>()
                    .map(|ioerr| ioerr.raw_os_error())
                {
                    Some(Some(libc::EAGAIN)) => continue,
                    _ => return Err(err).context("open sub-path")?,
                }
            }
        }
    }

    Ok(handle.unwrap_or(
        user::resolve(root, path).context("fallback user-space resolution for RESOLVE_IN_ROOT")?,
    ))
}

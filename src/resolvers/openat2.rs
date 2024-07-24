/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

use crate::{
    error::{self, Error},
    resolvers::ResolverFlags,
    syscalls::{self, OpenHow},
    Handle,
};

use std::{fs::File, os::unix::io::AsRawFd, path::Path};

use snafu::ResultExt;

/// Resolve `path` within `root` through `openat2(2)`.
pub(crate) fn resolve<P: AsRef<Path>>(
    root: &File,
    path: P,
    rflags: ResolverFlags,
) -> Result<Handle, Error> {
    ensure!(
        *syscalls::OPENAT2_IS_SUPPORTED,
        error::NotSupportedSnafu { feature: "openat2" }
    );

    // Copy the O_NOFOLLOW and RESOLVE_NO_SYMLINKS bits from flags.
    let oflags = libc::O_PATH as u64 | rflags.openat2_flag_bits();
    let rflags =
        libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS | rflags.openat2_resolve_bits();

    let how = OpenHow {
        flags: oflags,
        resolve: rflags,
        ..Default::default()
    };

    // openat2(2) can fail with -EAGAIN if there was a racing rename or mount
    // *anywhere on the system*. This can happen pretty frequently, so what we
    // do is attempt the openat2(2) a couple of times. If it still fails, just
    // error out.
    for _ in 0..16 {
        match syscalls::openat2(root.as_raw_fd(), path.as_ref(), &how) {
            Ok(file) => return Ok(Handle::from_file_unchecked(file)),
            Err(err) => match err.root_cause().raw_os_error() {
                Some(libc::ENOSYS) => {
                    // shouldn't happen
                    return error::NotSupportedSnafu { feature: "openat2" }.fail();
                }
                Some(libc::EAGAIN) => continue,
                // TODO: Add wrapper for known-bad openat2 return codes.
                //Some(libc::EXDEV) | Some(libc::ELOOP) => { ... }
                _ => {
                    return Err(err).context(error::RawOsSnafu {
                        operation: "openat2 subpath",
                    })?
                }
            },
        }
    }

    error::SafetyViolationSnafu {
        description: "racing filesystem changes caused openat2 to abort",
    }
    .fail()
}

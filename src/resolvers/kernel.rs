/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2020 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2020 SUSE LLC
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
    error::{self, Error, ErrorExt},
    resolvers::{self, ResolverFlags},
    syscalls::unstable,
    Handle,
};

use std::{fs::File, os::unix::io::AsRawFd, path::Path};

use snafu::ResultExt;

lazy_static! {
    pub(crate) static ref IS_SUPPORTED: bool =
        unstable::openat2(libc::AT_FDCWD, ".", &Default::default()).is_ok();
}

/// Resolve `path` within `root` through `openat2(2)`.
pub(crate) fn resolve<P: AsRef<Path>>(
    root: &File,
    path: P,
    flags: ResolverFlags,
) -> Result<Handle, Error> {
    ensure!(*IS_SUPPORTED, error::NotSupported { feature: "openat2" });

    let mut how = unstable::OpenHow::default();
    how.flags = libc::O_PATH as u64;
    // RESOLVE_IN_ROOT does exactly what we want, but we also want to avoid
    // resolving magic-links. RESOLVE_IN_ROOT already blocks magic-link
    // crossings, but that may change in the future (if the magic-links are
    // considered "safe") but we should still explicitly avoid them entirely.
    how.resolve = unstable::RESOLVE_IN_ROOT | unstable::RESOLVE_NO_MAGICLINKS | flags.bits;

    // openat2(2) can fail with -EAGAIN if there was a racing rename or mount
    // *anywhere on the system*. This can happen pretty frequently, so what we
    // do is attempt the openat2(2) a couple of times, and then fall-back to
    // userspace emulation.
    let mut handle: Option<File> = None;
    for _ in 0..16 {
        match unstable::openat2(root.as_raw_fd(), path.as_ref(), &how) {
            Ok(file) => {
                handle = Some(file);
                break;
            }
            Err(err) => match err.root_cause().raw_os_error() {
                Some(libc::ENOSYS) => break, // shouldn't happen
                Some(libc::EAGAIN) => continue,
                // TODO: Add wrapper for known-bad openat2 return codes.
                //Some(libc::EXDEV) | Some(libc::ELOOP) => { ... }
                _ => {
                    return Err(err).context(error::RawOsError {
                        operation: "openat2 subpath",
                    })?
                }
            },
        }
    }

    handle.map_or_else(
        || {
            resolvers::user::resolve(root, path, flags)
                .wrap("fallback user-space resolution for RESOLVE_IN_ROOT")
        },
        |file| Ok(Handle::from_file_unchecked(file)),
    )
}

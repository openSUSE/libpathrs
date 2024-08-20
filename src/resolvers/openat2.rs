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

use crate::{
    error::{Error, ErrorImpl},
    flags::{OpenFlags, ResolverFlags},
    resolvers::PartialLookup,
    syscalls::{self, OpenHow},
    utils::PathIterExt,
    Handle,
};

use std::{
    fs::File,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};

/// Resolve `path` within `root` through `openat2(2)`.
pub(crate) fn resolve<P: AsRef<Path>>(
    root: &File,
    path: P,
    rflags: ResolverFlags,
    no_follow_trailing: bool,
) -> Result<Handle, Error> {
    if !*syscalls::OPENAT2_IS_SUPPORTED {
        Err(ErrorImpl::NotSupported {
            feature: "openat2".into(),
        })?
    }

    // Copy the O_NOFOLLOW and RESOLVE_NO_SYMLINKS bits from flags.
    let mut oflags = OpenFlags::O_PATH;
    if no_follow_trailing {
        oflags.insert(OpenFlags::O_NOFOLLOW);
    }
    let rflags = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS | rflags.bits();

    let how = OpenHow {
        flags: oflags.bits() as u64,
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
                    Err(ErrorImpl::NotSupported {
                        feature: "openat2".into(),
                    })?
                }
                Some(libc::EAGAIN) => continue,
                // TODO: Add wrapper for known-bad openat2 return codes.
                //Some(libc::EXDEV) | Some(libc::ELOOP) => { ... }
                _ => Err(ErrorImpl::RawOsError {
                    operation: "openat2 subpath".into(),
                    source: err,
                })?,
            },
        }
    }

    Err(ErrorImpl::SafetyViolation {
        description: "racing filesystem changes caused openat2 to abort".into(),
    })?
}

/// Resolve as many components as possible in `path` within `root` using
/// `openat2(2)`.
pub(crate) fn resolve_partial(
    root: &File,
    path: &Path,
    rflags: ResolverFlags,
    no_follow_trailing: bool,
) -> Result<PartialLookup<Handle>, Error> {
    let mut last_error = match resolve(root, path, rflags, no_follow_trailing) {
        Ok(handle) => return Ok(PartialLookup::Complete(handle)),
        Err(err) => err,
    };

    // TODO: We probably want to do a git-bisect-like binary-search here. For
    //       paths with a large number of components this could make a
    //       significant difference, though in practice you'll only see.
    //       really large paths this could make a significant difference.
    for (path, remaining) in path.partial_ancestors() {
        match resolve(root, path, rflags, no_follow_trailing) {
            Ok(handle) => {
                return Ok(PartialLookup::Partial {
                    handle,
                    remaining: remaining.map(PathBuf::from).unwrap_or("".into()),
                    last_error,
                })
            }
            Err(err) => last_error = err,
        }
    }

    // Fall back to returning (root, path) if there was no path found.
    //
    // TODO: In theory you should never hit this case because
    // partial_ancestors() always returns a "root" value. This should probably
    // be unreachable!()...
    Ok(PartialLookup::Partial {
        handle: root
            .try_clone()
            .map(Handle::from_file_unchecked)
            .map_err(|err| ErrorImpl::OsError {
                operation: "clone root".into(),
                source: err,
            })?,
        remaining: path.into(),
        last_error,
    })
}

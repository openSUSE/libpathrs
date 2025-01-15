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
    os::unix::io::AsFd,
    path::{Path, PathBuf},
};

/// Open `path` within `root` through `openat(2)`.
///
/// This is an optimised version of `resolve(root, path, ...)?.reopen(flags)`.
pub(crate) fn open<Fd: AsFd, P: AsRef<Path>>(
    root: Fd,
    path: P,
    rflags: ResolverFlags,
    oflags: OpenFlags,
) -> Result<File, Error> {
    if !*syscalls::OPENAT2_IS_SUPPORTED {
        Err(ErrorImpl::NotSupported {
            feature: "openat2".into(),
        })?
    }

    let rflags = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS | rflags.bits();
    let how = OpenHow {
        flags: oflags.bits() as u64,
        resolve: rflags,
        ..Default::default()
    };

    syscalls::openat2(&root, path.as_ref(), &how)
        .map(File::from)
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "openat2 one-shot open".into(),
                source: err,
            }
            .into()
        })
}

/// Resolve `path` within `root` through `openat2(2)`.
pub(crate) fn resolve<Fd: AsFd, P: AsRef<Path>>(
    root: Fd,
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
        match syscalls::openat2(&root, path.as_ref(), &how) {
            Ok(file) => return Ok(Handle::from_fd(file)),
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
pub(crate) fn resolve_partial<Fd: AsFd>(
    root: Fd,
    path: &Path,
    rflags: ResolverFlags,
    no_follow_trailing: bool,
) -> Result<PartialLookup<Handle>, Error> {
    let root = root.as_fd();
    let mut last_error = match resolve(root, path, rflags, no_follow_trailing) {
        Ok(handle) => return Ok(PartialLookup::Complete(handle)),
        Err(err) => err,
    };

    // TODO: We probably want to do a git-bisect-like binary-search here. For
    //       paths with a large number of components this could make a
    //       significant difference, though in practice you'll only see fairly
    //       short paths so the implementation complexity might not be worth it.
    for (path, remaining) in path.partial_ancestors() {
        if last_error.is_safety_violation() {
            // If we hit a safety violation, we return an error instead of a
            // partial resolution to match the behaviour of the O_PATH
            // resolver (and to avoid some possible weird bug in libpathrs
            // being exploited to return some result to Root::mkdir_all).
            return Err(last_error);
        }
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

    unreachable!("partial_ancestors should include root path which must be resolvable");
}

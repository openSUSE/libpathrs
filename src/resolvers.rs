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

#![forbid(unsafe_code)]

//! Resolver implementations for libpathrs.

use crate::{
    error::{Error, ErrorImpl, ErrorKind},
    flags::{OpenFlags, ResolverFlags},
    syscalls,
    utils::FdExt,
    Handle,
};

use std::{
    fs::File,
    io::Error as IOError,
    os::unix::io::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    rc::Rc,
};

use once_cell::sync::Lazy;

/// `O_PATH`-based userspace resolver.
pub(crate) mod opath {
    mod r#impl;
    pub(crate) use r#impl::*;

    mod symlink_stack;
    pub(crate) use symlink_stack::{SymlinkStack, SymlinkStackError};
}

/// `openat2(2)`-based in-kernel resolver.
pub(crate) mod openat2;

/// A limited resolver only used for `/proc` lookups in `ProcfsHandle`.
pub(crate) mod procfs;

/// Maximum number of symlink traversals we will accept.
const MAX_SYMLINK_TRAVERSALS: usize = 128;

/// The backend used for path resolution within a [`Root`] to get a [`Handle`].
///
/// We don't generally recommend specifying this, since libpathrs will
/// automatically detect the best backend for your platform (which is the value
/// returned by `Resolver::default`). However, this can be useful for testing.
///
/// [`Root`]: crate::Root
/// [`Handle`]: crate::Handle
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum ResolverBackend {
    /// Use the native `openat2(2)` backend (requires kernel support).
    KernelOpenat2,
    /// Use the userspace "emulated" backend.
    EmulatedOpath,
    // TODO: Implement a HardcoreEmulated which does pivot_root(2) and all the
    //       rest of it. It'd be useful to compare against and for some
    //       hyper-concerned users.
}

// MSRV(1.80): Use LazyLock.
static DEFAULT_RESOLVER_TYPE: Lazy<ResolverBackend> = Lazy::new(|| {
    if *syscalls::OPENAT2_IS_SUPPORTED {
        ResolverBackend::KernelOpenat2
    } else {
        ResolverBackend::EmulatedOpath
    }
});

impl Default for ResolverBackend {
    fn default() -> Self {
        *DEFAULT_RESOLVER_TYPE
    }
}

impl ResolverBackend {
    /// Checks if the resolver is supported on the current platform.
    #[cfg(test)]
    pub(crate) fn supported(self) -> bool {
        match self {
            ResolverBackend::KernelOpenat2 => *syscalls::OPENAT2_IS_SUPPORTED,
            ResolverBackend::EmulatedOpath => true,
        }
    }
}

/// Resolover backend and its associated flags.
///
/// This is the primary structure used to configure how a given [`Root`] will
/// conduct path resolutions.
///
/// [`Root`]: crate::Root
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Resolver {
    /// Underlying resolution backend used.
    pub(crate) backend: ResolverBackend,
    /// Flags to pass to the resolution backend.
    pub flags: ResolverFlags,
}

/// Only used for internal resolver implementations.
#[derive(Debug)]
pub(crate) enum PartialLookup<H, E = Error> {
    Complete(H),
    Partial {
        handle: H,
        remaining: PathBuf,
        last_error: E,
    },
}

impl<H> AsRef<H> for PartialLookup<H> {
    fn as_ref(&self) -> &H {
        match self {
            Self::Complete(handle) => handle,
            Self::Partial { handle, .. } => handle,
        }
    }
}

impl TryInto<Handle> for PartialLookup<Handle> {
    type Error = Error;

    fn try_into(self) -> Result<Handle, Self::Error> {
        match self {
            Self::Complete(handle) => Ok(handle),
            Self::Partial { last_error, .. } => Err(last_error),
        }
    }
}

impl TryInto<Handle> for PartialLookup<Rc<OwnedFd>> {
    type Error = Error;

    fn try_into(self) -> Result<Handle, Self::Error> {
        PartialLookup::<Handle>::from(self).try_into()
    }
}

impl TryInto<(Handle, Option<PathBuf>)> for PartialLookup<Handle> {
    type Error = Error;

    fn try_into(self) -> Result<(Handle, Option<PathBuf>), Self::Error> {
        match self {
            Self::Complete(handle) => Ok((handle, None)),
            Self::Partial {
                handle,
                remaining,
                last_error,
            } => match last_error.kind() {
                ErrorKind::OsError(Some(libc::ENOENT)) => Ok((handle, Some(remaining))),
                _ => Err(last_error),
            },
        }
    }
}

impl From<PartialLookup<Rc<OwnedFd>>> for PartialLookup<Handle> {
    fn from(result: PartialLookup<Rc<OwnedFd>>) -> Self {
        let (rc, partial) = match result {
            PartialLookup::Complete(rc) => (rc, None),
            PartialLookup::Partial {
                handle,
                remaining,
                last_error,
            } => (handle, Some((remaining, last_error))),
        };

        // We are now sure that there is only a single reference to whatever
        // current points to. There is nowhere else we could've stashed a
        // reference, and we only do Rc::clone for root (which we've dropped).
        let handle = Handle::from_fd(
            // MSRV(1.70): Use Rc::into_inner().
            Rc::try_unwrap(rc)
                .expect("current handle in lookup should only have a single Rc reference"),
        );

        match partial {
            None => Self::Complete(handle),
            Some((remaining, last_error)) => Self::Partial {
                handle,
                remaining,
                last_error,
            },
        }
    }
}

impl Resolver {
    pub(crate) fn open<Fd: AsFd, P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        root: Fd,
        path: P,
        flags: F,
    ) -> Result<File, Error> {
        let flags = flags.into();

        // O_CREAT cannot be emulated by the O_PATH resolver (and in the
        // fallback case the flag gets silently ignored unless you also set
        // O_EXCL) so we need to explicitly return an error if it is provided.
        if flags.intersects(OpenFlags::O_CREAT | OpenFlags::O_EXCL) {
            Err(ErrorImpl::InvalidArgument {
                name: "oflags".into(),
                description: "open flags to one-shot open cannot contain O_CREAT or O_EXCL".into(),
            })?
        }

        match self.backend {
            // For backends without an accelerated one-shot open()
            // implementation, we can just do the lookup+reopen thing in one go.
            // For cffi users, this makes plain "open" operations faster.
            _ => {
                let handle = self.resolve(root, path, flags.contains(OpenFlags::O_NOFOLLOW))?;

                // O_NOFOLLOW makes things a little tricky. Unlike
                // FdExt::reopen, we have to support O_NOFOLLOW|O_PATH of
                // symlinks, but that is easily emulated by returning the handle
                // directly without a reopen.
                if handle.metadata()?.is_symlink() {
                    // If the user also asked for O_DIRECTORY, make sure we
                    // return the right error.
                    if flags.contains(OpenFlags::O_DIRECTORY) {
                        Err(ErrorImpl::OsError {
                            operation: "emulated openat2".into(),
                            source: IOError::from_raw_os_error(libc::ENOTDIR),
                        })?;
                    }

                    // If the user requested O_PATH|O_NOFOLLOW, then the only
                    // option we have is to return the handle we got. Without
                    // O_EMPTYPATH there is no easy way to apply any extra flags
                    // a user might've requested.
                    // TODO: Should we error out if the user asks for extra
                    // flags that don't match the flags for our handles?
                    if flags.contains(OpenFlags::O_PATH) {
                        return Ok(OwnedFd::from(handle).into());
                    }

                    // Otherwise, the user asked for O_NOFOLLOW and we saw a
                    // symlink, so return ELOOP like openat2 would.
                    Err(ErrorImpl::OsError {
                        operation: "emulated openat2".into(),
                        source: IOError::from_raw_os_error(libc::ELOOP),
                    })?;
                }

                handle.reopen(flags)
            }
        }
    }

    #[inline]
    pub(crate) fn resolve<Fd: AsFd, P: AsRef<Path>>(
        &self,
        root: Fd,
        path: P,
        no_follow_trailing: bool,
    ) -> Result<Handle, Error> {
        match self.backend {
            ResolverBackend::KernelOpenat2 => {
                openat2::resolve(root, path, self.flags, no_follow_trailing)
            }
            ResolverBackend::EmulatedOpath => {
                opath::resolve(root, path, self.flags, no_follow_trailing)
            }
        }
    }

    #[inline]
    pub(crate) fn resolve_partial<Fd: AsFd, P: AsRef<Path>>(
        &self,
        root: Fd,
        path: P,
        no_follow_trailing: bool,
    ) -> Result<PartialLookup<Handle>, Error> {
        match self.backend {
            ResolverBackend::KernelOpenat2 => {
                openat2::resolve_partial(root, path.as_ref(), self.flags, no_follow_trailing)
            }
            ResolverBackend::EmulatedOpath => {
                opath::resolve_partial(root, path.as_ref(), self.flags, no_follow_trailing)
                    // Rc<File> -> Handle
                    .map(Into::into)
            }
        }
    }
}

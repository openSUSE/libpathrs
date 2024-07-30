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

#![forbid(unsafe_code)]

use crate::{error::Error, syscalls, Handle};

use std::{fs::File, path::Path};

/// `O_PATH`-based userspace resolver.
pub mod opath;
/// `openat2(2)`-based in-kernel resolver.
pub mod openat2;
/// A limited resolver only used for `/proc` lookups in `ProcfsHandle`.
pub(crate) mod procfs;

/// Maximum number of symlink traversals we will accept.
const MAX_SYMLINK_TRAVERSALS: usize = 128;

bitflags! {
    /// Optional flags to modify the resolution of paths inside a [`Root`].
    ///
    /// [`Root`]: struct.Root.html
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct ResolverFlags: u64 {
        // TODO: We should probably have our own bits...
        const NO_SYMLINKS = libc::RESOLVE_NO_SYMLINKS;
    }
}

/// The backend used for path resolution within a [`Root`] to get a [`Handle`].
///
/// We don't generally recommend specifying this, since libpathrs will
/// automatically detect the best backend for your platform (which is the value
/// returned by `Resolver::default`). However, this can be useful for testing.
///
/// [`Root`]: struct.Root.html
/// [`Handle`]: struct.Handle.html
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResolverBackend {
    /// Use the native `openat2(2)` backend (requires kernel support).
    KernelOpenat2,
    /// Use the userspace "emulated" backend.
    EmulatedOpath,
    // TODO: Implement a HardcoreEmulated which does pivot_root(2) and all the
    //       rest of it. It'd be useful to compare against and for some
    //       hyper-concerned users.
}

lazy_static! {
    static ref DEFAULT_RESOLVER_TYPE: ResolverBackend = if *syscalls::OPENAT2_IS_SUPPORTED {
        ResolverBackend::KernelOpenat2
    } else {
        ResolverBackend::EmulatedOpath
    };
}

impl Default for ResolverBackend {
    fn default() -> Self {
        *DEFAULT_RESOLVER_TYPE
    }
}

impl ResolverBackend {
    /// Checks if the resolver is supported on the current platform.
    pub fn supported(self) -> bool {
        match self {
            ResolverBackend::KernelOpenat2 => *syscalls::OPENAT2_IS_SUPPORTED,
            ResolverBackend::EmulatedOpath => true,
        }
    }
}

/// Resolover backend and its associated flags.
///
/// This is the primary structure used to configure how a given [`Root`] will
/// conduct path resolutions. It's not recommended to change the
/// [`ResolverBackend`] but it wouldn't hurt.
///
/// [`Root`]: struct.Root.html
/// [`ResolverBackend`]: enum.ResolverBackend.html
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Resolver {
    /// Underlying resolution backend used.
    pub backend: ResolverBackend,
    /// Flags to pass to the resolution backend.
    pub flags: ResolverFlags,
}

impl Resolver {
    /// Internal dispatcher to the relevant backend.
    #[inline]
    pub(crate) fn resolve<P: AsRef<Path>>(
        &self,
        root: &File,
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
}

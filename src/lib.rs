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

//! libpathrs provides a series of primitives for Linux programs to safely
//! handle path operations inside an untrusted directory tree.
//!
//! The idea is that a [`Root`] handle is like a handle for resolution inside a
//! [`chroot(2)`], with [`Handle`] being an `O_PATH` descriptor which you can
//! "upgrade" to a proper [`File`]. However this library acts far more
//! efficiently than spawning a new process and doing a full [`chroot(2)`] for
//! every operation.
//!
//! In order to ensure the maximum possible number of people can make us of this
//! library to increase the overall security of Linux tooling, it is written in
//! Rust (to be memory-safe) and produces C dylibs for usage with any language
//! that supports C-based FFI.
//!
//! # Assumptions
//!
//! This library assumes that the kernel supports all of the needed features for
//! at least one libpathrs backend. At time of writing, those are:
//!
//! * A working `/proc` mount, such that `/proc/self/fd/` operates correctly.
//!   libpathrs will explicitly verify that the `/proc` mount is actually a
//!   bone-fide `procfs` instance (to avoid potential trickery) and abort if
//!   `/proc` is not actually `procfs`.
//! * Native Backend:
//!   - `openat2` support.
//!
//! # Examples
//!
//! The recommended usage of libpathrs looks something like this:
//!
//! ```
//! # extern crate libc;
//! # use pathrs::{error::Error, Root, OpenFlags};
//! # fn main() -> Result<(), Error> {
//! let (root_path, unsafe_path) = ("/path/to/root", "/etc/passwd");
//! # let root_path = "/";
//! // Get a root handle for resolution.
//! let root = Root::open(root_path)?;
//! // Resolve the path.
//! let handle = root.resolve(unsafe_path)?;
//! // Upgrade the handle to a full std::fs::File.
//! let file = handle.reopen(OpenFlags::O_RDONLY)?;
//!
//! // Or, in one line:
//! let file = root.resolve(unsafe_path)?
//!                .reopen(OpenFlags::O_RDONLY)?;
//! # Ok(())
//! # }
//! ```
//!
//! The corresponding C example would be:
//!
//! ```c
//! #include <pathrs.h>
//!
//! int get_my_fd(void)
//! {
//!     const char *root_path = "/path/to/root";
//!     const char *unsafe_path = "/etc/passwd";
//!
//!     int liberr = 0;
//!     int root = -EBADF,
//!         handle = -EBADF,
//!         fd = -EBADF;
//!
//!     root = pathrs_root_open(root_path);
//!     if (root < 0) {
//!         liberr = root;
//!         goto err;
//!     }
//!
//!     handle = pathrs_resolve(root, unsafe_path);
//!     if (handle < 0) {
//!         liberr = handle;
//!         goto err;
//!     }
//!
//!     fd = pathrs_reopen(handle, O_RDONLY);
//!     if (fd < 0) {
//!         liberr = fd;
//!         goto err;
//!     }
//!
//! err:
//!     if (liberr < 0) {
//!         pathrs_error_t *error = pathrs_errorinfo(liberr);
//!         fprintf(stderr, "Uh-oh: %s (errno=%d)\n", error->description, error->saved_errno);
//!         pathrs_errorinfo_free(error);
//!     }
//!     close(root);
//!     close(handle);
//!     return fd;
//! }
//! ```
//!
//! [`Root`]: struct.Root.html
//! [`Handle`]: trait.Handle.html
//! [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
//! [`chroot(2)`]: http://man7.org/linux/man-pages/man2/chroot.2.html

// libpathrs only supports Linux at the moment.
#![cfg(target_os = "linux")]
#![deny(rustdoc::broken_intra_doc_links)]
// We use this the coverage_attribute when doing coverage runs.
// <https://github.com/rust-lang/rust/issues/84605>
#![cfg_attr(coverage, feature(coverage_attribute))]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate snafu;

// `OpenFlags`
pub mod flags;
#[doc(inline)]
pub use flags::OpenFlags;

// `Handle` implementation.
mod handle;
#[doc(inline)]
pub use handle::*;

// `Root` implementation.
mod root;
#[doc(inline)]
pub use root::*;

// `Error` definitions.
pub mod error;

// Backend resolver implementations.
mod resolvers;
#[doc(inline)]
pub use resolvers::{Resolver, ResolverBackend, ResolverFlags};

// C API.
mod capi;

// Internally used helpers.
mod syscalls;
mod utils;

// Library tetss.
#[cfg(test)]
mod tests;

/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

//! libpathrs provides a series of primitives for Linux programs to safely
//! handle path operations inside an untrusted directory tree.
//!
//! The idea is that a [`Root`] handle is like a handle for resolution inside a
//! [`chroot(2)`], with [`Handle`] being an `O_PATH` descriptor which you can
//! "upgrade" to a proper [`File`]. However this library acts far more
//! efficiently than spawning a new process and doing a full [`chroot(2)`] for
//! every operation.
//!
//! # Example
//!
//! The recommended usage of libpathrs looks something like this:
//!
//! ```
//! # use pathrs::{error::Error, flags::OpenFlags, Root};
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
//! # C API
//!
//! In order to ensure the maximum possible number of people can make us of this
//! library to increase the overall security of Linux tooling, it is written in
//! Rust (to be memory-safe) and produces C dylibs for usage with any language
//! that supports C-based FFI. To further help expand how many folks can use
//! libpathrs, libpathrs's MSRV is Rust 1.63, to allow us to build on more
//! stable operating systems (such as Debian Buster, which provides Rust 1.63).
//!
//! A C example corresponding to the above Rust code would look like:
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
//!     root = pathrs_open_root(root_path);
//!     if (root < 0) {
//!         liberr = root;
//!         goto err;
//!     }
//!
//!     handle = pathrs_inroot_resolve(root, unsafe_path);
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
//! # Kernel Support
//!
//! libpathrs is designed to only work with Linux, as it uses several Linux-only
//! APIs.
//!
//! libpathrs was designed alongside [`openat2(2)`] (available since Linux 5.6)
//! and dynamically tries to use the latest kernel features to provide the
//! maximum possible protection against racing attackers. However, it also
//! provides support for older kernel versions (in theory up to Linux
//! 2.6.39 but we do not currently test this) by emulating newer kernel features
//! in userspace.
//!
//! However, we strongly recommend you use at least Linux 5.8 to get a
//! reasonable amount of protection against various attacks, and ideally at
//! least Linux 6.8 to make use of all of the protections we have implemented.
//! See the following table for what kernel features we optionally support and
//! what they are used for.
//!
//! | Feature               | Minimum Kernel Version  | Description | Fallback |
//! | --------------------- | ----------------------- | ----------- | -------- |
//! | `/proc/thread-self`   | Linux 3.17 (2014-10-05) | Used when operating on the current thread's `/proc` directory for use with `PATHRS_PROC_THREAD_SELF`. | `/proc/self/task/$tid` is used, but this might not be available in some edge cases so `/proc/self` is used as a final fallback. |
//! | [`open_tree(2)`]      | Linux 4.18 (2018-08-12) | Used to create a private procfs handle when operating on `/proc` (this is a copy of the host `/proc` -- in most cases this will also strip any overmounts). Requires `CAP_SYS_ADMIN` privileges. | Open a regular handle to `/proc`. This can lead to certain race attacks if the attacker can dynamically create mounts. |
//! | [`fsopen(2)`]         | Linux 5.1 (2019-05-05)  | Used to create a private procfs handle when operating on `/proc` (with a completely fresh copy of `/proc` -- in some cases this operation will fail if there are locked overmounts on top of `/proc`). Requires `CAP_SYS_ADMIN` privileges. | Try to use [`open_tree(2)`] instead -- in the case of errors due to locked overmounts, [`open_tree(2)`] will be used to create a recursive copy that preserves the overmounts. This means that an attacker would not be able to actively change the mounts on top of `/proc` but there might be some overmounts that libpathrs will detect (and reject). |
//! | [`openat2(2)`]        | Linux 5.6 (2020-03-29)  | In-kernel restrictions of path lookup. This is used extensively by `libpathrs` to safely do path lookups. | Userspace emulated path lookups. |
//! | `STATX_MNT_ID`        | Linux 5.8 (2020-08-02)  | Used to verify whether there are bind-mounts on top of `/proc` that could result in insecure operations. | There is **no fallback**. Not using this protection can lead to fairly trivial attacks if an attacker can configure your mount table. |
//! | `STATX_MNT_ID_UNIQUE` | Linux 6.8 (2024-03-10)  | Used for the same reason as `STATX_MNT_ID`, but allows us to protect against mount ID recycling. This is effectively a safer version of `STATX_MNT_ID`. | `STATX_MNT_ID` is used (see the `STATX_MNT_ID` fallback if it's not available either). |
//!
//! For more information about the work behind `openat2(2)`, you can read the
//! following LWN articles (note that the merged version of `openat2(2)` is
//! different to the version described by LWN):
//!
//!  * [New AT_ flags for restricting pathname lookup][lwn-atflags]
//!  * [Restricting path name lookup with openat2()][lwn-openat2]
//!
//! [`openat2(2)`]: https://www.man7.org/linux/man-pages/man2/openat2.2.html
//! [lwn-atflags]: https://lwn.net/Articles/767547/
//! [lwn-openat2]: https://lwn.net/Articles/796868/
//! [`File`]: std::fs::File
//! [`chroot(2)`]: http://man7.org/linux/man-pages/man2/chroot.2.html
//! [`open_tree(2)`]: https://github.com/brauner/man-pages-md/blob/main/open_tree.md
//! [`fsopen(2)`]: https://github.com/brauner/man-pages-md/blob/main/fsopen.md

// libpathrs only supports Linux at the moment.
#![cfg(target_os = "linux")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(missing_debug_implementations)]
// We use this the coverage_attribute when doing coverage runs.
// <https://github.com/rust-lang/rust/issues/84605>
#![cfg_attr(coverage, feature(coverage_attribute))]

// `Handle` implementation.
mod handle;
#[doc(inline)]
pub use handle::*;

// `Root` implementation.
mod root;
#[doc(inline)]
pub use root::*;

pub mod error;
pub mod flags;
pub mod procfs;

// Resolver backend implementations.
mod resolvers;

// C API.
#[cfg(feature = "capi")]
mod capi;

// Internally used helpers.
mod syscalls;
mod utils;

// Library tests.
#[cfg(test)]
mod tests;

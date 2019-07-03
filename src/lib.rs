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
//! * Native Backend:
//!   - `openat2` support.
//!
//! # Examples
//!
//! The recommended usage of libpathrs looks something like this:
//!
//! ```
//! # use std::error::Error;
//! use std::fs::OpenOptions;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), FailureError> {
//! // Get a root handle for resolution.
//! let root = Root::open("/path/to/root")?;
//! // Resolve the path.
//! let handle = root.resolve("/etc/passwd")?;
//! // Upgrade the handle to a full std::fs::File.
//! let file = handle.reopen(OpenOptions::new().read(true))?;
//!
//! // Or, in one line:
//! let file = root.resolve("/etc/passwd")?
//!                .reopen(OpenOptions::new().read(true))?;
//! # Ok(())
//! # }
//! ```
//!
//! The corresponding C example would be:
//!
//! ```c
//! int get_my_fd(void)
//! {
//!     int fd = -1;
//!     pathrs_root_t *root = NULL;
//!     pathrs_handle_t *handle = NULL;
//!     pathrs_error_t error = {};
//!
//!     root = pathrs_open("/path/to/root");
//!     if (!root)
//!         goto err;
//!
//!     handle = pathrs_inroot_resolve(root, "/etc/passwd");
//!     if (!handle)
//!         goto err;
//!
//!     fd = pathrs_reopen(handle, O_RDONLY);
//!     if (fd < 0)
//!         goto err;
//!
//!     goto out;
//!
//! err:
//!     if (pathrs_error(&error) <= 0)
//!         abort();
//!     fprintf(stderr, "got error (errno=%d): %s\n", error.errno, error.description);
//!
//! out:
//!     pathrs_hfree(handle);
//!     pathrs_rfree(root);
//!     return fd;
//! }
//! ```
//!
//! [`Root`]: struct.Root.html
//! [`Handle`]: trait.Handle.html
//! [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
//! [`chroot(2)`]: http://man7.org/linux/man-pages/man2/chroot.2.html

#[macro_use]
extern crate lazy_static;
extern crate errno;
#[macro_use]
extern crate failure;
extern crate libc;

mod handle;
pub use handle::*;

mod root;
pub use root::*;

mod ffi;
mod kernel;
mod user;
mod utils;

use std::io::Error as IOError;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

/// The underlying [`cause`] of the [`failure::Error`] type returned by
/// libpathrs.
///
/// [`cause`]: https://docs.rs/failure/*/failure/struct.Error.html#method.cause
/// [`failure::Error`]: https://docs.rs/failure/*/failure/struct.Error.html
#[derive(Fail, Debug)]
pub enum Error {
    /// The requested feature is not yet implemented.
    #[fail(display = "feature not yet implemented: {}", _0)]
    NotImplemented(&'static str),

    /// One of the provided arguments in invalid. The returned tuple is
    /// (argument name, description of error).
    #[fail(display = "invalid {} argument: {}", _0, _1)]
    InvalidArgument(&'static str, &'static str),

    /// Returned whenever libpathrs has detected some form of safety requirement
    /// violation. This might be an attempted breakout by an attacker or even a
    /// bug internal to libpathrs.
    #[fail(display = "violation of safety requirement: {}", _0)]
    SafetyViolation(&'static str),

    /// An operating system error during a raw-syscall execution.
    #[fail(
        display = "syscall error {}({}=>{:?}, {:?})",
        syscall, fd, fdpath, path
    )]
    OsPathError {
        syscall: &'static str,
        // XXX: Ideally this would be fd: (RawFd, PathBuf) but #[fail(display)]
        //      doesn't like referencing tuple elements in the display field.
        //      It's apparently a compiler limitation.
        fd: RawFd,
        fdpath: PathBuf,
        path: PathBuf,
        #[fail(cause)]
        cause: IOError,
    },
}

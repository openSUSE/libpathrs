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
//! # use crate::Error;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Error> {
//! // Get a root handle for resolution.
//! let root = Root::open("/path/to/root")?;
//! // Resolve the path.
//! let handle = root.resolve("/etc/passwd")?;
//! // Upgrade the handle to a full std::fs::File.
//! let file = handle.reopen(libc::O_RDONLY)?;
//!
//! // Or, in one line:
//! let file = root.resolve("/etc/passwd")?
//!                .reopen(libc::O_RDONLY)?;
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
//!     int fd = -1;
//!     pathrs_root_t *root = NULL;
//!     pathrs_handle_t *handle = NULL;
//!     pathrs_error_t *error = NULL;
//!
//!     root = pathrs_open("/path/to/root");
//!     if (!root)
//!         abort(); /* will never happen */
//!     error = pathrs_error(PATHRS_ROOT, root);
//!     if (error)
//!         goto err;
//!
//!     handle = pathrs_resolve(root, "/etc/passwd");
//!     if (!handle) {
//!         error = pathrs_error(PATHRS_ROOT, root);
//!         goto err;
//!     }
//!
//!     fd = pathrs_reopen(handle, O_RDONLY);
//!     if (fd < 0) {
//!         error = pathrs_error(PATHRS_HANDLE, handle);
//!         goto err;
//!     }
//!
//!     goto out;
//!
//! err:
//!     fprintf(stderr, "Uh-oh: %s (errno=%d)\n", error->description, error->saved_errno);
//!     /* Optionally, print out the backtrace... */
//!
//! out:
//!     pathrs_free(PATHRS_ROOT, root);
//!     pathrs_free(PATHRS_HANDLE, handle);
//!     pathrs_free(PATHRS_ERROR, error);
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

extern crate errno;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate snafu;

mod handle;
pub use handle::*;

mod root;
pub use root::*;

mod syscalls;
pub use syscalls::Error as SyscallError;

// C-friendly API.
mod ffi;
// Backends.
mod kernel;
mod user;
// Internally used helpers.
mod utils;

// XXX: This is a workaround until
//      https://github.com/shepmaster/snafu/issues/188 is resolved.
pub use errors::Error;
mod errors {
    use snafu::{Backtrace, ResultExt};
    use std::error::Error as StdError;
    use std::io::Error as IOError;

    /// The primary error type returned by libpathrs. All public interfaces of
    /// libpathrs will return this error in `Result`s.
    ///
    /// # Caveats
    /// Until [`Error::chain`] is stabilised, it will be necessary for callers
    /// to manually implement their own version of this feature.
    ///
    /// [`Error::chain`]: https://doc.rust-lang.org/nightly/std/error/trait.Error.html#method.chain
    #[derive(Snafu, Debug)]
    #[snafu(visibility = "pub(crate)")]
    pub enum Error {
        /// The requested feature is not yet implemented.
        #[snafu(display("feature '{}' not implemented", feature))]
        NotImplemented {
            /// Feature which is not implemented.
            feature: &'static str,
            backtrace: Option<Backtrace>,
        },

        /// The requested feature is not supported by this kernel.
        #[snafu(display("feature '{}' not supported on this kernel", feature))]
        NotSupported {
            /// Feature which is not supported.
            feature: &'static str,
            backtrace: Option<Backtrace>,
        },

        /// One of the provided arguments in invalid.
        #[snafu(display("invalid {} argument: {}", name, description))]
        InvalidArgument {
            /// Name of the invalid argument.
            name: &'static str,
            /// Description of what makes the argument invalid.
            description: &'static str,
            backtrace: Option<Backtrace>,
        },

        /// libpathrs has detected some form of safety requirement violation. This
        /// might be an attempted breakout by an attacker or even a bug internal to
        /// libpathrs.
        #[snafu(display("violation of safety requirement: {}", description))]
        SafetyViolation {
            /// Description of safety requirement which was violated.
            description: &'static str,
            backtrace: Option<Backtrace>,
        },

        /// The requested libpathrs operation directly resulted in an operating
        /// system error. This should be contrasted with [`InternalOsError`] (which
        /// is an error triggered internally by libpathrs while servicing the user
        /// request).
        ///
        /// [`InternalOsError`]: enum.Error.html#variant.InternalOsError
        #[snafu(display("{} failed", operation))]
        OsError {
            operation: &'static str,
            source: IOError,
            backtrace: Option<Backtrace>,
        },

        /// The requested libpathrs operation directly resulted in an operating
        /// system error. This should be contrasted with [`InternalOsError`] (which
        /// is an error triggered internally by libpathrs while servicing the user
        /// request).
        ///
        /// [`InternalOsError`]: enum.Error.html#variant.InternalOsError
        #[snafu(display("{} failed", operation))]
        RawOsError {
            operation: &'static str,
            #[snafu(backtrace)]
            source: super::SyscallError,
        },

        /// Wrapped represents an Error which has some simple string-wrapping
        /// information.
        #[snafu(display("{}", context))]
        Wrapped {
            context: String,
            #[snafu(backtrace)]
            #[snafu(source(from(Error, Box::new)))]
            source: Box<Error>,
        },
    }

    // Private trait necessary to work around the "orphan trait" restriction.
    pub(crate) trait ErrorExt {
        /// Wrap a `Result<..., Error>` with an additional context string.
        fn wrap<S: Into<String>>(self, context: S) -> Self;
    }

    impl<T> ErrorExt for Result<T, Error> {
        fn wrap<S: Into<String>>(self, context: S) -> Self {
            self.context(Wrapped {
                context: context.into(),
            })
        }
    }

    /// A backport of the nightly-only [`Chain`]. This method
    /// will be removed as soon as that is stabilised.
    ///
    /// [`Chain`]: https://doc.rust-lang.org/nightly/std/error/struct.Chain.html
    // XXX: https://github.com/rust-lang/rust/issues/58520
    pub(crate) struct Chain<'a> {
        current: Option<&'a (dyn StdError + 'static)>,
    }

    impl<'a> Iterator for Chain<'a> {
        type Item = &'a (dyn StdError + 'static);

        fn next(&mut self) -> Option<Self::Item> {
            let current = self.current;
            self.current = self.current.and_then(StdError::source);
            current
        }
    }

    impl Error {
        /// A backport of the nightly-only [`Error::chain`]. This method
        /// will be removed as soon as that is stabilised.
        ///
        /// [`Error::chain`]: https://doc.rust-lang.org/nightly/std/error/trait.Error.html#method.chain
        // XXX: https://github.com/rust-lang/rust/issues/58520
        pub(crate) fn iter_chain_hotfix(&self) -> Chain {
            Chain {
                current: Some(self),
            }
        }

        /// Shorthand for `self.iter_chain_hotfix().last()`.
        pub(crate) fn root_cause(&self) -> &(dyn StdError + 'static) {
            self.iter_chain_hotfix()
                .last()
                .expect("Error::iter_chain_hotfix() should have at least one result")
        }
    }
}

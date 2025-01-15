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

#![forbid(unsafe_code)]

//! Error types for libpathrs.

// NOTE: This module is mostly a workaround until several issues have been
//       resolved:
//
//  * `std::error::Error::chain` is stabilised.
//  * I figure out a nice way to implement GlobalBacktrace...

use crate::{resolvers::opath::SymlinkStackError, syscalls::Error as SyscallError};

use std::{borrow::Cow, io::Error as IOError};

// TODO: Add a backtrace to Error. We would just need to add an automatic
//       Backtrace::capture() in From. But it's not clear whether we want to
//       export the crate types here without std::backtrace::Backtrace.
// MSRV(1.65): Use std::backtrace::Backtrace.

/// Opaque error type for libpathrs.
///
/// If you wish to do non-trivial error handling with libpathrs errors, use
/// [`Error::kind`] to get an [`ErrorKind`] you can handle programmatically.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] Box<ErrorImpl>);

impl<E: Into<ErrorImpl>> From<E> for Error {
    // TODO: Is there a way to make this not be exported at all?
    #[doc(hidden)]
    fn from(err: E) -> Self {
        Self(Box::new(err.into()))
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.0.kind()
    }

    pub(crate) fn is_safety_violation(&self) -> bool {
        self.0.is_safety_violation()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum ErrorImpl {
    #[allow(dead_code)]
    #[error("feature {feature} is not implemented")]
    NotImplemented { feature: Cow<'static, str> },

    #[error("feature {feature} not supported on this kernel")]
    NotSupported { feature: Cow<'static, str> },

    #[error("invalid {name} argument: {description}")]
    InvalidArgument {
        name: Cow<'static, str>,
        description: Cow<'static, str>,
    },

    #[error("violation of safety requirement: {description}")]
    SafetyViolation { description: Cow<'static, str> },

    #[error("broken symlink stack during iteration: {description}")]
    BadSymlinkStackError {
        description: Cow<'static, str>,
        source: SymlinkStackError,
    },

    #[error("{operation} failed")]
    OsError {
        operation: Cow<'static, str>,
        source: IOError,
    },

    #[error("{operation} failed")]
    RawOsError {
        operation: Cow<'static, str>,
        source: SyscallError,
    },

    #[error("integer parsing failed")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("{context}")]
    Wrapped {
        context: Cow<'static, str>,
        source: Box<ErrorImpl>,
    },
}

/// Underlying error class for libpathrs errors.
///
/// This is similar in concept to [`std::io::ErrorKind`]. Note that the
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The requested feature is not implemented in libpathrs.
    NotImplemented,
    /// The requested feature is not supported by the system.
    NotSupported,
    /// The provided arguments to libpathrs were invalid.
    InvalidArgument,
    /// libpaths encountered a state where the safety of the operation could not
    /// be guaranteeed. This is usually the result of an attack by a malicious
    /// program.
    SafetyViolation,
    /// Some internal error occurred. For more information, see the string
    /// description of the original [`Error`].
    InternalError,
    /// The underlying error came from a system call. The provided
    /// [`std::io::RawOsError`] is the numerical value of the `errno` number, if
    /// available.
    // TODO: We might want to use Option<std::io::ErrorKind>?
    OsError(Option<i32>),
}

impl ErrorImpl {
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::NotImplemented { .. } => ErrorKind::NotImplemented,
            Self::NotSupported { .. } => ErrorKind::NotSupported,
            Self::InvalidArgument { .. } => ErrorKind::InvalidArgument,
            Self::SafetyViolation { .. } => ErrorKind::SafetyViolation,
            // Any syscall-related errors get mapped to an OsError, since the
            // distinction doesn't matter to users checking error values.
            Self::OsError { source, .. } => ErrorKind::OsError(source.raw_os_error()),
            Self::RawOsError { source, .. } => {
                ErrorKind::OsError(source.root_cause().raw_os_error())
            }
            // These errors are internal error types that we don't want to
            // expose outside of the crate. All that matters to users is that
            // there was some internal error.
            Self::BadSymlinkStackError { .. } | Self::ParseIntError(_) => ErrorKind::InternalError,
            Self::Wrapped { source, .. } => source.kind(),
        }
    }

    pub(crate) fn is_safety_violation(&self) -> bool {
        self.kind().is_safety_violation()
    }
}

impl ErrorKind {
    /// Return a C-like errno for the [`ErrorKind`].
    ///
    /// Aside from fetching the errno represented by standard
    /// [`ErrorKind::OsError`] errors, pure-Rust errors are also mapped to C
    /// errno values where appropriate.
    pub(crate) fn errno(&self) -> Option<i32> {
        match self {
            ErrorKind::NotImplemented => Some(libc::ENOSYS),
            ErrorKind::InvalidArgument => Some(libc::EINVAL),
            ErrorKind::SafetyViolation => Some(libc::EXDEV),
            ErrorKind::OsError(errno) => *errno,
            _ => None,
        }
    }

    pub(crate) fn is_safety_violation(&self) -> bool {
        self.errno() == Self::SafetyViolation.errno()
    }
}

// Private trait necessary to work around the "orphan trait" restriction.
pub(crate) trait ErrorExt: Sized {
    /// Wrap a `Result<..., Error>` with an additional context string.
    fn wrap<S: Into<String>>(self, context: S) -> Self {
        self.with_wrap(|| context.into())
    }

    /// Wrap a `Result<..., Error>` with an additional context string created by
    /// a closure.
    fn with_wrap<F>(self, context_fn: F) -> Self
    where
        F: FnOnce() -> String;
}

impl ErrorExt for ErrorImpl {
    fn with_wrap<F>(self, context_fn: F) -> Self
    where
        F: FnOnce() -> String,
    {
        Self::Wrapped {
            context: context_fn().into(),
            source: self.into(),
        }
    }
}

impl ErrorExt for Error {
    fn with_wrap<F>(self, context_fn: F) -> Self
    where
        F: FnOnce() -> String,
    {
        self.0.with_wrap(context_fn).into()
    }
}

impl<T, E: ErrorExt> ErrorExt for Result<T, E> {
    fn with_wrap<F>(self, context_fn: F) -> Self
    where
        F: FnOnce() -> String,
    {
        self.map_err(|err| err.with_wrap(context_fn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn error_kind_errno() {
        assert_eq!(
            ErrorKind::InvalidArgument.errno(),
            Some(libc::EINVAL),
            "ErrorKind::InvalidArgument is equivalent to EINVAL"
        );
        assert_eq!(
            ErrorKind::NotImplemented.errno(),
            Some(libc::ENOSYS),
            "ErrorKind::NotImplemented is equivalent to ENOSYS"
        );
        assert_eq!(
            ErrorKind::SafetyViolation.errno(),
            Some(libc::EXDEV),
            "ErrorKind::SafetyViolation is equivalent to EXDEV"
        );
        assert_eq!(
            ErrorKind::OsError(Some(libc::ENOANO)).errno(),
            Some(libc::ENOANO),
            "ErrorKind::OsError(...)::errno() returns the inner errno"
        );
    }
}

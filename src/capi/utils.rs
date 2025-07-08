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

use crate::error::{Error, ErrorImpl};

use std::{
    cmp,
    ffi::{CStr, CString, OsStr},
    marker::PhantomData,
    os::unix::{
        ffi::OsStrExt,
        io::{AsRawFd, BorrowedFd, RawFd},
    },
    path::Path,
    ptr,
};

use libc::{c_char, c_int, size_t};

/// Equivalent to [`BorrowedFd`], except that there are no restrictions on what
/// value the inner [`RawFd`] can take. This is necessary because C callers
/// could reasonably pass `-1` as a file descriptor value and we need to verify
/// that the value is valid to avoid UB.
///
/// This type is FFI-safe and is intended for use in `extern "C" fn` signatures.
/// While [`BorrowedFd`] (and `Option<BorrowedFd>`) are technically FFI-safe,
/// apparently using them in `extern "C" fn` signatures directly is not
/// recommended for the above reason.
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct CBorrowedFd<'fd> {
    inner: RawFd,
    _phantom: PhantomData<BorrowedFd<'fd>>,
}

impl<'fd> CBorrowedFd<'fd> {
    /// Take a [`CBorrowedFd`] from C FFI and convert it to a proper
    /// [`BorrowedFd`] after making sure that it has a valid value (ie. is not
    /// negative).
    pub(crate) fn try_as_borrowed_fd(&self) -> Result<BorrowedFd<'fd>, Error> {
        // TODO: We might want to support AT_FDCWD in the future. The
        //       openat2 resolver handles it correctly, but the O_PATH
        //       resolver and try_clone() probably need some work.
        // MSRV(1.66): Use match ..0?
        if self.inner.is_negative() {
            Err(ErrorImpl::InvalidArgument {
                // TODO: Should this error be EBADF?
                name: "fd".into(),
                description: "passed file descriptors must not be negative".into(),
            }
            .into())
        } else {
            // SAFETY: The C caller guarantees that the file descriptor is valid for
            //         the lifetime of CBorrowedFd (which is the same lifetime as
            //         BorrowedFd). We verify that the file descriptor is not
            //         negative, so it is definitely valid.
            Ok(unsafe { BorrowedFd::borrow_raw(self.inner) })
        }
    }
}

impl<'fd> From<BorrowedFd<'fd>> for CBorrowedFd<'fd> {
    fn from(fd: BorrowedFd<'_>) -> CBorrowedFd<'_> {
        CBorrowedFd {
            inner: fd.as_raw_fd(),
            _phantom: PhantomData,
        }
    }
}

// TODO: An AsFd impl would be even nicer but I suspect the lifetimes can't be
//       expressed.

pub(crate) unsafe fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, Error> {
    if path.is_null() {
        Err(ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "cannot be NULL".into(),
        })?
    }
    // SAFETY: C caller guarantees that the path is a valid C-style string.
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    Ok(OsStr::from_bytes(bytes).as_ref())
}

pub(crate) unsafe fn copy_path_into_buffer(
    path: impl AsRef<Path>,
    buf: *mut c_char,
    bufsize: size_t,
) -> Result<c_int, Error> {
    let path = CString::new(path.as_ref().as_os_str().as_bytes())
        .expect("link from readlink should not contain any nulls");
    // MSRV(1.79): Switch to .count_bytes().
    let path_len = path.to_bytes().len();

    // If the linkbuf is null, we just return the number of bytes we
    // would've written.
    if !buf.is_null() && bufsize > 0 {
        // SAFETY: The C caller guarantees that buf is safe to write to
        // up to bufsize bytes.
        unsafe {
            let to_copy = cmp::min(path_len, bufsize);
            ptr::copy_nonoverlapping(path.as_ptr(), buf, to_copy);
        }
    }
    Ok(path_len as c_int)
}

pub(crate) trait Leakable: Sized {
    /// Leak a structure such that it can be passed through C-FFI.
    fn leak(self) -> &'static mut Self {
        Box::leak(Box::new(self))
    }

    /// Given a structure leaked through Leakable::leak, un-leak it.
    ///
    /// SAFETY: Callers must be sure to only ever call this once on a given
    /// pointer (otherwise memory corruption will occur).
    unsafe fn unleak(&'static mut self) -> Self {
        // SAFETY: Box::from_raw is safe because the caller guarantees that
        // the pointer we get is the same one we gave them, and it will only
        // ever be called once with the same pointer.
        *unsafe { Box::from_raw(self as *mut Self) }
    }

    /// Shorthand for `std::mem::drop(self.unleak())`.
    ///
    /// SAFETY: Same unsafety issue as `self.unleak()`.
    unsafe fn free(&'static mut self) {
        // SAFETY: Caller guarantees this is safe to do.
        let _ = unsafe { self.unleak() };
        // drop Self
    }
}

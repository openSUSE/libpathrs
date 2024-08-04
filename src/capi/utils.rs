/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
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

use crate::error::{self, Error};

use std::{
    cmp,
    ffi::{CStr, CString, OsStr},
    io::Error as IOError,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
};

use libc::{c_char, c_int, size_t};

pub(crate) fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, Error> {
    ensure!(
        !path.is_null(),
        error::InvalidArgumentSnafu {
            name: "path",
            description: "cannot be NULL",
        }
    );
    // SAFETY: C caller guarantees that the path is a valid C-style string.
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    Ok(OsStr::from_bytes(bytes).as_ref())
}

pub(crate) fn copy_path_into_buffer<P: AsRef<Path>>(
    path: P,
    buf: *mut c_char,
    bufsize: size_t,
) -> Result<c_int, Error> {
    let path = CString::new(path.as_ref().as_os_str().as_bytes())
        .expect("link from readlink should not contain any nulls");

    // If the linkbuf is null, we just return the number of bytes we
    // would've written.
    if !buf.is_null() && bufsize > 0 {
        let to_copy = cmp::min(path.count_bytes(), bufsize);
        // SAFETY: The C caller guarantees that buf is safe to write to
        // up to bufsize bytes.
        unsafe {
            ptr::copy_nonoverlapping(path.as_ptr(), buf, to_copy);
        }
    }

    Ok(path.count_bytes() as c_int)
}

pub(crate) trait Leakable {
    /// Leak a structure such that it can be passed through C-FFI.
    fn leak(self) -> &'static mut Self;

    /// Given a structure leaked through Leakable::leak, un-leak it.
    ///
    /// SAFETY: Callers must be sure to only ever call this once on a given
    /// pointer (otherwise memory corruption will occur).
    unsafe fn unleak(&'static mut self) -> Self;

    /// Shorthand for `std::mem::drop(self.unleak())`.
    ///
    /// SAFETY: Same unsafety issue as `self.unleak()`.
    unsafe fn free(&'static mut self);
}

/// A macro to implement the trivial methods of Leakable -- due to a restriction
/// of the Rust compiler (you cannot have default trait methods that use Self
/// directly, because the size of Self is not known by the trait).
///
/// ```ignore
/// leakable!{ impl Leakable for CError; }
/// leakable!{ impl<T> Leakable for CVec<T>; }
/// ```
macro_rules! leakable {
    // Inner implementation.
    (...) => {
        fn leak(self) -> &'static mut Self {
            Box::leak(Box::new(self))
        }

        unsafe fn unleak(&'static mut self) -> Self {
            // SAFETY: Box::from_raw is safe because the caller guarantees that
            // the pointer we get is the same one we gave them, and it will only
            // ever be called once with the same pointer.
            *unsafe { Box::from_raw(self as *mut Self) }
        }

        unsafe fn free(&'static mut self) {
            // SAFETY: Caller guarantees this is safe to do.
            let _ = unsafe { self.unleak() };
            // drop Self
        }
    };

    (impl Leakable for $type:ty ;) => {
        impl Leakable for $type {
            leakable!(...);
        }
    };

    (impl<$($generics:tt),+> Leakable for $type:ty ;) => {
        impl<$($generics),+> Leakable for $type {
            leakable!(...);
        }
    };
}

/// Attempts to represent a Rust Error type in C. This structure must be freed
/// using pathrs_errorinfo_free().
// NOTE: This API is exposed to library users in a read-only manner with memory
//       management done by libpathrs -- so you may only ever append to it.
#[repr(align(8), C)]
pub struct CError {
    /// Raw errno(3) value of the underlying error (or 0 if the source of the
    /// error was not due to a syscall error).
    // We can't call this field "errno" because glibc defines errno(3) as a
    // macro, causing all sorts of problems if you have a struct with an "errno"
    // field. Best to avoid those headaches.
    pub saved_errno: u64,

    /// Textual description of the error.
    pub description: *const c_char,
}

leakable! {
    impl Leakable for CError;
}

impl From<&Error> for CError {
    /// Construct a new CError struct based on the given error. The description
    /// is pretty-printed in a C-like manner (causes are appended to one another
    /// with separating colons). In addition, if the root-cause of the error is
    /// an IOError then errno is populated with that value.
    fn from(err: &Error) -> Self {
        let desc = err.iter_chain_hotfix().fold(String::new(), |mut s, next| {
            if !s.is_empty() {
                s.push_str(": ");
            }
            s.push_str(&next.to_string());
            s
        });

        // Create a C-compatible string for CError.description.
        let desc =
            CString::new(desc).expect("CString::new(description) failed in CError generation");

        let errno = match err.root_cause().downcast_ref::<IOError>() {
            Some(err) => err.raw_os_error().unwrap_or(0).abs(),
            _ => 0,
        };

        CError {
            saved_errno: errno.try_into().unwrap_or(0),
            description: desc.into_raw(),
        }
    }
}

impl Drop for CError {
    fn drop(&mut self) {
        if !self.description.is_null() {
            let description = self.description as *mut c_char;
            // Clear the pointer to avoid double-frees.
            self.description = ptr::null_mut();
            // SAFETY: CString::from_raw is safe because the C caller guarantees
            //         that the pointer we get is the same one we gave them.
            let _ = unsafe { CString::from_raw(description) };
            // drop the CString
        }
    }
}

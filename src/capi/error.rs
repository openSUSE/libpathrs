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
    capi::{ret::CReturn, utils::Leakable},
    error::Error,
};

use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap},
    error::Error as StdError,
    ffi::CString,
    ptr,
    sync::Mutex,
};

use libc::{c_char, c_int};
use once_cell::sync::Lazy;
use rand::{self, Rng};

// TODO: Switch this to using a slab or similar structure, possibly using a less
// heavy-weight lock?
// MSRV(1.80): Use LazyLock.
static ERROR_MAP: Lazy<Mutex<HashMap<CReturn, Error>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn store_error(err: Error) -> CReturn {
    let mut err_map = ERROR_MAP.lock().unwrap();

    // Try to find a negative error value we can use. We avoid using anything in
    // 0..4096 to avoid users interpreting the return value as an -errno (at the
    // moment, the largest errno is ~150 but the kernel currently reserves
    // 4096 values as possible ERR_PTR values).
    let mut g = rand::thread_rng();
    loop {
        let idx = g.gen_range(CReturn::MIN..=-4096);
        match err_map.entry(idx) {
            HashMapEntry::Occupied(_) => continue,
            HashMapEntry::Vacant(slot) => {
                slot.insert(err);
                return idx;
            }
        }
    }
}

/// Attempts to represent a Rust Error type in C. This structure must be freed
/// using pathrs_errorinfo_free().
// NOTE: This API is exposed to library users in a read-only manner with memory
//       management done by libpathrs -- so you may only ever append to it.
#[repr(align(8), C)]
pub struct CError {
    // TODO: Put a version or size here so that C users can tell what fields are
    // valid if we add fields in the future.
    /// Raw errno(3) value of the underlying error (or 0 if the source of the
    /// error was not due to a syscall error).
    // We can't call this field "errno" because glibc defines errno(3) as a
    // macro, causing all sorts of problems if you have a struct with an "errno"
    // field. Best to avoid those headaches.
    pub saved_errno: u64,

    /// Textual description of the error.
    pub description: *const c_char,
}

impl Leakable for CError {}

impl From<&Error> for CError {
    /// Construct a new CError struct based on the given error. The description
    /// is pretty-printed in a C-like manner (causes are appended to one another
    /// with separating colons). In addition, if the root-cause of the error is
    /// an IOError then errno is populated with that value.
    fn from(err: &Error) -> Self {
        // TODO: Switch to Error::chain() once it's stabilised.
        //       <https://github.com/rust-lang/rust/issues/58520>
        let desc = {
            let mut desc = err.to_string();
            let mut err: &(dyn StdError) = err;
            while let Some(next) = err.source() {
                desc.push_str(": ");
                desc.push_str(&next.to_string());
                err = next;
            }
            // Create a C-compatible string for CError.description.
            CString::new(desc).expect("CString::new(description) failed in CError generation")
        };

        // Map the error to a C errno if possible.
        // TODO: We might want to use ESERVERFAULT (An untranslatable error
        // occurred) for untranslatable errors?
        let saved_errno = err.kind().errno().unwrap_or(0).unsigned_abs();

        CError {
            saved_errno: saved_errno.into(),
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

/// Retrieve error information about an error id returned by a pathrs operation.
///
/// Whenever an error occurs with libpathrs, a negative number describing that
/// error (the error id) is returned. pathrs_errorinfo() is used to retrieve
/// that information:
///
/// ```c
/// fd = pathrs_inroot_resolve(root, "/foo/bar");
/// if (fd < 0) {
///     // fd is an error id
///     pathrs_error_t *error = pathrs_errorinfo(fd);
///     // ... print the error information ...
///     pathrs_errorinfo_free(error);
/// }
/// ```
///
/// Once pathrs_errorinfo() is called for a particular error id, that error id
/// is no longer valid and should not be used for subsequent pathrs_errorinfo()
/// calls.
///
/// Error ids are only unique from one another until pathrs_errorinfo() is
/// called, at which point the id can be re-used for subsequent errors. The
/// precise format of error ids is completely opaque and they should never be
/// compared directly or used for anything other than with pathrs_errorinfo().
///
/// Error ids are not thread-specific and thus pathrs_errorinfo() can be called
/// on a different thread to the thread where the operation failed (this is of
/// particular note to green-thread language bindings like Go, where this is
/// important).
///
/// # Return Value
///
/// If there was a saved error with the provided id, a pathrs_error_t is
/// returned describing the error. Use pathrs_errorinfo_free() to free the
/// associated memory once you are done with the error.
#[no_mangle]
pub unsafe extern "C" fn pathrs_errorinfo(err_id: c_int) -> Option<&'static mut CError> {
    let mut err_map = ERROR_MAP.lock().unwrap();

    err_map
        .remove(&err_id)
        .as_ref()
        .map(CError::from)
        .map(Leakable::leak)
}

/// Free the pathrs_error_t object returned by pathrs_errorinfo().
#[no_mangle]
pub unsafe extern "C" fn pathrs_errorinfo_free(ptr: *mut CError) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: The C caller guarantees that the pointer is of the correct type
    // and that this isn't a double-free.
    unsafe { (*ptr).free() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, ErrorImpl};

    use std::io::Error as IOError;

    use pretty_assertions::assert_eq;

    #[test]
    fn cerror_ioerror_errno() {
        let err = Error::from(ErrorImpl::OsError {
            operation: "fake operation".into(),
            source: IOError::from_raw_os_error(libc::ENOANO),
        });

        assert_eq!(
            err.kind().errno(),
            Some(libc::ENOANO),
            "basic kind().errno() should return the right error"
        );

        let cerr = CError::from(&err);
        assert_eq!(
            cerr.saved_errno,
            libc::ENOANO as u64,
            "cerror should contain errno for OsError"
        );
    }

    #[test]
    fn cerror_einval_errno() {
        let err = Error::from(ErrorImpl::InvalidArgument {
            name: "fake argument".into(),
            description: "fake description".into(),
        });

        assert_eq!(
            err.kind().errno(),
            Some(libc::EINVAL),
            "InvalidArgument kind().errno() should return the right error"
        );

        let cerr = CError::from(&err);
        assert_eq!(
            cerr.saved_errno,
            libc::EINVAL as u64,
            "cerror should contain EINVAL errno for InvalidArgument"
        );
    }

    #[test]
    fn cerror_enosys_errno() {
        let err = Error::from(ErrorImpl::NotImplemented {
            feature: "fake feature".into(),
        });

        assert_eq!(
            err.kind().errno(),
            Some(libc::ENOSYS),
            "NotImplemented kind().errno() should return the right error"
        );

        let cerr = CError::from(&err);
        assert_eq!(
            cerr.saved_errno,
            libc::ENOSYS as u64,
            "cerror should contain ENOSYS errno for NotImplemented"
        );
    }

    #[test]
    fn cerror_exdev_errno() {
        let err = Error::from(ErrorImpl::SafetyViolation {
            description: "fake safety violation".into(),
        });

        assert_eq!(
            err.kind().errno(),
            Some(libc::EXDEV),
            "SafetyViolation kind().errno() should return the right error"
        );

        let cerr = CError::from(&err);
        assert_eq!(
            cerr.saved_errno,
            libc::EXDEV as u64,
            "cerror should contain EXDEV errno for SafetyViolation"
        );
    }

    #[test]
    fn cerror_no_errno() {
        let parse_err = "a123".parse::<i32>().unwrap_err();
        let err = Error::from(parse_err);

        assert_eq!(
            err.kind().errno(),
            None,
            "ParseIntError kind().errno() should return no errno"
        );

        let cerr = CError::from(&err);
        assert_eq!(
            cerr.saved_errno, 0,
            "cerror should contain zero errno for ParseIntError"
        );
    }
}

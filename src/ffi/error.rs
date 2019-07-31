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

use std::cell::RefCell;
use std::ffi::CString;
use std::io::Error as IOError;

use failure::Error;
use libc::{c_int, c_uchar};

thread_local! {
    static LAST_ERROR: RefCell<Option<Box<Error>>> = RefCell::new(None);
}

/// An error description and (optionally) the underlying errno value that
/// triggered it (if there is no underlying errno, it is 0).
#[repr(C)]
pub struct CError {
    pub errno: i32,
    // TODO: Ideally, we would have a dynamically-sized struct here but Rust
    //       really doesn't like doing this. We could probably do it manually
    //       with libc::calloc(), but I'm not a huge fan of this idea.
    pub description: [c_uchar; 1024],
}

impl Default for CError {
    #[inline]
    fn default() -> Self {
        // repr(C) struct with no references is always safe.
        unsafe { std::mem::zeroed() }
    }
}

/// Very helpful wrapper to use in "pub extern fn" Rust FFI functions, to allow
/// for error handling to be done in a much more Rust-like manner.
///
/// ```deadcode
/// # use std::os::raw::c_char;
/// # fn main() {}
/// use failure::Error;
/// use libpathrs::ffi::error;
///
/// #[no_mangle]
/// pub extern fn func(msg: *const c_char) -> c_int {
///     error::ffi_wrap(-1, move || {
///         if msg.is_null() {
///             bail!("null pointer!");
///         }
///         Ok(42)
///     })
/// }
/// ```
pub fn ffi_wrap<F, R>(on_err: R, func: F) -> R
where
    F: FnOnce() -> Result<R, Error>,
{
    // Clear the error before the operation to avoid the errno problem.
    let _ = take_error();
    func().unwrap_or_else(|err| {
        set_error(err);
        on_err
    })
}

/// Construct a new CError struct based on the given error. The description is
/// pretty-printed in a C-like manner (causes are appended to one another with
/// separating colons). In addition, if the root-cause of the error is an
/// IOError then errno is populated with that value.
fn to_cerror(err: &Error) -> Result<CError, Error> {
    let fail = err.as_fail();
    let desc = err
        .iter_causes()
        .fold(fail.to_string(), |prev, next| format!("{}: {}", prev, next));

    let mut cerr: CError = Default::default();
    {
        // Create a C-compatible string, and truncate it to the size of our
        // fixed-length description slot. There's not much we can usefully do if
        // the error message is larger than 1K.
        let desc = CString::new(desc)?
            .into_bytes()
            .into_iter()
            .take(cerr.description.len() - 1)
            .chain(vec![0])
            .collect::<Vec<_>>();
        assert!(desc.len() <= cerr.description.len());

        // memcpy into the fixed buffer.
        let (prefix, _) = cerr.description.split_at_mut(desc.len());
        prefix.copy_from_slice(desc.as_slice());
    }
    cerr.errno = match fail.find_root_cause().downcast_ref::<IOError>() {
        Some(err) => err.raw_os_error().unwrap_or(0),
        _ => 0,
    };
    Ok(cerr)
}

/// Update the most recent error from Rust, clearing whatever error might have
/// been previously set.
pub fn set_error(err: Error) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    })
}

/// Retreive the most recent error from Rust, clearing the stored value.
pub fn take_error() -> Option<Box<Error>> {
    LAST_ERROR.with(|prev| prev.borrow_mut().take())
}

/// Copy the currently-stored infomation into the provided buffer.
///
/// If there was a stored error, a positive value is returned. If there was no
/// stored error, the contents of buffer are undefined and 0 is returned. If an
/// internal error occurs during processing, -1 is returned.
#[no_mangle]
pub extern "C" fn pathrs_error(buffer: *mut CError) -> c_int {
    if buffer.is_null() {
        return -1;
    }

    let last_error = match take_error() {
        Some(err) => err,
        None => return 0,
    };

    let cerr = match to_cerror(&last_error) {
        Ok(cerr) => cerr,
        Err(_) => return -1, // TODO: Log a warning...
    };
    unsafe { *buffer = cerr };

    std::mem::size_of::<CError>() as c_int
}

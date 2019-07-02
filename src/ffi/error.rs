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
use std::{ptr, slice};

use failure::Error;
use libc::{c_char, c_int};

thread_local! {
    static LAST_ERROR: RefCell<Option<Box<Error>>> = RefCell::new(None);
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

/// Pretty-print the error in a C-like or Go-like way (causes are appended to
/// one another with separating colons).
fn format_err(err: &Error) -> String {
    let fail = err.as_fail();
    err.iter_causes()
        .fold(fail.to_string(), |prev, next| format!("{}: {}", prev, next))
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

/// Get the string size currently-stored error (including the trailing NUL
/// byte). A return value of 0 indicates that there is no currently-stored
/// error. Cannot fail.
#[no_mangle]
pub extern "C" fn pathrs_error_length() -> c_int {
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => format_err(err).len() as c_int + 1,
        None => 0,
    })
}

/// Copy the currently-stored error string into the provided buffer. If the
/// buffer is not large enough to fit the message (see pathrs_error_length) or
/// is NULL, then -1 is returned. If the operation succeeds, the number of bytes
/// written (including the trailing NUL byte) is returned and the error is
/// cleared from libpathrs's side. If there was no error, then 0 is returned.
#[no_mangle]
pub extern "C" fn pathrs_error(buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        return -1;
    }

    let last_error = match take_error() {
        Some(err) => err,
        None => return 0,
    };

    let error_message = format_err(&last_error);
    if error_message.len() >= length as usize {
        // No need to do any mutex logic because LAST_ERROR is thread-local.
        set_error(*last_error);
        return -1;
    }

    unsafe {
        let buffer = slice::from_raw_parts_mut(buffer as *mut u8, length as usize);
        ptr::copy_nonoverlapping(
            error_message.as_ptr(),
            buffer.as_mut_ptr(),
            error_message.len(),
        );
        buffer[error_message.len()] = 0;
    }

    error_message.len() as c_int + 1
}

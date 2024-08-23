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
    capi::utils::{CError, Leakable},
    error::Error,
    Handle, Root,
};

use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap},
    os::unix::io::{IntoRawFd, OwnedFd},
    sync::Mutex,
};

use libc::c_int;
use rand::{self, Rng};

type CReturn = c_int;

pub(super) trait IntoCReturn {
    fn into_c_return(self) -> CReturn;
}

// TODO: Switch this to using a slab or similar structure, possibly using a less
// heavy-weight lock? Maybe sharded-slab?
// MSRV(1.70): Use OnceLock.
// MSRV(1.80): Use LazyLock.
lazy_static! {
    static ref ERROR_MAP: Mutex<HashMap<CReturn, Error>> = Mutex::new(HashMap::new());
}

fn store_error(err: Error) -> CReturn {
    let mut err_map = ERROR_MAP.lock().unwrap();

    // Try to find a negative error value we can use.
    let mut g = rand::thread_rng();
    loop {
        let idx = g.gen_range(CReturn::MIN..=-1);
        match err_map.entry(idx) {
            HashMapEntry::Occupied(_) => continue,
            HashMapEntry::Vacant(slot) => {
                slot.insert(err);
                return idx;
            }
        }
    }
}

// TODO: Is it possible for us to return an actual OwnedFd through FFI when we
//       need to? Unfortunately, CReturn may end up returning -1 which is an
//       invalid OwnedFd/BorrowedFd value...
//       <https://users.rust-lang.org/t/what-is-the-reason-for-the-1-restriction-in-ownedfd-borrowedfd/116450>

impl IntoCReturn for () {
    fn into_c_return(self) -> CReturn {
        0
    }
}

impl IntoCReturn for CReturn {
    fn into_c_return(self) -> CReturn {
        self
    }
}

impl IntoCReturn for OwnedFd {
    fn into_c_return(self) -> CReturn {
        self.into_raw_fd()
    }
}

impl IntoCReturn for Root {
    fn into_c_return(self) -> CReturn {
        OwnedFd::from(self).into_c_return()
    }
}

impl IntoCReturn for Handle {
    fn into_c_return(self) -> CReturn {
        OwnedFd::from(self).into_c_return()
    }
}

impl<V> IntoCReturn for Result<V, Error>
where
    V: IntoCReturn,
{
    fn into_c_return(self) -> CReturn {
        // self.map_or_else(store_error, IntoCReturn::into_c_return)
        match self {
            Ok(ok) => ok.into_c_return(),
            Err(err) => store_error(err),
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
/// fd = pathrs_resolve(root, "/foo/bar");
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
pub extern "C" fn pathrs_errorinfo(err_id: c_int) -> Option<&'static mut CError> {
    let mut err_map = ERROR_MAP.lock().unwrap();

    err_map
        .remove(&err_id)
        .as_ref()
        .map(CError::from)
        .map(Leakable::leak)
}

/// Free the pathrs_error_t object returned by pathrs_errorinfo().
#[no_mangle]
pub extern "C" fn pathrs_errorinfo_free(ptr: *mut CError) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: The C caller guarantees that the pointer is of the correct type
    // and that this isn't a double-free.
    unsafe { (*ptr).free() }
}

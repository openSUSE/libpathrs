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
    capi::error as capi_error,
    error::{ErrorExt, ErrorKind},
    tests::traits::ErrorImpl,
};

use std::{
    ffi::{CStr, CString, OsStr},
    fmt,
    os::unix::{
        ffi::OsStrExt,
        io::{FromRawFd, OwnedFd},
    },
    path::{Path, PathBuf},
    ptr,
};

use errno::Errno;

#[derive(Debug, Clone, thiserror::Error)]
pub struct CapiError {
    errno: Option<Errno>,
    description: String,
}

impl fmt::Display for CapiError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{}", self.description)?;
        if let Some(errno) = self.errno {
            write!(fmt, " ({errno})")?;
        }
        Ok(())
    }
}

impl ErrorExt for CapiError {
    fn with_wrap<F>(self, context_fn: F) -> Self
    where
        F: FnOnce() -> String,
    {
        Self {
            errno: self.errno,
            description: context_fn() + ": " + &self.description,
        }
    }
}

impl ErrorImpl for CapiError {
    fn kind(&self) -> ErrorKind {
        if let Some(errno) = self.errno {
            ErrorKind::OsError(Some(errno.0))
        } else {
            // TODO: We should probably have an actual "no-op" error here that
            //       is unused except for these tests so we can properly detect
            //       a bad ErrorKind.
            ErrorKind::InternalError
        }
    }
}

fn fetch_error(res: libc::c_int) -> Result<libc::c_int, CapiError> {
    if res >= 0 {
        Ok(res)
    } else {
        // SAFETY: pathrs_errorinfo is safe to call in general.
        match unsafe { capi_error::pathrs_errorinfo(res) } {
            Some(err) => {
                let errno = match err.saved_errno as i32 {
                    0 => None,
                    errno => Some(Errno(errno)),
                };
                // SAFETY: pathrs_errorinfo returns a valid string pointer. We
                // can't take ownership because pathrs_errorinfo_free() will do
                // the freeing for us.
                let description = unsafe { CStr::from_ptr(err.description) }
                    .to_string_lossy()
                    .to_string();

                // Free the error from the error map, now that we copied the
                // contents.
                // SAFETY: We are the only ones holding a reference to the err
                // pointer and don't touch it later, so we can free it freely.
                unsafe { capi_error::pathrs_errorinfo_free(err as *mut _) }

                Err(CapiError { errno, description })
            }
            None => panic!("unknown error id {res}"),
        }
    }
}

pub(in crate::tests) fn path_to_cstring<P: AsRef<Path>>(path: P) -> CString {
    CString::new(path.as_ref().as_os_str().as_bytes())
        .expect("normal path conversion shouldn't result in spurious nul bytes")
}

pub(in crate::tests) fn call_capi<Func>(func: Func) -> Result<libc::c_int, CapiError>
where
    Func: Fn() -> libc::c_int,
{
    fetch_error(func())
}

pub(in crate::tests) fn call_capi_zst<Func>(func: Func) -> Result<(), CapiError>
where
    Func: Fn() -> libc::c_int,
{
    call_capi(func).map(|val| {
        assert_eq!(
            val, 0,
            "call_capi_zst must only be called on methods that return <= 0: got {val}"
        );
    })
}

pub(in crate::tests) fn call_capi_fd<Func>(func: Func) -> Result<OwnedFd, CapiError>
where
    Func: Fn() -> libc::c_int,
{
    // SAFETY: The caller has guaranteed us that the closure will return an fd.
    call_capi(func).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(in crate::tests) fn call_capi_readlink<Func>(func: Func) -> Result<PathBuf, CapiError>
where
    Func: Fn(*mut libc::c_char, libc::size_t) -> libc::c_int,
{
    // Get the actual size by passing NULL.
    let mut actual_size = {
        // Try zero-size.
        let size1 = fetch_error(func(123 as *mut _, 0))? as usize;
        // Try NULL ptr.
        let size2 = fetch_error(func(ptr::null_mut(), 1000))? as usize;
        assert_eq!(size1, size2, "readlink size should be the same");
        size1
    };

    // Start with a smaller buffer so we can exercise the trimming logic.
    let mut linkbuf: Vec<u8> = Vec::with_capacity(0);
    actual_size /= 2;
    while actual_size > linkbuf.capacity() {
        linkbuf.reserve(actual_size);
        actual_size = fetch_error(func(
            linkbuf.as_mut_ptr() as *mut libc::c_char,
            linkbuf.capacity(),
        ))? as usize;
    }
    // SAFETY: The C code guarantees that actual_size is how many bytes are filled.
    unsafe { linkbuf.set_len(actual_size) };

    Ok(PathBuf::from(OsStr::from_bytes(
        // readlink does *not* append a null terminator!
        CString::new(linkbuf)
            .expect("constructing a CString from the C API's copied CString should work")
            .to_bytes(),
    )))
}

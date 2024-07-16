/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

use crate::{
    error::{self, Error},
    Handle, Root,
};

use std::{
    collections::HashMap,
    convert::{self, TryInto},
    ffi::{CStr, CString, OsStr},
    io::Error as IOError,
    mem,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
    sync::{Mutex, RwLock},
    thread::{self, ThreadId},
};

use backtrace::Backtrace;
use libc::{c_char, c_void};
use snafu::{ErrorCompat, OptionExt};

/// The type of object being passed to "object agnostic" libpathrs functions.
// The values of the enum are baked into the API, you can only append to it.
// TODO: #[non_exhaustive]
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CPointerType {
    __PATHRS_INVALID_TYPE = 0,
    /// NULL.
    PATHRS_NONE = 0xDFFF,
    /// `pathrs_error_t`
    PATHRS_ERROR = 0xE000,
    /// `pathrs_root_t`
    PATHRS_ROOT = 0xE001,
    /// `pathrs_handle_t`
    PATHRS_HANDLE = 0xE002,
}

pub(crate) fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, Error> {
    ensure!(
        !path.is_null(),
        error::InvalidArgument {
            name: "path",
            description: "cannot be NULL",
        }
    );
    // SAFETY: C caller guarantees that the path is a valid C-style string.
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    Ok(OsStr::from_bytes(bytes).as_ref())
}

pub(crate) trait Leakable {
    /// Leak a structure such that it can be passed through C-FFI.
    fn leak(self) -> &'static mut Self;

    /// Given a structure leaked through Leakable::leak, un-leak it. Callers
    /// must be sure to only ever call this once on a given pointer (otherwise
    /// memory corruption will occur).
    fn unleak(&'static mut self) -> Self;

    /// Shorthand for `std::mem::drop(self.unleak())`.
    fn free(&'static mut self);
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

        fn unleak(&'static mut self) -> Self {
            // SAFETY: Box::from_raw is safe because the C caller guarantees
            //         that the pointer we get is the same one we gave them, and
            //         it will only ever be called once with the same pointer.
            *unsafe { Box::from_raw(self as *mut Self) }
        }

        fn free(&'static mut self) {
            let _ = self.unleak();
            // drop Self
        }
    };

    (impl Leakable for $type:ty ;) => {
        impl Leakable for $type {
            leakable!(...);
        }
    };

    (impl <$($generics:tt),+> Leakable for $type:ty ;) => {
        impl<$($generics),+> Leakable for $type {
            leakable!(...);
        }
    };
}

pub(crate) trait ErrorWrap {
    fn wrap<F, R>(&mut self, c_error: R, func: F) -> R
    where
        F: FnOnce() -> Result<R, Error>;
}

impl ErrorWrap for Option<Error> {
    fn wrap<F, R>(&mut self, c_error: R, func: F) -> R
    where
        F: FnOnce() -> Result<R, Error>,
    {
        // Always clear the error to avoid the errno problem.
        *self = None;
        func().unwrap_or_else(|err| {
            *self = Some(err);
            c_error
        })
    }
}

/// This is only exported to work around a Rust compiler restriction. Consider
/// it an implementation detail and don't make use of it.
// Wrapping struct which we can given C a pointer to. &T isn't an option,
// because DSTs (fat pointers) like dyn T (and thus &dyn T) have no FFI-safe
// representation. So we need to hide it within an FFI-safe pointer (such as a
// trivial struct).
#[doc(hidden)]
#[derive(Debug)]
pub struct CPointer<T> {
    pub(crate) inner: RwLock<Option<T>>,
    // TODO: Switch to evmap or something with more granular locking.
    last_error: Mutex<HashMap<ThreadId, Option<Error>>>,
}

leakable! {
    impl<T> Leakable for CPointer<T>;
}

impl<T> CPointer<T> {
    pub(crate) fn from_err(err: Error) -> Self {
        CPointer {
            inner: RwLock::new(None),
            last_error: Mutex::new({
                let mut map = HashMap::new();
                map.insert(thread::current().id(), Some(err));
                map
            }),
        }
    }

    pub(crate) fn take_err(&self) -> Option<Error> {
        self.last_error
            .lock()
            .unwrap()
            .remove(&thread::current().id())
            .and_then(convert::identity)
    }

    fn do_wrap_err<F, R>(&self, c_error: R, func: F) -> R
    where
        F: FnOnce() -> Result<R, Error>,
    {
        let mut last_error: Option<Error> = None;
        let c_return = func().unwrap_or_else(|err| {
            last_error = Some(err);
            c_error
        });

        // Store the error.
        self.last_error
            .lock()
            .unwrap()
            .insert(thread::current().id(), last_error);

        c_return
    }

    pub(crate) fn wrap_err<F, R>(&self, c_error: R, func: F) -> R
    where
        F: FnOnce(&T) -> Result<R, Error>,
    {
        // TODO: Figure out how to handle None inners here. Currently this
        //       produces a "can't move out of dereference" error, which
        //       resulted in a bunch of .context() checks in the C API functions
        //       themselves.
        self.do_wrap_err(c_error, || {
            let inner = self.inner.read().unwrap();
            let inner = inner.as_ref().context(error::InvalidArgument {
                name: "ptr",
                description: "invalid pathrs object",
            })?;
            func(&inner)
        })
    }

    pub(crate) fn take_wrap_err<F, R>(&self, c_error: R, func: F) -> R
    where
        F: FnOnce(T) -> Result<R, Error>,
    {
        self.do_wrap_err(c_error, || {
            let mut inner = self.inner.write().unwrap();
            let inner = inner.take().context(error::InvalidArgument {
                name: "ptr",
                description: "invalid pathrs object",
            })?;
            func(inner)
        })
    }
}

impl<T> From<T> for CPointer<T> {
    fn from(inner: T) -> Self {
        CPointer {
            inner: RwLock::new(Some(inner)),
            last_error: Mutex::new(HashMap::new()),
        }
    }
}

/// A handle to the root of a directory tree to resolve within. The only purpose
/// of this "root handle" is to get Handles to inodes within the directory tree.
///
/// At the time of writing, it is considered a *VERY BAD IDEA* to open a Root
/// inside a possibly-attacker-controlled directory tree. While we do have
/// protections that should defend against it (for both drivers), it's far more
/// dangerous than just opening a directory tree which is not inside a
/// potentially-untrusted directory.
pub type CRoot = CPointer<Root>;

/// A handle to a path within a given Root. This handle references an
/// already-resolved path which can be used for only one purpose -- to "re-open"
/// the handle and get an actual fs::File which can be used for ordinary
/// operations.
///
/// It is critical for the safety of users of this library that *at no point* do
/// you use interfaces like libc::openat directly on file descriptors you get
/// from using this library (or extract the RawFd from a fs::File). You must
/// always use operations through a Root.
pub type CHandle = CPointer<Handle>;

/// Represents a Rust Vec<T> in an FFI-safe way. It is absolutely critical that
/// the FFI user does not modify *any* of these fields.
#[repr(align(8), C)]
#[derive(Debug)]
pub struct CVec<T> {
    /// Pointer to the head of the vector (probably shouldn't be modified).
    pub head: *const T,
    /// Number of elements in the vector (must not be modified).
    pub length: usize,
    /// Capacity of the vector (must not be modified).
    pub __capacity: usize,
}

leakable! {
    impl<T> Leakable for CVec<T>;
}

impl<T> From<Vec<T>> for CVec<T> {
    fn from(vec: Vec<T>) -> Self {
        let head = vec.as_ptr();
        let length = vec.len();
        let capacity = vec.capacity();

        // We now in charge of Vec's memory.
        mem::forget(vec);

        CVec {
            head,
            length,
            __capacity: capacity,
        }
    }
}

impl<T> Drop for CVec<T> {
    fn drop(&mut self) {
        if self.head.is_null() {
            let head = self.head as *mut T;
            // Clear the pointer to avoid double-frees.
            self.head = ptr::null_mut();
            // SAFETY: Vec::from_raw_parts is safe because the C caller
            //         guarantees that the (pointer, length, capacity) tuple is
            //         unchanged from when we created the CVec.
            let _ = unsafe { Vec::from_raw_parts(head, self.length, self.__capacity) };
            // drop the Vec and all its contents
        }
    }
}

/// Represents a single entry in a Rust backtrace in C. This structure is
/// owned by the relevant `pathrs_error_t`.
#[repr(align(8), C)]
#[derive(Debug)]
pub struct CBacktraceEntry {
    /// Instruction pointer at time of backtrace.
    pub ip: *const c_void,

    /// Address of the enclosing symbol at time of backtrace.
    pub symbol_address: *const c_void,

    /// Symbol name for @symbol_address (or NULL if none could be resolved).
    pub symbol_name: *const c_char,

    /// Filename in which the symbol is defined (or NULL if none could be
    /// resolved -- usually due to lack of debugging symbols).
    pub symbol_file: *const c_char,

    /// Line within @symbol_file on which the symbol is defined (will only make
    /// sense if @symbol_file is non-NULL).
    pub symbol_lineno: u32,
}

impl Drop for CBacktraceEntry {
    fn drop(&mut self) {
        if !self.symbol_name.is_null() {
            let symbol_name = self.symbol_name as *mut c_char;
            // Clear the pointer to avoid double-frees.
            self.symbol_name = ptr::null_mut();
            // SAFETY: CString::from_raw is safe because the C caller guarantees
            //         that the pointer we get is the same one we gave them.
            let _ = unsafe { CString::from_raw(symbol_name) };
            // drop the CString
        }
        if !self.symbol_file.is_null() {
            let symbol_file = self.symbol_file as *mut c_char;
            // Clear the pointer to avoid double-frees.
            self.symbol_file = ptr::null_mut();
            // SAFETY: CString::from_raw is safe because the C caller guarantees
            //         that the pointer we get is the same one we gave them.
            let _ = unsafe { CString::from_raw(symbol_file as *mut c_char) };
            // drop the CString
        }
    }
}

/// This is only exported to work around a Rust compiler restriction. Consider
/// it an implementation detail and don't make use of it.
pub type CBacktrace = CVec<CBacktraceEntry>;

impl From<Backtrace> for CBacktrace {
    fn from(mut backtrace: Backtrace) -> Self {
        // Make sure we've resolved as many symbols as possible.
        backtrace.resolve();

        // Construct a CVec<CBacktraceEntry> for leaking.
        backtrace
            .frames()
            .iter()
            .map(|frame| {
                let symbol = frame.symbols().last();

                // XXX: Option::flatten is in Rust 1.40.0 stable.

                let (name, file, lineno) = match symbol {
                    Some(symbol) => {
                        let name = symbol.name().map(|name| {
                            CString::new(name.to_string()).expect(
                                "CString::new(symbol_name) failed in CBacktraceEntry generation",
                            )
                        });

                        let file = symbol.filename().map(|file| {
                            CString::new(file.as_os_str().as_bytes()).expect(
                                "CString::new(symbol_file) failed in CBacktraceEntry generation",
                            )
                        });

                        (name, file, symbol.lineno())
                    }
                    None => (None, None, None),
                };

                CBacktraceEntry {
                    ip: frame.ip(),
                    symbol_address: frame.symbol_address(),
                    symbol_name: name.map(CString::into_raw).unwrap_or(ptr::null_mut())
                        as *const c_char,
                    symbol_file: file.map(CString::into_raw).unwrap_or(ptr::null_mut())
                        as *const c_char,
                    symbol_lineno: lineno.unwrap_or(0),
                }
            })
            .collect::<Vec<_>>()
            .into()
    }
}

/// Attempts to represent a Rust Error type in C. This structure must be freed
/// using `pathrs_free(PATHRS_ERROR)`.
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

    /// Backtrace captured at the error site (or NULL if backtraces have been
    /// disabled at libpathrs build-time or through an environment variable).
    pub backtrace: Option<&'static mut CBacktrace>,
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
            if s != "" {
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
            backtrace: ErrorCompat::backtrace(err)
                .cloned()
                .map(CBacktrace::from)
                .map(Leakable::leak),
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

        if let Some(ref mut backtrace) = self.backtrace {
            // The following is an exceptionally dirty hack to deal with the
            // fact that we cannot move a &'static mut in this context. However,
            // this is all okay because the &'static mut is being used as a
            // pointer to a leaked CBacktrace.
            let backtrace = *backtrace as *mut CBacktrace;
            // Remove self.backtrace reference before we do free it. We don't
            // want something to dereference it.
            self.backtrace = None;
            // And finally, free the backtrace.
            // SAFETY: While this is a &'static mut, we are the effective owner
            //         of this pointer because the C caller guarantees they
            //         won't use this pointer. And no Rust code will use it
            //         because we are in Drop.
            unsafe { &mut *backtrace }.free();
        }
    }
}

/// Retrieve the error stored by a pathrs object.
///
/// Whenever an error occurs during an operation on a pathrs object, the object
/// will store the error for retrieval with pathrs_error(). Note that performing
/// any subsequent operations will clear the stored error -- so the error must
/// immediately be fetched by the caller.
///
/// If there is no error associated with the object, NULL is returned (thus you
/// can safely check for whether an error occurred with pathrs_error).
///
/// It is critical that the correct pathrs_type_t is provided for the given
/// pointer (otherwise memory corruption will almost certainly occur).
#[no_mangle]
pub extern "C" fn pathrs_error(
    ptr_type: CPointerType,
    ptr: *const c_void,
) -> Option<&'static mut CError> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: All of these casts and dereferences are safe because the C caller
    //         has assured us that the type passed is correct.
    let err = match ptr_type {
        CPointerType::PATHRS_NONE => return None,
        CPointerType::PATHRS_ERROR => return None, // TODO: Clone the CError.
        CPointerType::PATHRS_ROOT => {
            // SAFETY: See above.
            let root = unsafe { &*(ptr as *const CRoot) };
            root.take_err()
        }
        CPointerType::PATHRS_HANDLE => {
            // SAFETY: See above.
            let handle = unsafe { &*(ptr as *const CHandle) };
            handle.take_err()
        }
        _ => panic!("invalid ptr_type: {:?}", ptr_type),
    };

    err.as_ref().map(CError::from).map(Leakable::leak)
}

/// Free a libpathrs object.
///
/// It is critical that the correct pathrs_type_t is provided for the given
/// pointer (otherwise memory corruption will almost certainly occur).
#[no_mangle]
pub extern "C" fn pathrs_free(ptr_type: CPointerType, ptr: *const c_void) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: All of these casts and dereferences are safe because the C caller
    //         has assured us that the type passed is correct.
    match ptr_type {
        CPointerType::PATHRS_NONE => (),
        // SAFETY: See above.
        CPointerType::PATHRS_ERROR => unsafe { &mut *(ptr as *mut CError) }.free(),
        // SAFETY: See above.
        CPointerType::PATHRS_ROOT => unsafe { &mut *(ptr as *mut CRoot) }.free(),
        // SAFETY: See above.
        CPointerType::PATHRS_HANDLE => unsafe { &mut *(ptr as *mut CHandle) }.free(),
        _ => panic!("invalid ptr_type: {:?}", ptr_type),
    }
}

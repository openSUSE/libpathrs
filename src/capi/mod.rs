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

// We need to permit unsafe code because we are exposing C APIs over FFI and
// thus need to interact with C callers.
#![allow(unsafe_code)]

use crate::{
    error::{self, Error, ErrorExt},
    resolvers::{Resolver, ResolverBackend, ResolverFlags},
    syscalls, Handle, InodeType, OpenFlags, RenameFlags, Root,
};

use std::convert::TryInto;
use std::ffi::{CStr, CString, OsStr};
use std::fs::Permissions;
use std::io::Error as IOError;
use std::os::unix::{
    ffi::OsStrExt,
    fs::PermissionsExt,
    io::{AsRawFd, IntoRawFd, RawFd},
};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::{cmp, mem, ptr};

use backtrace::Backtrace;
use libc::{c_char, c_int, c_uint, c_void, dev_t};
use snafu::{ErrorCompat, OptionExt, ResultExt};

trait Leakable {
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
/// ```
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

/// This is only exported to work around a Rust compiler restriction. Consider
/// it an implementation detail and don't make use of it.
// Wrapping struct which we can given C a pointer to. &T isn't an option,
// because DSTs (fat pointers) like dyn T (and thus &dyn T) have no FFI-safe
// representation. So we need to hide it within an FFI-safe pointer (such as a
// trivial struct).
pub struct CPointer<T> {
    inner: Option<T>,
    last_error: Option<Error>,
}

leakable! {
    impl<T> Leakable for CPointer<T>;
}

impl<T> From<T> for CPointer<T> {
    fn from(inner: T) -> Self {
        CPointer {
            inner: Some(inner),
            last_error: None,
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

// Private trait necessary to work around the "orphan trait" restriction.
trait ErrorWrap {
    fn wrap<F, R>(&mut self, c_err: R, func: F) -> R
    where
        F: FnOnce() -> Result<R, Error>;
}

impl ErrorWrap for Option<Error> {
    /// Very helpful wrapper to use in "pub extern fn" Rust FFI functions, to
    /// allow for error handling to be done in a much more Rust-like manner. The
    /// idea is that the Rust error is stored in some fixed variable (hopefully
    /// associated with the object being operated on) while the C FFI binding
    /// returns a C-friendly error code.
    ///
    /// ```
    /// # use std::os::raw::c_char;
    /// # fn main() {}
    /// use libpathrs::{Error, error, ffi::error};
    ///
    /// #[no_mangle]
    /// pub extern fn func(msg: *const c_char) -> c_int {
    ///     let mut last_error: Option<Error> = None;
    ///     last_error.wrap(-1, move || {
    ///         ensure!(!msg.is_null(), error::InvalidArgument {
    ///             name: "msg",
    ///             description: "must not be a null pointer",
    ///         });
    ///         Ok(42)
    ///     })
    /// }
    /// ```
    fn wrap<F, R>(&mut self, c_err: R, func: F) -> R
    where
        F: FnOnce() -> Result<R, Error>,
    {
        // Clear the error before the operation to avoid the "errno problem".
        *self = None;
        func().unwrap_or_else(|err| {
            *self = Some(err);
            c_err
        })
    }
}

/// Represents a Rust Vec<T> in an FFI-safe way. It is absolutely critical that
/// the FFI user does not modify *any* of these fields.
#[repr(align(8), C)]
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
            head: head,
            length: length,
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
    ptr: *mut c_void,
) -> Option<&'static mut CError> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: All of these casts and dereferences are safe because the C caller
    //         has assured us that the type passed is correct.
    let last_error = match ptr_type {
        CPointerType::PATHRS_NONE => return None,
        CPointerType::PATHRS_ERROR => return None,
        CPointerType::PATHRS_ROOT => {
            // SAFETY: See above.
            let root = unsafe { &mut *(ptr as *mut CRoot) };
            &mut root.last_error
        }
        CPointerType::PATHRS_HANDLE => {
            // SAFETY: See above.
            let handle = unsafe { &mut *(ptr as *mut CHandle) };
            &mut handle.last_error
        }
        _ => panic!("invalid ptr_type: {:?}", ptr_type),
    };

    last_error.as_ref().map(CError::from).map(Leakable::leak)
}

fn parse_path<'a>(path: *const c_char) -> Result<&'a Path, Error> {
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

/// Open a root handle.
///
/// The default resolver is automatically chosen based on the running kernel.
/// You can switch the resolver used with pathrs_configure() -- though this
/// is not strictly recommended unless you have a good reason to do it.
///
/// The provided path must be an existing directory.
///
/// NOTE: Unlike other libpathrs methods, pathrs_open will *always* return a
///       pathrs_root_t (but in the case of an error, the returned root handle
///       will be a "dummy" which is just used to store the error encountered
///       during setup). Errors during pathrs_open() can only be detected by
///       immediately calling pathrs_error() with the returned root handle --
///       and as with valid root handles, the caller must free it with
///       pathrs_free().
///
///       This unfortunate API wart is necessary because there is no obvious
///       place to store a libpathrs error when first creating an root handle
///       (other than using thread-local storage but that opens several other
///       cans of worms). This approach was chosen because in principle users
///       could call pathrs_error() after every libpathrs API call.
#[no_mangle]
pub extern "C" fn pathrs_open(path: *const c_char) -> &'static mut CRoot {
    match parse_path(path).and_then(Root::open) {
        Ok(root) => CRoot {
            inner: Some(root),
            last_error: None,
        },
        Err(err) => CRoot {
            inner: None,
            last_error: Some(err),
        },
    }
    .leak()
}

/// Represents an FFI-safe configuration structure which supports setting and getting.
trait CConfig: Default {
    /// Verify that the pointer type and pointer are valid for this type of
    /// `CConfig`. This is mostly a sanity-check (`pathrs_configure()` knows the
    /// mapping between `CPointerType` and Rust type).
    fn verify(ptr_type: CPointerType, ptr: *mut c_void) -> Result<(), Error>;

    /// Fetch the configuration from the ptr object, and store it in this config
    /// object.
    fn fetch(&mut self, ptr: *const c_void) -> Result<(), Error>;

    /// Apply a configuration to the given ptr object.
    fn apply(&self, ptr: *mut c_void) -> Result<(), Error>;
}

/// The backend used for path resolution within a `pathrs_root_t` to get a
/// `pathrs_handle_t`. Can be used with `pathrs_configure()` to change the
/// resolver for a `pathrs_root_t`.
// TODO: #[non_exhaustive]
#[repr(u64)]
#[allow(non_camel_case_types, dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CResolver {
    __PATHRS_INVALID_RESOLVER = 0,
    /// Use the native openat2(2) backend (requires kernel support).
    PATHRS_KERNEL_RESOLVER = 0xF000,
    /// Use the userspace "emulated" backend.
    PATHRS_EMULATED_RESOLVER = 0xF001,
}

impl From<ResolverBackend> for CResolver {
    fn from(other: ResolverBackend) -> Self {
        match other {
            ResolverBackend::Kernel => CResolver::PATHRS_KERNEL_RESOLVER,
            ResolverBackend::Emulated => CResolver::PATHRS_EMULATED_RESOLVER,
        }
    }
}

impl Into<ResolverBackend> for CResolver {
    fn into(self) -> ResolverBackend {
        match self {
            CResolver::PATHRS_KERNEL_RESOLVER => ResolverBackend::Kernel,
            CResolver::PATHRS_EMULATED_RESOLVER => ResolverBackend::Emulated,
            _ => panic!("invalid resolver: {:?}", self),
        }
    }
}

/// Configuration for a specific `pathrs_root_t`, for use with
///    `pathrs_configure(PATHRS_ROOT, <root>)`
#[repr(align(8), C)]
pub struct CRootConfig {
    /// Resolver used for all resolution under this `pathrs_root_t`.
    pub resolver: CResolver,
    /// Flags to pass to resolver. These must be valid `RESOLVE_*` flags. At
    /// time of writing, only `RESOLVE_NO_SYMLINKS` is supported.
    pub flags: u64,
}

impl Default for CRootConfig {
    fn default() -> Self {
        // Zero-fill by default to match C.
        Self {
            resolver: CResolver::__PATHRS_INVALID_RESOLVER,
            flags: 0,
        }
    }
}

impl CConfig for CRootConfig {
    fn verify(ptr_type: CPointerType, ptr: *mut c_void) -> Result<(), Error> {
        // Guaranteed by pathrs_configure.
        assert!(ptr_type == CPointerType::PATHRS_ROOT);
        ensure!(
            !ptr.is_null(),
            error::InvalidArgument {
                name: "ptr",
                description: "ptr must be non-NULL",
            }
        );

        // SAFETY: This cast and dereference is safe because the C caller has
        //         assured us that the type passed is correct.
        let root = unsafe { &mut *(ptr as *mut CRoot) };
        // Check that it's a valid object.
        ensure!(
            root.inner.is_some(),
            error::InvalidArgument {
                name: "ptr",
                description: "invalid pathrs object",
            }
        );

        Ok(())
    }

    fn fetch(&mut self, ptr: *const c_void) -> Result<(), Error> {
        // SAFETY: This cast and dereference is safe because the C caller has
        //         assured us that the type passed is correct.
        let root = unsafe { &*(ptr as *const CRoot) }
            .inner
            .as_ref()
            .expect("object must be valid");

        *self = Self {
            resolver: root.resolver.backend.into(),
            flags: root.resolver.flags.bits(),
        };
        Ok(())
    }

    fn apply(&self, ptr: *mut c_void) -> Result<(), Error> {
        // SAFETY: This cast and dereference is safe because the C caller has
        //         assured us that the type passed is correct.
        let root = unsafe { &mut *(ptr as *mut CRoot) }
            .inner
            .as_mut()
            .expect("object must be valid");

        root.resolver = Resolver {
            backend: self.resolver.into(),
            flags: ResolverFlags::from_bits(self.flags).context(error::InvalidArgument {
                name: "pathrs_config_global_t.flags",
                description: "must only contain valid flags",
            })?,
        };
        Ok(())
    }
}

/// Global configuration for pathrs, for use with
///    `pathrs_configure(PATHRS_NONE, NULL)`
#[repr(align(8), C)]
pub struct CGlobalConfig {
    /// Sets whether backtraces will be generated for errors. This is a global
    /// setting, and defaults to **disabled** for release builds of libpathrs
    /// (but is **enabled** for debug builds).
    pub error_backtraces: bool,
    /// Extra padding fields -- must be set to zero.
    pub __padding: [u8; 7],
}

impl Default for CGlobalConfig {
    fn default() -> Self {
        // Zero-fill by default to match C.
        Self {
            error_backtraces: false,
            __padding: [0; 7],
        }
    }
}

impl CConfig for CGlobalConfig {
    fn verify(ptr_type: CPointerType, ptr: *mut c_void) -> Result<(), Error> {
        // Guaranteed by pathrs_configure.
        assert!(ptr_type == CPointerType::PATHRS_NONE);
        ensure!(
            ptr.is_null(),
            error::InvalidArgument {
                name: "ptr",
                description: "ptr must be NULL with PATHRS_NONE",
            }
        );
        Ok(())
    }

    fn fetch(&mut self, _ptr: *const c_void) -> Result<(), Error> {
        self.error_backtraces = error::BACKTRACES_ENABLED.load(Ordering::SeqCst);
        Ok(())
    }

    fn apply(&self, _ptr: *mut c_void) -> Result<(), Error> {
        error::BACKTRACES_ENABLED.store(self.error_backtraces, Ordering::SeqCst);
        Ok(())
    }
}

/// Copy a struct from a C caller to Rust.
///
/// This is done very similarly to `copy_struct_from_user()` within Linux for
/// newer `openat2(2)`-style syscalls. The basic idea is that the caller
/// provides ptr_size as an effective version number, but it remains
/// forward-compatible (a newer caller that doesn't use new features still
/// works). New features will always require a non-zero value to be set in a new
/// struct field (or a new flag but that can be easily detected).
fn copy_struct_in<T: CConfig>(
    dst: &mut T,
    ptr: *const c_void,
    ptr_size: usize,
) -> Result<(), Error> {
    let lib_size = mem::size_of::<T>();

    // Zero-fill dst before we do anything.
    *dst = Default::default();

    // How much should we copy?
    let copy = cmp::min(ptr_size, lib_size);
    let rest = cmp::max(ptr_size, lib_size) - copy; // (ptr_size - lib_size).abs()

    if ptr_size > lib_size {
        // Deal with trailing bytes -- this is effectively check_zeroed_user().
        // SAFETY: Calculating the offset is safe because the caller has
        //         guaranteed us that the pointer passed is valid for ptr_size
        //         (>= copy) bytes.
        let start_ptr = unsafe { (ptr as *const u8).offset(copy as isize) };
        for i in 0..rest {
            // SAFETY: Reading this is safe because the caller has guaranteed us
            //         that the pointer passed is valid for ptr_size bytes.
            let val = unsafe { ptr::read_unaligned(start_ptr.offset(i as isize)) };
            // TODO: This should probably be a specific error type...
            ensure!(val == 0, error::InvalidArgument {
                name: "new_cfg_ptr",
                description: format!("trailing non-zero bytes in struct -- library too old (lib_size={}) or broken calling code", lib_size),
            });
        }
    }

    // This is safe because dst is a #[repr(align(8), C)] struct which the C
    // caller has assured us has the right type and size. dst is definitely not
    // overlapping because it's a stack variable not a C pointer.
    unsafe { ptr::copy_nonoverlapping(ptr as *const u8, dst as *mut T as *mut u8, copy) };
    Ok(())
}

/// Copy a struct from Rust to a C caller.
///
/// This is conceptually similar to `copy_struct_from_user()` within Linux, and
/// thus `copy_struct_in()`. However we don't care if there are non-zero bytes
/// in the Rust side of things -- the caller wouldn't know what to do with them.
fn copy_struct_out<T: CConfig>(src: &T, ptr: *mut c_void, ptr_size: usize) -> Result<(), Error> {
    let lib_size = mem::size_of::<T>();

    // Zero-fill ptr before we do anything.
    // SAFETY: The C caller has guaranteed that the pointer is valid for writing
    //         for the specified length (and is correctly aligned). The target
    //         type is #[repr(C)] and safe to zero-fill by design -- see
    //         pathrs_configure() for more details.
    unsafe { ptr::write_bytes(ptr as *mut u8, 0, ptr_size) };

    // How much should we copy?
    let copy = cmp::min(ptr_size, lib_size);

    // SAFETY: This is safe because dst is a #[repr(align(8), C)] struct which
    //         the C caller has assured us has the right type and size. src is
    //         definitely not overlapping because it's a stack variable not a C
    //         pointer.
    unsafe { ptr::copy_nonoverlapping(src as *const T as *const u8, ptr as *mut u8, copy) };
    Ok(())
}

/// Configure pathrs and its objects and fetch the current configuration.
///
/// Given a (ptr_type, ptr) combination the provided @new_ptr configuration will
/// be applied, while the previous configuration will be stored in @old_ptr.
///
/// If @new_ptr is NULL the active configuration will be unchanged (but @old_ptr
/// will be filled with the active configuration). Similarly, if @old_ptr is
/// NULL the active configuration will be changed but the old configuration will
/// not be stored anywhere. If both are NULL, the operation is a no-op.
///
/// Only certain objects can be configured with pathrs_configure():
///
///   * PATHRS_NONE (@ptr == NULL), with pathrs_config_global_t.
///   * PATHRS_ROOT, with pathrs_config_root_t.
///
/// The caller *must* set @cfg_size to the sizeof the configuration type being
/// passed. This is used for backwards and forward compatibility (similar to the
/// openat2(2) and similar syscalls).
///
/// For all other types, a pathrs_error_t will be returned (and as usual, it is
/// up to the caller to pathrs_free it).
#[no_mangle]
pub extern "C" fn pathrs_configure(
    ptr_type: CPointerType,
    ptr: *mut c_void,
    old_cfg_ptr: *mut c_void,
    new_cfg_ptr: *const c_void,
    cfg_size: usize,
) -> Option<&'static mut CError> {
    // XXX: All of this could probably be made quite a bit neater with a macro.

    let mut error: Option<Error> = None;
    error.wrap((), move || {
        // First, check that ptr is valid and ptr_type can be configured.
        match ptr_type {
            CPointerType::PATHRS_NONE => CGlobalConfig::verify(ptr_type, ptr),
            CPointerType::PATHRS_ROOT => CRootConfig::verify(ptr_type, ptr),
            _ => error::InvalidArgument {
                name: "ptr_type",
                description: "type cannot be configured",
            }
            .fail(),
        }?;

        // First, get the original configuration (if requested).
        if !old_cfg_ptr.is_null() {
            // In all of the following cases, we are going to create a copy of
            // the library's internal config structure (zero-filled by default)
            // and then copy min(cfg_size, mem::size_of::<internal config>())
            // bytes to the copy. We then verify that the user's copy doesn't
            // have any trailing non-zero bytes.
            //
            // This is all entirely safe because the type is #[repr(align(8),
            // C)] and contains no non-nullable values. The C caller assures us
            // that the type of the struct passed is correct, and that cfg_size
            // actually is the size of the struct they've given us.
            //
            // The purpose of this is to implement forward and backwards
            // compatibility, a-la openat2(2) and similar syscalls (symbol
            // versioning doesn't help us with struct extension).
            match ptr_type {
                CPointerType::PATHRS_NONE => {
                    let mut old_cfg = CGlobalConfig::default();
                    old_cfg.fetch(ptr)?;
                    copy_struct_out(&old_cfg, old_cfg_ptr, cfg_size)
                        .wrap("copy libpathrs config to caller old_cfg_ptr")?;
                }
                CPointerType::PATHRS_ROOT => {
                    let mut old_cfg = CRootConfig::default();
                    old_cfg.fetch(ptr)?;
                    copy_struct_out(&old_cfg, old_cfg_ptr, cfg_size)
                        .wrap("copy libpathrs config to caller old_cfg_ptr")?;
                }
                _ => unreachable!(), // already handled above
            };
        }

        // Finally, set the new configuration (if requested).
        if !new_cfg_ptr.is_null() {
            // In all of the following cases, we are going to create a copy of
            // the library's internal config structure (zero-filled by default)
            // and then copy min(cfg_size, mem::size_of::<internal config>())
            // bytes to the copy. We then verify that the user's copy doesn't
            // have any trailing non-zero bytes.
            //
            // This is all entirely safe because the type is #[repr(align(8),
            // C)] and contains no non-nullable values. The C caller assures us
            // that the type of the struct passed is correct, and that cfg_size
            // actually is the size of the struct they've given us.
            //
            // The purpose of this is to implement forward and backwards
            // compatibility, a-la openat2(2) and similar syscalls (symbol
            // versioning doesn't help us with struct extension).
            match ptr_type {
                CPointerType::PATHRS_NONE => {
                    let mut new_cfg = CGlobalConfig::default();
                    copy_struct_in(&mut new_cfg, new_cfg_ptr, cfg_size)
                        .wrap("copy caller new_cfg_ptr to libpathrs config")?;
                    // Check that padding is zeroed.
                    ensure!(
                        new_cfg.__padding.iter().all(|e| *e == 0),
                        error::InvalidArgument {
                            name: "new_cfg_ptr",
                            description: "unused padding fields must be zero",
                        }
                    );
                    new_cfg.apply(ptr)?;
                }
                CPointerType::PATHRS_ROOT => {
                    let mut new_cfg = CRootConfig::default();
                    copy_struct_in(&mut new_cfg, new_cfg_ptr, cfg_size)
                        .wrap("copy caller new_cfg_ptr to libpathrs config")?;
                    new_cfg.apply(ptr)?;
                }
                _ => unreachable!(), // already handled above
            };
        }

        Ok(())
    });

    error.as_ref().map(CError::from).map(Leakable::leak)
}

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

/// Free a libpathrs object.
///
/// It is critical that the correct pathrs_type_t is provided for the given
/// pointer (otherwise memory corruption will almost certainly occur).
#[no_mangle]
pub extern "C" fn pathrs_free(ptr_type: CPointerType, ptr: *mut c_void) {
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

/// "Upgrade" the handle to a usable fd, suitable for reading and writing. This
/// does not consume the original handle (allowing for it to be used many
/// times).
///
/// It should be noted that the use of O_CREAT *is not* supported (and will
/// result in an error). Handles only refer to *existing* files. Instead you
/// need to use creat().
///
/// In addition, O_NOCTTY is automatically set when opening the path. If you
/// want to use the path as a controlling terminal, you will have to do
/// ioctl(fd, TIOCSCTTY, 0) yourself.
#[no_mangle]
pub extern "C" fn pathrs_reopen(handle: &mut CHandle, flags: c_int) -> RawFd {
    let flags = OpenFlags(flags);
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &handle.inner;

    handle.last_error.wrap(-1, || {
        let file = inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "handle",
                description: "invalid pathrs object",
            })?
            .reopen(flags)?;
        // Rust sets O_CLOEXEC by default, without an opt-out. We need to
        // disable it if we weren't asked to do O_CLOEXEC.
        if flags.0 & libc::O_CLOEXEC == 0 {
            syscalls::fcntl_unset_cloexec(file.as_raw_fd()).context(error::RawOsError {
                operation: "clear O_CLOEXEC on fd",
            })?;
        }
        Ok(file.into_raw_fd())
    })
}

/// Within the given root's tree, resolve the given path (with all symlinks
/// being scoped to the root) and return a handle to that path. The path *must
/// already exist*, otherwise an error will occur.
#[no_mangle]
pub extern "C" fn pathrs_resolve(
    root: &mut CRoot,
    path: *const c_char,
) -> Option<&'static mut CHandle> {
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &root.inner;

    root.last_error.wrap(None, move || {
        inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "root",
                description: "invalid pathrs object",
            })?
            .resolve(parse_path(path)?)
            .map(CHandle::from)
            .map(Leakable::leak)
            .map(Option::from)
    })
}

/// Within the given root's tree, perform the rename (with all symlinks being
/// scoped to the root). The flags argument is identical to the renameat2(2)
/// flags that are supported on the system.
#[no_mangle]
pub extern "C" fn pathrs_rename(
    root: &mut CRoot,
    src: *const c_char,
    dst: *const c_char,
    flags: c_int,
) -> c_int {
    let flags = RenameFlags(flags);
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &root.inner;

    root.last_error.wrap(-1, move || {
        inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "root",
                description: "invalid pathrs object",
            })?
            .rename(parse_path(src)?, parse_path(dst)?, flags)
            .and(Ok(0))
    })
}

// Within the root, create an inode at the path with the given mode. If the
// path already exists, an error is returned (effectively acting as though
// O_EXCL is always set). Each pathrs_* corresponds to the matching syscall.

// TODO: Replace all these wrappers with macros. It's quite repetitive.

#[no_mangle]
pub extern "C" fn pathrs_creat(
    root: &mut CRoot,
    path: *const c_char,
    mode: c_uint,
) -> Option<&'static mut CHandle> {
    let mode = mode & !libc::S_IFMT;
    let perm = Permissions::from_mode(mode);
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &root.inner;

    root.last_error.wrap(None, move || {
        inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "root",
                description: "invalid pathrs object",
            })?
            .create_file(parse_path(path)?, &perm)
            .map(CHandle::from)
            .map(Leakable::leak)
            .map(Option::from)
    })
}

#[no_mangle]
pub extern "C" fn pathrs_mkdir(root: &mut CRoot, path: *const c_char, mode: c_uint) -> c_int {
    let mode = mode & !libc::S_IFMT;

    pathrs_mknod(root, path, libc::S_IFDIR | mode, 0)
}

#[no_mangle]
pub extern "C" fn pathrs_mknod(
    root: &mut CRoot,
    path: *const c_char,
    mode: c_uint,
    dev: dev_t,
) -> c_int {
    let fmt = mode & libc::S_IFMT;
    let perms = Permissions::from_mode(mode ^ fmt);
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &root.inner;

    root.last_error.wrap(-1, move || {
        let path = parse_path(path)?;
        let inode_type = match fmt {
            libc::S_IFREG => InodeType::File(&perms),
            libc::S_IFDIR => InodeType::Directory(&perms),
            libc::S_IFBLK => InodeType::BlockDevice(&perms, dev),
            libc::S_IFCHR => InodeType::CharacterDevice(&perms, dev),
            libc::S_IFIFO => InodeType::Fifo(&perms),
            libc::S_IFSOCK => error::NotImplemented {
                feature: "mknod(S_IFSOCK)",
            }
            .fail()?,
            _ => error::InvalidArgument {
                name: "mode",
                description: "invalid S_IFMT mask",
            }
            .fail()?,
        };
        inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "root",
                description: "invalid pathrs object",
            })?
            .create(path, &inode_type)
            .and(Ok(0))
    })
}

#[no_mangle]
pub extern "C" fn pathrs_symlink(
    root: &mut CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &root.inner;

    root.last_error.wrap(-1, move || {
        let path = parse_path(path)?;
        let target = parse_path(target)?;

        inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "root",
                description: "invalid pathrs object",
            })?
            .create(path, &InodeType::Symlink(target))
            .and(Ok(0))
    })
}

#[no_mangle]
pub extern "C" fn pathrs_hardlink(
    root: &mut CRoot,
    path: *const c_char,
    target: *const c_char,
) -> c_int {
    // Workaround for https://github.com/rust-lang/rust/issues/53488.
    let inner = &root.inner;

    root.last_error.wrap(-1, move || {
        let path = parse_path(path)?;
        let target = parse_path(target)?;

        inner
            .as_ref()
            .context(error::InvalidArgument {
                name: "root",
                description: "invalid pathrs object",
            })?
            .create(path, &InodeType::Hardlink(target))
            .and(Ok(0))
    })
}

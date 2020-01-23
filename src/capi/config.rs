/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019, 2020 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019, 2020 SUSE LLC
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

// TODO: We should switch to string-based configuration. Using structs will
//       unlikely work for very long in the long-term.

use crate::{
    capi::utils::{CError, CPointerType, CRoot, CRootInner, ErrorWrap, Leakable},
    error::{self, Error, ErrorExt},
    resolvers::{Resolver, ResolverBackend, ResolverFlags},
};

use std::{cmp, mem, ptr, sync::atomic::Ordering};

use libc::c_void;
use snafu::OptionExt;

/// Represents an FFI-safe configuration structure which supports setting and getting.
trait CConfig: Default {
    type Object;
    type ObjectInner;

    /// Verify that the pointer type and pointer are valid for this type of
    /// `CConfig`. This is mostly a sanity-check (`pathrs_configure()` knows the
    /// mapping between `CPointerType` and Rust type).
    fn verify(ptr_type: CPointerType, ptr: *mut c_void) -> Result<&'static Self::Object, Error>;

    /// Fetch the configuration from the ptr object, and store it in this config
    /// object.
    fn fetch(&mut self, from: &Self::ObjectInner) -> Result<(), Error>;

    /// Apply a configuration to the given ptr object.
    fn apply(&self, to: &mut Self::ObjectInner) -> Result<(), Error>;
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
#[derive(Debug)]
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
    type Object = CRoot;
    type ObjectInner = CRootInner;

    fn verify(ptr_type: CPointerType, ptr: *mut c_void) -> Result<&'static Self::Object, Error> {
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
        let root = unsafe { &*(ptr as *const CRoot) };
        {
            // Check that it's a valid object.
            let root = root.inner.lock().unwrap();
            ensure!(
                root.inner.is_some(),
                error::InvalidArgument {
                    name: "ptr",
                    description: "invalid pathrs object",
                }
            );
        }

        Ok(root)
    }

    fn fetch(&mut self, ptr: &Self::ObjectInner) -> Result<(), Error> {
        let root = ptr.inner.as_ref().context(error::InvalidArgument {
            name: "ptr",
            description: "invalid pathrs object",
        })?;

        *self = Self {
            resolver: root.resolver.backend.into(),
            flags: root.resolver.flags.bits(),
        };
        Ok(())
    }

    fn apply(&self, ptr: &mut Self::ObjectInner) -> Result<(), Error> {
        let root = ptr.inner.as_mut().context(error::InvalidArgument {
            name: "ptr",
            description: "invalid pathrs object",
        })?;

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
#[derive(Debug, Default)]
pub struct CGlobalConfig {
    /// Sets whether backtraces will be generated for errors. This is a global
    /// setting, and defaults to **disabled** for release builds of libpathrs
    /// (but is **enabled** for debug builds).
    pub error_backtraces: bool,
    /// Extra padding fields -- must be set to zero.
    pub __padding: [u8; 7],
}

impl CConfig for CGlobalConfig {
    type Object = ();
    type ObjectInner = ();

    fn verify(ptr_type: CPointerType, ptr: *mut c_void) -> Result<&'static Self::Object, Error> {
        // Guaranteed by pathrs_configure.
        assert!(ptr_type == CPointerType::PATHRS_NONE);
        ensure!(
            ptr.is_null(),
            error::InvalidArgument {
                name: "ptr",
                description: "ptr must be NULL with PATHRS_NONE",
            }
        );
        Ok(&())
    }

    fn fetch(&mut self, _ptr: &Self::ObjectInner) -> Result<(), Error> {
        self.error_backtraces = error::BACKTRACES_ENABLED.load(Ordering::SeqCst);
        Ok(())
    }

    fn apply(&self, _ptr: &mut Self::ObjectInner) -> Result<(), Error> {
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
        let start_ptr = unsafe { (ptr as *const u8).add(copy) };
        for i in 0..rest {
            // SAFETY: Reading this is safe because the caller has guaranteed us
            //         that the pointer passed is valid for ptr_size bytes.
            let val = unsafe { ptr::read_unaligned(start_ptr.add(i)) };
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
    // TODO: This entire interface should be rewritten and redesigned.

    let mut error: Option<Error> = None;
    error.wrap((), move || {
        // First, check that ptr is valid and ptr_type can be configured.
        match ptr_type {
            CPointerType::PATHRS_NONE => {
                let _ = CGlobalConfig::verify(ptr_type, ptr)?;
                if !old_cfg_ptr.is_null() {
                    let mut old_cfg = CGlobalConfig::default();
                    old_cfg.fetch(&())?;
                    copy_struct_out(&old_cfg, old_cfg_ptr, cfg_size)
                        .wrap("copy libpathrs config to caller old_cfg_ptr")?;
                }
                if !new_cfg_ptr.is_null() {
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
                    new_cfg.apply(&mut ())?;
                }
            }
            CPointerType::PATHRS_ROOT => {
                let obj = CRootConfig::verify(ptr_type, ptr)?;
                let mut obj_inner = obj.inner.lock().unwrap();

                if !old_cfg_ptr.is_null() {
                    let mut old_cfg = CRootConfig::default();
                    old_cfg.fetch(&obj_inner)?;
                    copy_struct_out(&old_cfg, old_cfg_ptr, cfg_size)
                        .wrap("copy libpathrs config to caller old_cfg_ptr")?;
                }
                if !new_cfg_ptr.is_null() {
                    let mut new_cfg = CRootConfig::default();
                    copy_struct_in(&mut new_cfg, new_cfg_ptr, cfg_size)
                        .wrap("copy caller new_cfg_ptr to libpathrs config")?;
                    new_cfg.apply(&mut obj_inner)?;
                }
            }
            _ => {
                return error::InvalidArgument {
                    name: "ptr_type",
                    description: "type cannot be configured",
                }
                .fail()?;
            }
        };
        Ok(())
    });

    error.as_ref().map(CError::from).map(Leakable::leak)
}

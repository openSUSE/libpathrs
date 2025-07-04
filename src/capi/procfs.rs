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
    capi::{ret::IntoCReturn, utils},
    error::{Error, ErrorImpl},
    flags::OpenFlags,
    procfs::{ProcfsBase, ProcfsHandle},
};

use std::os::unix::io::{OwnedFd, RawFd};

use libc::{c_char, c_int, size_t};
use open_enum::open_enum;

/// Indicate what base directory should be used when doing operations with
/// `pathrs_proc_*`.
#[open_enum]
#[repr(u64)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types, dead_code)]
pub enum CProcfsBase {
    /// Use /proc. Note that this mode may be more expensive because we have
    /// to take steps to try to avoid leaking unmasked procfs handles, so you
    /// should use PATHRS_PROC_SELF if you can.
    PATHRS_PROC_ROOT = 0x5001_FFFF,

    /// Use /proc/self. For most programs, this is the standard choice.
    PATHRS_PROC_SELF = 0x091D_5E1F,

    /// Use /proc/thread-self. In multi-threaded programs where one thread has a
    /// different CLONE_FS, it is possible for /proc/self to point the wrong
    /// thread and so /proc/thread-self may be necessary.
    ///
    /// NOTE: Using /proc/thread-self may require care if used from languages
    /// where your code can change threads without warning and old threads can
    /// be killed (such as Go -- where you want to use runtime.LockOSThread).
    PATHRS_PROC_THREAD_SELF = 0x3EAD_5E1F,
}

impl TryFrom<CProcfsBase> for ProcfsBase {
    type Error = Error;

    fn try_from(c_base: CProcfsBase) -> Result<Self, Self::Error> {
        match c_base {
            CProcfsBase::PATHRS_PROC_ROOT => Ok(ProcfsBase::ProcRoot),
            CProcfsBase::PATHRS_PROC_SELF => Ok(ProcfsBase::ProcSelf),
            CProcfsBase::PATHRS_PROC_THREAD_SELF => Ok(ProcfsBase::ProcThreadSelf),
            _ => Err(ErrorImpl::InvalidArgument {
                name: "procfs base".into(),
                description: "the procfs base must be one of the PATHRS_PROC_* values".into(),
            }
            .into()),
        }
    }
}

#[cfg(test)]
impl From<ProcfsBase> for CProcfsBase {
    fn from(base: ProcfsBase) -> Self {
        match base {
            ProcfsBase::ProcRoot => CProcfsBase::PATHRS_PROC_ROOT,
            ProcfsBase::ProcSelf => CProcfsBase::PATHRS_PROC_SELF,
            ProcfsBase::ProcThreadSelf => CProcfsBase::PATHRS_PROC_THREAD_SELF,
        }
    }
}

/// Safely open a path inside a `/proc` handle.
///
/// Any bind-mounts or other over-mounts will (depending on what kernel features
/// are available) be detected and an error will be returned. Non-trailing
/// symlinks are followed but care is taken to ensure the symlinks are
/// legitimate.
///
/// Unless you intend to open a magic-link, `O_NOFOLLOW` should be set in flags.
/// Lookups with `O_NOFOLLOW` are guaranteed to never be tricked by bind-mounts
/// (on new enough Linux kernels).
///
/// If you wish to resolve a magic-link, you need to unset `O_NOFOLLOW`.
/// Unfortunately (if libpathrs is using the regular host `/proc` mount), this
/// lookup mode cannot protect you against an attacker that can modify the mount
/// table during this operation.
///
/// NOTE: Instead of using paths like `/proc/thread-self/fd`, `base` is used to
/// indicate what "base path" inside procfs is used. For example, to re-open a
/// file descriptor:
///
/// ```c
/// fd = pathrs_proc_open(PATHRS_PROC_THREAD_SELF, "fd/101", O_RDWR);
/// if (fd < 0) {
///     liberr = fd; // for use with pathrs_errorinfo()
///     goto err;
/// }
/// ```
///
/// # Return Value
///
/// On success, this function returns a file descriptor. The file descriptor
/// will have the `O_CLOEXEC` flag automatically applied.
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub unsafe extern "C" fn pathrs_proc_open(
    base: CProcfsBase,
    path: *const c_char,
    flags: c_int,
) -> RawFd {
    || -> Result<_, Error> {
        let base = base.try_into()?;
        let path = unsafe { utils::parse_path(path) }?; // SAFETY: C caller guarantees path is safe.
        let oflags = OpenFlags::from_bits_retain(flags);
        let procfs = ProcfsHandle::new()?;

        match oflags.contains(OpenFlags::O_NOFOLLOW) {
            true => procfs.open(base, path, oflags),
            false => procfs.open_follow(base, path, oflags),
        }
    }()
    .map(OwnedFd::from)
    .into_c_return()
}

/// Safely read the contents of a symlink inside `/proc`.
///
/// As with `pathrs_proc_open`, any bind-mounts or other over-mounts will
/// (depending on what kernel features are available) be detected and an error
/// will be returned. Non-trailing symlinks are followed but care is taken to
/// ensure the symlinks are legitimate.
///
/// This function is effectively shorthand for
///
/// ```c
/// fd = pathrs_proc_open(base, path, O_PATH|O_NOFOLLOW);
/// if (fd < 0) {
///     liberr = fd; // for use with pathrs_errorinfo()
///     goto err;
/// }
/// copied = readlinkat(fd, "", linkbuf, linkbuf_size);
/// close(fd);
/// ```
///
/// # Return Value
///
/// On success, this function copies the symlink contents to `linkbuf` (up to
/// `linkbuf_size` bytes) and returns the full size of the symlink path buffer.
/// This function will not copy the trailing NUL byte, and the return size does
/// not include the NUL byte. A `NULL` `linkbuf` or invalid `linkbuf_size` are
/// treated as zero-size buffers.
///
/// NOTE: Unlike readlinkat(2), in the case where linkbuf is too small to
/// contain the symlink contents, pathrs_proc_readlink() will return *the number
/// of bytes it would have copied if the buffer was large enough*. This matches
/// the behaviour of pathrs_inroot_readlink().
///
/// If an error occurs, this function will return a negative error code. To
/// retrieve information about the error (such as a string describing the error,
/// the system errno(7) value associated with the error, etc), use
/// pathrs_errorinfo().
#[no_mangle]
pub unsafe extern "C" fn pathrs_proc_readlink(
    base: CProcfsBase,
    path: *const c_char,
    linkbuf: *mut c_char,
    linkbuf_size: size_t,
) -> c_int {
    || -> Result<_, Error> {
        let base = base.try_into()?;
        let path = unsafe { utils::parse_path(path) }?; // SAFETY: C caller guarantees path is safe.
        let link_target = ProcfsHandle::new()?.readlink(base, path)?;
        // SAFETY: C caller guarantees buffer is at least linkbuf_size and can
        // be written to.
        unsafe { utils::copy_path_into_buffer(link_target, linkbuf, linkbuf_size) }
    }()
    .into_c_return()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::ErrorKind, procfs::ProcfsBase};

    use pretty_assertions::assert_eq;

    #[test]
    fn procfsbase_try_from_crepr_procroot() {
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase::PATHRS_PROC_ROOT).map_err(|e| e.kind()),
            Ok(ProcfsBase::ProcRoot),
            "PATHRS_PROC_ROOT.try_into()"
        );
    }

    #[test]
    fn procfsbase_try_from_crepr_procself() {
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase::PATHRS_PROC_SELF).map_err(|e| e.kind()),
            Ok(ProcfsBase::ProcSelf),
            "PATHRS_PROC_SELF.try_into()"
        );
    }

    #[test]
    fn procfsbase_try_from_crepr_procthreadself() {
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase::PATHRS_PROC_THREAD_SELF).map_err(|e| e.kind()),
            Ok(ProcfsBase::ProcThreadSelf),
            "PATHRS_PROC_THREAD_SELF.try_into()"
        );
    }

    #[test]
    fn procfsbase_try_from_crepr_invalid() {
        // Plain values are invalid.
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(0)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "(0).try_into() -- invalid value"
        );
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(0xDEADBEEF)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "(0xDEADBEEF).try_into() -- invalid value"
        );
    }

    #[test]
    fn procfsbase_into_crepr_procroot() {
        assert_eq!(
            CProcfsBase::from(ProcfsBase::ProcRoot),
            CProcfsBase::PATHRS_PROC_ROOT,
            "ProcRoot.into() == PATHRS_PROC_ROOT"
        );
    }

    #[test]
    fn procfsbase_into_crepr_procself() {
        assert_eq!(
            CProcfsBase::from(ProcfsBase::ProcSelf),
            CProcfsBase::PATHRS_PROC_SELF,
            "ProcSelf.into() == PATHRS_PROC_SELF"
        );
    }

    #[test]
    fn procfsbase_into_crepr_procthreadself() {
        assert_eq!(
            CProcfsBase::from(ProcfsBase::ProcThreadSelf),
            CProcfsBase::PATHRS_PROC_THREAD_SELF,
            "ProcThreadSelf.into() == PATHRS_PROC_THREAD_SELF"
        );
    }

    fn check_round_trip(rust: ProcfsBase, c: CProcfsBase) {
        let c_to_rust: ProcfsBase = c.try_into().expect("should be valid value");
        assert_eq!(
            rust, c_to_rust,
            "c-to-rust ProcfsBase conversion ({c:?}.try_into())"
        );

        let rust_to_c: CProcfsBase = rust.into();
        assert_eq!(
            c, rust_to_c,
            "rust-to-c ProcfsBase conversion ({rust:?}.into())"
        );

        let c_to_rust_to_c: CProcfsBase = c_to_rust.into();
        assert_eq!(
            c, c_to_rust_to_c,
            "rust-to-c-to-rust ProcfsBase conversion ({c_to_rust:?}.into())"
        );

        let rust_to_c_to_rust: ProcfsBase = rust_to_c
            .try_into()
            .expect("must be valid value when round-tripping");
        assert_eq!(
            rust, rust_to_c_to_rust,
            "rust-to-c-to-rust ProcfsBase conversion ({rust_to_c:?}.try_into())"
        );
    }

    #[test]
    fn procfsbase_round_trip_procroot() {
        check_round_trip(ProcfsBase::ProcRoot, CProcfsBase::PATHRS_PROC_ROOT);
    }

    #[test]
    fn procfsbase_round_trip_procself() {
        check_round_trip(ProcfsBase::ProcSelf, CProcfsBase::PATHRS_PROC_SELF);
    }

    #[test]
    fn procfsbase_round_trip_procthreadself() {
        check_round_trip(
            ProcfsBase::ProcThreadSelf,
            CProcfsBase::PATHRS_PROC_THREAD_SELF,
        );
    }
}

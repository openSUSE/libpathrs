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
    error::{Error, ErrorExt, ErrorImpl},
    flags::OpenFlags,
    procfs::{ProcfsBase, ProcfsHandle},
};

use std::os::unix::io::{OwnedFd, RawFd};

use libc::{c_char, c_int, size_t};
use open_enum::open_enum;

/// Bits in `pathrs_proc_base_t` that indicate the type of the base value.
///
/// NOTE: This is used internally by libpathrs. You should avoid using this
/// macro if possible.
pub const __PATHRS_PROC_TYPE_MASK: u64 = 0xFFFF_FFFF_0000_0000;

/// Bits in `pathrs_proc_base_t` that must be set for "special" `PATHRS_PROC_*`
/// values.
const __PATHRS_PROC_TYPE_SPECIAL: u64 = 0xFFFF_FFFE_0000_0000;

// Make sure that __PATHRS_PROC_TYPE_SPECIAL only uses bits in the mask.
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL,
    __PATHRS_PROC_TYPE_SPECIAL & __PATHRS_PROC_TYPE_MASK,
);

/// Bits in `pathrs_proc_base_t` that must be set for `/proc/$pid` values. Don't
/// use this directly, instead use `PATHRS_PROC_PID(n)` to convert a PID to an
/// appropriate `pathrs_proc_base_t` value.
///
/// NOTE: This is used internally by libpathrs. You should avoid using this
/// macro if possible.
// For future-proofing the top 32 bits are blocked off by the mask, but in case
// we ever need to expand the size of pid_t (incredibly unlikely) we only use
// the top-most bit.
pub const __PATHRS_PROC_TYPE_PID: u64 = 0x8000_0000_0000_0000;

// Make sure that __PATHRS_PROC_TYPE_PID only uses bits in the mask.
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_PID,
    __PATHRS_PROC_TYPE_PID & __PATHRS_PROC_TYPE_MASK,
);

/// Indicate what base directory should be used when doing operations with
/// `pathrs_proc_*`. In addition to the values defined here, the following
/// macros can be used for other values:
///
///  * `PATHRS_PROC_PID(pid)` refers to the `/proc/<pid>` directory for the
///    process with PID (or TID) `pid`.
///
///    Note that this operation is inherently racy and should probably avoided
///    for most uses -- see the block comment above `PATHRS_PROC_PID(n)` for
///    more details.
///
/// Unknown values will result in an error being returned.
// NOTE: We need to open-code the values in the definition because cbindgen
// cannot yet evaluate constexprs (see <>) and both Go's CGo and Python's cffi
// struggle to deal with non-constant values (actually CGo struggles even with
// unsigned literals -- see <https://github.com/golang/go/issues/39136>).
#[open_enum]
#[repr(u64)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types, dead_code)]
#[allow(clippy::unusual_byte_groupings)] // FIXME: workaround for <https://github.com/rust-lang/rust-clippy/issues/15210>
pub enum CProcfsBase {
    /// Use /proc. Note that this mode may be more expensive because we have
    /// to take steps to try to avoid leaking unmasked procfs handles, so you
    /// should use PATHRS_PROC_SELF if you can.
    PATHRS_PROC_ROOT = 0xFFFF_FFFE_7072_6F63u64, // "proc"

    /// Use /proc/self. For most programs, this is the standard choice.
    PATHRS_PROC_SELF = 0xFFFF_FFFE_091D_5E1Fu64, // pid-self

    /// Use /proc/thread-self. In multi-threaded programs where one thread has a
    /// different CLONE_FS, it is possible for /proc/self to point the wrong
    /// thread and so /proc/thread-self may be necessary.
    ///
    /// NOTE: Using /proc/thread-self may require care if used from languages
    /// where your code can change threads without warning and old threads can
    /// be killed (such as Go -- where you want to use runtime.LockOSThread).
    PATHRS_PROC_THREAD_SELF = 0xFFFF_FFFE_3EAD_5E1Fu64, // thread-self
}

// Make sure the defined special values have the right type flag and the right
// values. The value checks are critical because we must not change these --
// changing them will break API compatibility silently.

static_assertions::const_assert_eq!(0xFFFFFFFE70726F63, CProcfsBase::PATHRS_PROC_ROOT.0);
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL | 0x7072_6F63,
    CProcfsBase::PATHRS_PROC_ROOT.0,
);
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL,
    CProcfsBase::PATHRS_PROC_ROOT.0 & __PATHRS_PROC_TYPE_MASK,
);

static_assertions::const_assert_eq!(0xFFFFFFFE091D5E1F, CProcfsBase::PATHRS_PROC_SELF.0);
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL | 0x091D_5E1F,
    CProcfsBase::PATHRS_PROC_SELF.0,
);
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL,
    CProcfsBase::PATHRS_PROC_SELF.0 & __PATHRS_PROC_TYPE_MASK,
);

static_assertions::const_assert_eq!(0xFFFFFFFE3EAD5E1F, CProcfsBase::PATHRS_PROC_THREAD_SELF.0);
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL | 0x3EAD_5E1F,
    CProcfsBase::PATHRS_PROC_THREAD_SELF.0,
);
static_assertions::const_assert_eq!(
    __PATHRS_PROC_TYPE_SPECIAL,
    CProcfsBase::PATHRS_PROC_THREAD_SELF.0 & __PATHRS_PROC_TYPE_MASK,
);

impl TryFrom<CProcfsBase> for ProcfsBase {
    type Error = Error;

    fn try_from(c_base: CProcfsBase) -> Result<Self, Self::Error> {
        // Cannot be used inline in a pattern.
        const U32_MAX: u64 = u32::MAX as _;
        const U32_MAX_PLUS_ONE: u64 = U32_MAX + 1;

        match c_base {
            CProcfsBase::PATHRS_PROC_ROOT => Ok(ProcfsBase::ProcRoot),
            CProcfsBase::PATHRS_PROC_SELF => Ok(ProcfsBase::ProcSelf),
            CProcfsBase::PATHRS_PROC_THREAD_SELF => Ok(ProcfsBase::ProcThreadSelf),
            CProcfsBase(arg) => match (
                arg & __PATHRS_PROC_TYPE_MASK,
                arg & !__PATHRS_PROC_TYPE_MASK,
            ) {
                // Make sure that we never run into a situation where the
                // argument value doesn't fit in a u32. If we ever need to
                // support this, we will need additional code changes.
                (_, value @ U32_MAX_PLUS_ONE..) => {
                    // This should really never actually happen, so ensure we
                    // have a compile-time check to avoid it.
                    static_assertions::const_assert_eq!(!__PATHRS_PROC_TYPE_MASK, u32::MAX as _);
                    // And mark this branch as unreachable.
                    unreachable!("the value portion of CProcfsBase({arg:#x}) cannot be larger than u32 (but {value:#x} is)");
                }

                // PATHRS_PROC_PID(pid)
                (__PATHRS_PROC_TYPE_PID, pid @ 1..=U32_MAX) => {
                    // Just make sure...
                    static_assertions::const_assert_eq!(U32_MAX, u32::MAX as u64);
                    // We can be sure it's okay to cast to u32, as we've checked
                    // statically and at runtime that the value is within the
                    // correct range to not truncate bits.
                    Ok(ProcfsBase::ProcPid(pid as u32))
                }

                // Error fallbacks for invalid subvalues or types.
                (base_type, value) => Err(ErrorImpl::InvalidArgument {
                    name: "procfs base".into(),
                    description: match base_type {
                        __PATHRS_PROC_TYPE_SPECIAL => format!("{arg:#X} is an invalid special procfs base (unknown sub-value {value:#X})"),
                        __PATHRS_PROC_TYPE_PID => format!("pid {value} is an invalid value for PATHRS_PROC_PID"),
                        _ => format!("{arg:#X} has an unknown procfs base type {base_type:#X}"),
                    }.into(),
                }.into()),
            }
            .wrap("the procfs base must be one of the PATHRS_PROC_* values or PATHRS_PROC_PID(n)")
        }
    }
}

#[cfg(test)]
impl From<ProcfsBase> for CProcfsBase {
    fn from(base: ProcfsBase) -> Self {
        match base {
            ProcfsBase::ProcPid(pid) => {
                // TODO: See if we can add some kind of static assertion that
                //       the type of the pid is not larger than the reserved
                //       block in __PATHRS_PROC_TYPE_MASK. Unfortunately Rust
                //       doesn't have a way of doing typeof(pid)... Maybe
                //       pattern_types would let us do this with something like
                //       ProcfsBase::ProcPid::0::MAX?
                //
                // static_assertions::const_assert_eq!(
                //   type_of<pid>::MAX & _PATHRS_PROC_TYPE_MASK,
                //   0,
                // );
                // static_assertions::const_assert_eq!(type_of<pid>::MAX, u32::MAX);

                // We know this to be true from the check in the above TryFrom
                // impl for ProcfsBase, but add an assertion here since we
                // cannot actually verify this statically at the moment.

                #[allow(clippy::absurd_extreme_comparisons)]
                {
                    assert!(pid <= u32::MAX, "pid in CProcfsBase must fit inside a u32");
                }
                assert_eq!(
                    pid as u64 & __PATHRS_PROC_TYPE_MASK, 0,
                    "invalid pid found when converting to CProcfsBase -- pid {pid} includes type bits ({__PATHRS_PROC_TYPE_MASK:#X})"
                );
                CProcfsBase(__PATHRS_PROC_TYPE_PID | pid as u64)
            }
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
    fn procfsbase_try_from_crepr_procpid() {
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_PID | 1)).map_err(|e| e.kind()),
            Ok(ProcfsBase::ProcPid(1)),
            "PATHRS_PROC_PID(12345).try_into()"
        );
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_PID | 12345)).map_err(|e| e.kind()),
            Ok(ProcfsBase::ProcPid(12345)),
            "PATHRS_PROC_PID(12345).try_into()"
        );
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_PID | u32::MAX as u64))
                .map_err(|e| e.kind()),
            Ok(ProcfsBase::ProcPid(u32::MAX)),
            "PATHRS_PROC_PID(u32::MAX).try_into()"
        );
    }

    #[test]
    fn procfsbase_try_from_crepr_procspecial_invalid() {
        // Invalid __PATHRS_PROC_TYPE_SPECIAL values.
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_SPECIAL)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "__PATHRS_PROC_TYPE_SPECIAL.try_into() -- invalid type"
        );
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_SPECIAL | 0xDEADBEEF))
                .map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "(__PATHRS_PROC_TYPE_SPECIAL | 0xDEADBEEF).try_into() -- invalid type"
        );
    }

    #[test]
    fn procfsbase_try_from_crepr_procpid_invalid() {
        // 0 is an invalid pid.
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_PID)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "PATHRS_PROC_PID(0).try_into() -- invalid pid"
        );
        // u32::MAX + 1 is an invalid value for multiple reasons.
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_PID | (u32::MAX as u64 + 1)))
                .map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "PATHRS_PROC_PID(u32::MAX + 1).try_into() -- invalid pid"
        );
    }

    #[test]
    fn procfsbase_try_from_crepr_proctype_invalid() {
        // Invalid __PATHRS_PROC_TYPE_MASK values.
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(0xDEAD_BEEF_0000_0001)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "0xDEAD_BEEF_0000_0001.try_into() -- invalid type"
        );
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(0xDEAD_BEEF_3EAD_5E1F)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "0xDEAD_BEEF_3EAD_5E1F.try_into() -- invalid type"
        );
        assert_eq!(
            ProcfsBase::try_from(CProcfsBase(__PATHRS_PROC_TYPE_MASK)).map_err(|e| e.kind()),
            Err(ErrorKind::InvalidArgument),
            "__PATHRS_PROC_TYPE_MASK.try_into() -- invalid type"
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

    #[test]
    fn procfsbase_into_crepr_procpid() {
        assert_eq!(
            CProcfsBase::from(ProcfsBase::ProcPid(1)),
            CProcfsBase(__PATHRS_PROC_TYPE_PID | 1),
            "ProcPid(1).into() == 1"
        );
        assert_eq!(
            CProcfsBase::from(ProcfsBase::ProcPid(1122334455)),
            CProcfsBase(__PATHRS_PROC_TYPE_PID | 1122334455),
            "ProcPid(1122334455).into() == 1122334455"
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

    #[test]
    fn procfsbase_round_trip_procpid() {
        check_round_trip(
            ProcfsBase::ProcPid(1),
            CProcfsBase(__PATHRS_PROC_TYPE_PID | 1),
        );
        check_round_trip(
            ProcfsBase::ProcPid(12345),
            CProcfsBase(__PATHRS_PROC_TYPE_PID | 12345),
        );
        check_round_trip(
            ProcfsBase::ProcPid(1122334455),
            CProcfsBase(__PATHRS_PROC_TYPE_PID | 1122334455),
        );
        check_round_trip(
            ProcfsBase::ProcPid(u32::MAX),
            CProcfsBase(__PATHRS_PROC_TYPE_PID | u32::MAX as u64),
        );
    }
}

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

//! Only used internally by libpathrs.
#![doc(hidden)]

use crate::utils::ToCString;
use crate::{Error, SyscallArg};

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::Error as IOError;
use std::os::unix::{
    ffi::OsStrExt,
    io::{FromRawFd, RawFd},
};
use std::path::{Path, PathBuf};

use failure::Error as FailureError;
use libc::{c_int, dev_t, mode_t, statfs};

// XXX: We might want to switch to nix at some point, but the interfaces
//      provided by nix are slightly non-ergonomic. I much prefer these simpler
//      C-like bindings. We also have the ability to check for support of each
//      syscall.

/// Wrapper for `fcntl(F_DUPFD_CLOEXEC)`.
///
/// This is required because [Rust's `File::try_clone` doesn't handle `O_PATH`
/// descriptors properly][bug62314]. I have [sent a PR to fix it][pr62425].
///
/// [bug62314]: https://github.com/rust-lang/rust/issues/62314
/// [pr62425]: https://github.com/rust-lang/rust/pull/62425
pub fn fcntl_dupfd_cloxec(fd: RawFd) -> Result<File, FailureError> {
    let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    let err = errno::errno();

    if fd >= 0 {
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(Error::SyscallError {
            name: "fcntl",
            args: vec![
                SyscallArg::from_fd(fd),
                SyscallArg::Raw("F_DUPFD_CLOEXEC".into()),
                SyscallArg::Raw("0".into()),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `fcntl(F_GETFD)` followed by `fcntl(F_SETFD)`, clearing the
/// `FD_CLOEXEC` bit.
///
/// This is required because Rust automatically sets `O_CLOEXEC` on all new
/// files, so we need to manually unset it when we return certain fds to the C
/// FFI (in fairness, `O_CLOEXEC` is a good default).
pub fn fcntl_unset_cloexec(fd: RawFd) -> Result<(), FailureError> {
    let old = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let err = errno::errno();

    if old < 0 {
        return Err(Error::SyscallError {
            name: "fcntl",
            args: vec![SyscallArg::from_fd(fd), SyscallArg::Raw("F_GETFD".into())],
            cause: err.into(),
        })?;
    }

    let new = old & !libc::FD_CLOEXEC;
    if new == old {
        return Ok(());
    }

    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, new) };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "fcntl",
            args: vec![
                SyscallArg::from_fd(fd),
                SyscallArg::Raw("F_SETFD".into()),
                SyscallArg::Raw(format!("0x{:x}", new)),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn openat_follow<P: AsRef<Path>>(
    dirfd: RawFd,
    path: P,
    flags: c_int,
    mode: mode_t,
) -> Result<File, FailureError> {
    let path = path.as_ref();
    let fd = unsafe {
        libc::openat(
            dirfd,
            path.to_c_string().as_ptr(),
            libc::O_CLOEXEC | flags,
            mode,
        )
    };
    let err = errno::errno();

    if fd >= 0 {
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(Error::SyscallError {
            name: "openat",
            args: vec![
                SyscallArg::from_fd(dirfd),
                SyscallArg::Path(path.into()),
                SyscallArg::Raw(format!("0x{:x}", flags)),
                SyscallArg::Raw(format!("0o{:o}", mode)),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOFOLLOW`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn openat<P: AsRef<Path>>(
    dirfd: RawFd,
    path: P,
    flags: c_int,
    mode: mode_t,
) -> Result<File, FailureError> {
    openat_follow(dirfd, path, libc::O_NOFOLLOW | flags, mode)
}

/// Wrapper for `readlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `readlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub fn readlinkat<P: AsRef<Path>>(dirfd: RawFd, path: P) -> Result<PathBuf, FailureError> {
    let path = path.as_ref();

    // If the contents of the symlink are larger than this, we raise a
    // SafetyViolation to avoid DoS vectors (because there is no way to get the
    // size of a symlink beforehand, you just have to read it).
    let mut buffer = [0 as u8; 32 * libc::PATH_MAX as usize];
    let len = unsafe {
        libc::readlinkat(
            dirfd,
            path.to_c_string().as_ptr(),
            buffer.as_mut_ptr() as *mut i8,
            buffer.len(),
        )
    };
    let mut err: IOError = errno::errno().into();
    let maybe_truncated = len >= (buffer.len() as isize);
    if len < 0 || maybe_truncated {
        if maybe_truncated {
            err = IOError::from_raw_os_error(libc::ENAMETOOLONG);
        }
        Err(Error::SyscallError {
            name: "readlinkat",
            args: vec![SyscallArg::from_fd(dirfd), SyscallArg::Path(path.into())],
            cause: err,
        })?
    } else {
        let content = OsStr::from_bytes(&buffer[..(len as usize)]);
        Ok(PathBuf::from(content))
    }
}

/// Wrapper for `mkdirat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mkdirat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn mkdirat<P: AsRef<Path>>(dirfd: RawFd, path: P, mode: mode_t) -> Result<(), FailureError> {
    let path = path.as_ref();
    let ret = unsafe { libc::mkdirat(dirfd, path.to_c_string().as_ptr(), mode) };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "mkdirat",
            args: vec![
                SyscallArg::from_fd(dirfd),
                SyscallArg::Path(path.into()),
                SyscallArg::Raw(format!("{:o}", mode)),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `mknodat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mknodat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn mknodat<P: AsRef<Path>>(
    dirfd: RawFd,
    path: P,
    mode: mode_t,
    dev: dev_t,
) -> Result<(), FailureError> {
    let path = path.as_ref();
    let ret = unsafe { libc::mknodat(dirfd, path.to_c_string().as_ptr(), mode, dev) };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "mknodat",
            args: vec![
                SyscallArg::from_fd(dirfd),
                SyscallArg::Path(path.into()),
                SyscallArg::Raw(format!("0o{:o}", mode)),
                SyscallArg::Raw(format!("0x{:x}", dev)), // TODO: Print {major, minor}.
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `unlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `unlinkat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn unlinkat<P: AsRef<Path>>(dirfd: RawFd, path: P, flags: c_int) -> Result<(), FailureError> {
    let path = path.as_ref();
    let ret = unsafe { libc::unlinkat(dirfd, path.to_c_string().as_ptr(), flags) };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "unlinkat",
            args: vec![
                SyscallArg::from_fd(dirfd),
                SyscallArg::Path(path.into()),
                SyscallArg::Raw(format!("0x{:x}", flags)),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `linkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `linkat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn linkat<P: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P,
    newdirfd: RawFd,
    newpath: P,
    flags: c_int,
) -> Result<(), FailureError> {
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    let ret = unsafe {
        libc::linkat(
            olddirfd,
            oldpath.to_c_string().as_ptr(),
            newdirfd,
            newpath.to_c_string().as_ptr(),
            flags,
        )
    };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "linkat",
            args: vec![
                SyscallArg::from_fd(olddirfd),
                SyscallArg::Path(oldpath.into()),
                SyscallArg::from_fd(newdirfd),
                SyscallArg::Path(newpath.into()),
                SyscallArg::Raw(format!("0x{:x}", flags)),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `symlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `symlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub fn symlinkat<P: AsRef<Path>>(target: P, dirfd: RawFd, path: P) -> Result<(), FailureError> {
    let (target, path) = (target.as_ref(), path.as_ref());
    let ret = unsafe {
        libc::symlinkat(
            target.to_c_string().as_ptr(),
            dirfd,
            path.to_c_string().as_ptr(),
        )
    };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "symlinkat",
            args: vec![
                SyscallArg::Path(target.into()),
                SyscallArg::from_fd(dirfd),
                SyscallArg::Path(path.into()),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `renameat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `renameat(2)`. We need the dirfd argument, so we need a wrapper.
pub fn renameat<P: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P,
    newdirfd: RawFd,
    newpath: P,
) -> Result<(), FailureError> {
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    let ret = unsafe {
        libc::renameat(
            olddirfd,
            oldpath.to_c_string().as_ptr(),
            newdirfd,
            newpath.to_c_string().as_ptr(),
        )
    };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::SyscallError {
            name: "renameat",
            args: vec![
                SyscallArg::from_fd(olddirfd),
                SyscallArg::Path(oldpath.into()),
                SyscallArg::from_fd(newdirfd),
                SyscallArg::Path(newpath.into()),
            ],
            cause: err.into(),
        })?
    }
}

lazy_static! {
    pub static ref RENAME_FLAGS_SUPPORTED: bool = {
        let ret = renameat2(
            libc::AT_FDCWD,
            ".",
            libc::AT_FDCWD,
            ".",
            libc::RENAME_EXCHANGE,
        );
        let err = errno::errno();
        // We expect EBUSY here, but just to be safe we only check for ENOSYS.
        (ret.is_ok() || err.0 != libc::ENOSYS)
    };
}

/// Wrapper for `renameat2(2)`.
///
/// This is needed because Rust doesn't provide any interface for `renameat2(2)`
/// (especially not an interface for the dirfd).
pub fn renameat2<P: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P,
    newdirfd: RawFd,
    newpath: P,
    flags: i32,
) -> Result<(), FailureError> {
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    let ret = unsafe {
        // (g)libc doesn't have a renameat2 wrapper in older versions.
        libc::syscall(
            libc::SYS_renameat2,
            olddirfd,
            oldpath.to_c_string().as_ptr(),
            newdirfd,
            newpath.to_c_string().as_ptr(),
            flags,
        )
    };
    let err = errno::errno();

    if ret >= 0 {
        Ok(())
    } else {
        if flags == 0 {
            // Fall back to renameat(2) if possible.
            return renameat(olddirfd, oldpath, newdirfd, newpath);
        }
        Err(Error::SyscallError {
            name: "renameat2",
            args: vec![
                SyscallArg::from_fd(olddirfd),
                SyscallArg::Path(oldpath.into()),
                SyscallArg::from_fd(newdirfd),
                SyscallArg::Path(newpath.into()),
                SyscallArg::Raw(format!("0x{:x}", flags)),
            ],
            cause: err.into(),
        })?
    }
}

/// Wrapper for `fstatfs(2)`.
///
/// This is needed because Rust doesn't provide any interface for `fstatfs(2)`.
pub fn fstatfs(fd: RawFd) -> Result<statfs, FailureError> {
    // repr(C) struct without internal references is definitely valid.
    let mut buf: statfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatfs(fd, &mut buf as *mut statfs) };
    let err = errno::errno();

    if ret >= 0 {
        Ok(buf)
    } else {
        Err(Error::SyscallError {
            name: "fstatfs",
            args: vec![SyscallArg::from_fd(fd)],
            cause: err.into(),
        })?
    }
}

/// WARNING: The ABI for this syscall is still being ironed out upstream. This
/// will almost certainly not work on your machine, and may cause other problems
/// depending on what syscall is using the syscall number this code will call.
pub mod unstable {
    use super::*;

    /// `OpenHow.access` field definition.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union Access {
        /// O_CREAT file mode (ignored otherwise).
        pub mode: u16,
        /// Restrict how the O_PATH may be re-opened (ignored otherwise).
        pub upgrade_mask: u16,
    }

    /// Arguments for how `openat2` should open the target path.
    ///
    /// If `extra` is zero, then `openat2` is identical to `openat`. Only one of the
    /// members of access may be set at any given time.
    #[repr(C)]
    #[derive(Clone)]
    pub struct OpenHow {
        /// O_* flags (unknown flags ignored).
        pub flags: i32,
        /// Access settings (ignored otherwise).
        pub access: Access,
        /// RESOLVE_* flags (`-EINVAL` on unknown flags).
        pub resolve: u16,
        /// Reserved for future extensions, must be zeroed.
        _reserved: [u64; 7],
    }

    impl OpenHow {
        #[inline]
        pub fn new() -> Self {
            // repr(C) struct without internal references is definitely valid.
            unsafe { std::mem::zeroed() }
        }
    }

    impl fmt::Display for OpenHow {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // self.flags
            write!(f, "{{ flags: 0x{:x}, ", self.flags)?;
            // self.access
            if self.flags & libc::O_PATH != 0 {
                write!(f, "upgrade_mask: 0x{:x}, ", unsafe {
                    self.access.upgrade_mask
                })?;
            } else if self.flags & (libc::O_CREAT | libc::O_TMPFILE) != 0 {
                write!(f, "mode: 0o{:o}, ", unsafe { self.access.mode })?;
            }
            // self.resolve
            write!(f, "resolve: 0x{:x} }}", self.resolve)
        }
    }

    /// Block mount-point crossings (including bind-mounts).
    #[allow(unused)]
    pub const RESOLVE_NO_XDEV: u16 = 0x01;

    /// Block traversal through procfs-style "magic links".
    #[allow(unused)]
    pub const RESOLVE_NO_MAGICLINKS: u16 = 0x02;

    /// Block traversal through all symlinks (implies RESOLVE_NO_MAGICLINKS).
    #[allow(unused)]
    pub const RESOLVE_NO_SYMLINKS: u16 = 0x04;

    /// Block "lexical" trickery like "..", symlinks-to-"/", and absolute paths
    /// which escape the dirfd.
    #[allow(unused)]
    pub const RESOLVE_BENEATH: u16 = 0x08;

    /// Make all jumps to "/" or ".." be scoped inside the dirfd (similar to
    /// `chroot`).
    #[allow(unused)]
    pub const RESOLVE_IN_ROOT: u16 = 0x10;

    /// Block re-opening with MAY_READ.
    #[allow(unused)]
    pub const UPGRADE_NOWRITE: u16 = 0x02;

    /// Block re-opening with MAY_READ.
    #[allow(unused)]
    pub const UPGRADE_NOREAD: u16 = 0x04;

    #[allow(non_upper_case_globals)]
    const SYS_openat2: i64 = 437;

    pub fn openat2<P: AsRef<Path>>(
        dirfd: RawFd,
        path: P,
        how: &OpenHow,
    ) -> Result<File, FailureError> {
        let path = path.as_ref();

        // Add O_CLOEXEC explicitly. No need for O_NOFOLLOW because
        // RESOLVE_IN_ROOT handles that correctly in a race-free way.
        let mut how = how.clone();
        how.flags |= libc::O_CLOEXEC;

        let fd = unsafe {
            libc::syscall(
                SYS_openat2,
                dirfd,
                path.to_c_string().as_ptr(),
                &how as *const OpenHow,
            )
        } as RawFd;
        let err = errno::errno();
        if fd >= 0 {
            Ok(unsafe { File::from_raw_fd(fd) })
        } else if err.0 == libc::EXDEV {
            Err(Error::SafetyViolation(
                "openat2 detected a potential attack",
            ))?
        } else {
            Err(Error::SyscallError {
                name: "openat2",
                args: vec![
                    SyscallArg::from_fd(dirfd),
                    SyscallArg::Path(path.into()),
                    SyscallArg::Raw(how.to_string()),
                ],
                cause: err.into(),
            })?
        }
    }
}

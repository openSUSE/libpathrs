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

// We need to permit unsafe code because we are interacting with libc APIs.
#![allow(unsafe_code)]

use crate::{
    flags::OpenFlags,
    utils::{FdExt, ToCString},
};

use std::{
    ffi::{CString, OsStr},
    fmt,
    io::Error as IOError,
    os::unix::{
        ffi::OsStrExt,
        io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    },
    path::{Path, PathBuf},
    ptr,
};

use libc::{c_int, c_uint, dev_t, mode_t, stat, statfs};

// TODO: Figure out how we can put a backtrace here (it seems we can't use
//       thiserror's backtrace support without nightly Rust because thiserror
//       wants to be able to derive an Error for Backtrace?). We could add a
//       backtrace to error::Error but if we also add a backtrace to
//       syscalls::Error this might get a little complicated.
// MSRV(1.65): Use std::backtrace::Backtrace.

// SAFETY: AT_FDCWD is always a valid file descriptor.
pub(crate) const AT_FDCWD: BorrowedFd<'static> = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
// SAFETY: BADFD is not a valid file descriptor, but it's not -1.
#[cfg(test)]
pub(crate) const BADFD: BorrowedFd<'static> = unsafe { BorrowedFd::borrow_raw(-libc::EBADF) };

// MSRV(1.70): Use OnceLock.
// MSRV(1.80): Use LazyLock.
lazy_static! {
    pub(crate) static ref OPENAT2_IS_SUPPORTED: bool =
        openat2(AT_FDCWD, ".", &Default::default()).is_ok();
}

/// Representation of a file descriptor and its associated path at a given point
/// in time.
///
/// This is primarily used to make pretty-printing syscall arguments much nicer,
/// and users really shouldn't be interacting with this directly.
///
/// # Caveats
/// Note that the file descriptor value is very unlikely to reference a live
/// file descriptor. Its value is only used for informational purposes.
#[derive(Clone, Debug)]
pub(crate) struct FrozenFd(c_int, Option<PathBuf>);

// TODO: Should probably be a pub(crate) impl.
impl<Fd: AsFd> From<Fd> for FrozenFd {
    fn from(fd: Fd) -> Self {
        // SAFETY: as_unsafe_path is safe here since it is only used for
        //         pretty-printing error messages and no real logic.
        Self(fd.as_fd().as_raw_fd(), fd.as_unsafe_path_unchecked().ok())
    }
}

impl fmt::Display for FrozenFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            libc::AT_FDCWD => write!(f, "[AT_FDCWD]")?,
            fd => write!(f, "[{}]", fd)?,
        };
        match &self.1 {
            Some(path) => write!(f, "{path:?}")?,
            None => write!(f, "<unknown>")?,
        };
        Ok(())
    }
}

/// Internal error returned by libpathrs's syscall wrappers.
///
/// The primary thing of note is that these errors contain detailed debugging
/// information about the arguments to each given syscall. Users would most
/// often not interact with these error variants directly and instead would make
/// use of the top-level [`Error`] type.
///
/// [`Error`]: crate::error::Error
#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("openat({dirfd}, {path}, 0x{flags:x}, 0o{mode:o})")]
    Openat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: OpenFlags,
        mode: u32,
        source: IOError,
    },

    #[error("openat2({dirfd}, {path}, {how}, {size})")]
    Openat2 {
        dirfd: FrozenFd,
        path: PathBuf,
        how: OpenHow,
        size: usize,
        source: IOError,
    },

    #[error("readlinkat({dirfd}, {path})")]
    Readlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        source: IOError,
    },

    #[error("mkdirat({dirfd}, {path}, 0o{mode:o})")]
    Mkdirat {
        dirfd: FrozenFd,
        path: PathBuf,
        mode: u32,
        source: IOError,
    },

    #[error("mknodat({dirfd}, {path}, 0o{mode:o}, {major}:{minor})")]
    Mknodat {
        dirfd: FrozenFd,
        path: PathBuf,
        mode: u32,
        major: u32,
        minor: u32,
        source: IOError,
    },

    #[error("unlinkat({dirfd}, {path}, 0x{flags:x})")]
    Unlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: i32,
        source: IOError,
    },

    #[error("linkat({olddirfd}, {oldpath}, {newdirfd}, {newpath}, 0x{flags:x})")]
    Linkat {
        olddirfd: FrozenFd,
        oldpath: PathBuf,
        newdirfd: FrozenFd,
        newpath: PathBuf,
        flags: i32,
        source: IOError,
    },

    #[error("symlinkat({dirfd}, {path}, {target})")]
    Symlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        target: PathBuf,
        source: IOError,
    },

    #[error("renameat({olddirfd}, {oldpath}, {newdirfd}, {newpath})")]
    Renameat {
        olddirfd: FrozenFd,
        oldpath: PathBuf,
        newdirfd: FrozenFd,
        newpath: PathBuf,
        source: IOError,
    },

    #[error("renameat2({olddirfd}, {oldpath}, {newdirfd}, {newpath}, 0x{flags:x})")]
    Renameat2 {
        olddirfd: FrozenFd,
        oldpath: PathBuf,
        newdirfd: FrozenFd,
        newpath: PathBuf,
        flags: u32,
        source: IOError,
    },

    #[error("fstatfs({fd})")]
    Fstatfs { fd: FrozenFd, source: IOError },

    #[error("fstatat({dirfd}, {path}, 0x{flags:x})")]
    Fstatat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: i32,
        source: IOError,
    },

    #[error("statx({dirfd}, {path}, flags=0x{flags:x}, mask=0x{mask:x})")]
    Statx {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: i32,
        mask: u32,
        source: IOError,
    },

    #[error("fsopen({fstype}, {flags:?})")]
    Fsopen {
        fstype: String,
        flags: FsopenFlags,
        source: IOError,
    },

    #[error("fsconfig({sfd}, FSCONFIG_CMD_CREATE)")]
    FsconfigCreate { sfd: FrozenFd, source: IOError },

    #[error("fsconfig({sfd}, FSCONFIG_SET_STRING, {key:?}, {value:?})")]
    FsconfigSetString {
        sfd: FrozenFd,
        key: String,
        value: String,
        source: IOError,
    },

    #[error("fsmount({sfd}, {flags:?}, 0x{mount_attrs:x})")]
    Fsmount {
        sfd: FrozenFd,
        flags: FsmountFlags,
        mount_attrs: u64,
        source: IOError,
    },

    #[error("open_tree({dirfd}, {path}, {flags:?})")]
    OpenTree {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: OpenTreeFlags,
        source: IOError,
    },
}

impl Error {
    pub(crate) fn root_cause(&self) -> &IOError {
        // XXX: This should probably be a macro...
        match self {
            Error::Openat { source, .. } => source,
            Error::Openat2 { source, .. } => source,
            Error::Readlinkat { source, .. } => source,
            Error::Mkdirat { source, .. } => source,
            Error::Mknodat { source, .. } => source,
            Error::Unlinkat { source, .. } => source,
            Error::Linkat { source, .. } => source,
            Error::Symlinkat { source, .. } => source,
            Error::Renameat { source, .. } => source,
            Error::Renameat2 { source, .. } => source,
            Error::Fstatfs { source, .. } => source,
            Error::Fstatat { source, .. } => source,
            Error::Statx { source, .. } => source,
            Error::Fsopen { source, .. } => source,
            Error::FsconfigCreate { source, .. } => source,
            Error::FsconfigSetString { source, .. } => source,
            Error::Fsmount { source, .. } => source,
            Error::OpenTree { source, .. } => source,
        }
    }
}

// TODO: We probably want to switch to rustix for most of these wrappers, though
//       the interfaces provided by rustix are slightly non-ergonomic. I much
//       prefer these simpler C-like bindings. We also have the ability to check
//       for support of each syscall.

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOCTTY`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn openat_follow<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    flags: c_int,
    mode: mode_t,
) -> Result<OwnedFd, Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    let flags = libc::O_CLOEXEC | libc::O_NOCTTY | flags;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe { libc::openat(dirfd.as_raw_fd(), path.to_c_string().as_ptr(), flags, mode) };
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(Error::Openat {
            dirfd: dirfd.into(),
            path: path.into(),
            flags: OpenFlags::from_bits_retain(flags),
            mode,
            source: err,
        })
    }
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOCTTY | O_NOFOLLOW`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn openat<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    flags: c_int,
    mode: mode_t,
) -> Result<OwnedFd, Error> {
    openat_follow(dirfd, path, libc::O_NOFOLLOW | flags, mode)
}

/// Wrapper for `readlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `readlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub(crate) fn readlinkat<Fd: AsFd, P: AsRef<Path>>(dirfd: Fd, path: P) -> Result<PathBuf, Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();

    // If the contents of the symlink are larger than this, we raise a
    // SafetyViolation to avoid DoS vectors (because there is no way to get the
    // size of a symlink beforehand, you just have to read it).
    let mut buffer = [0_u8; 32 * libc::PATH_MAX as usize];
    // SAFETY: Obviously safe-to-use Linux syscall.
    let len = unsafe {
        libc::readlinkat(
            dirfd.as_raw_fd(),
            path.to_c_string().as_ptr(),
            buffer.as_mut_ptr() as *mut i8,
            buffer.len(),
        )
    };
    let mut err = IOError::last_os_error();
    let maybe_truncated = len >= (buffer.len() as isize);
    if len < 0 || maybe_truncated {
        if maybe_truncated {
            err = IOError::from_raw_os_error(libc::ENAMETOOLONG);
        }
        Err(Error::Readlinkat {
            dirfd: dirfd.into(),
            path: path.into(),
            source: err,
        })
    } else {
        let content = OsStr::from_bytes(&buffer[..(len as usize)]);
        Ok(PathBuf::from(content))
    }
}

/// Wrapper for `mkdirat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mkdirat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn mkdirat<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    mode: mode_t,
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::mkdirat(dirfd.as_raw_fd(), path.to_c_string().as_ptr(), mode) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::Mkdirat {
            dirfd: dirfd.into(),
            path: path.into(),
            mode,
            source: err,
        })
    }
}

pub(crate) fn devmajorminor(dev: dev_t) -> (c_uint, c_uint) {
    // SAFETY: Obviously safe-to-use libc function.
    unsafe { (libc::major(dev), libc::minor(dev)) }
}

/// Wrapper for `mknodat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mknodat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn mknodat<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    mode: mode_t,
    dev: dev_t,
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::mknodat(dirfd.as_raw_fd(), path.to_c_string().as_ptr(), mode, dev) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        let (major, minor) = devmajorminor(dev);
        Err(Error::Mknodat {
            dirfd: dirfd.into(),
            path: path.into(),
            mode,
            major,
            minor,
            source: err,
        })
    }
}

/// Wrapper for `unlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `unlinkat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn unlinkat<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    flags: c_int,
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::unlinkat(dirfd.as_raw_fd(), path.to_c_string().as_ptr(), flags) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::Unlinkat {
            dirfd: dirfd.into(),
            path: path.into(),
            flags,
            source: err,
        })
    }
}

/// Wrapper for `linkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `linkat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn linkat<Fd1: AsFd, P1: AsRef<Path>, Fd2: AsFd, P2: AsRef<Path>>(
    olddirfd: Fd1,
    oldpath: P1,
    newdirfd: Fd2,
    newpath: P2,
    flags: c_int,
) -> Result<(), Error> {
    let (olddirfd, newdirfd) = (olddirfd.as_fd(), newdirfd.as_fd());
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::linkat(
            olddirfd.as_raw_fd(),
            oldpath.to_c_string().as_ptr(),
            newdirfd.as_raw_fd(),
            newpath.to_c_string().as_ptr(),
            flags,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::Linkat {
            olddirfd: olddirfd.into(),
            oldpath: oldpath.into(),
            newdirfd: newdirfd.into(),
            newpath: newpath.into(),
            flags,
            source: err,
        })
    }
}

/// Wrapper for `symlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `symlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub(crate) fn symlinkat<P1: AsRef<Path>, Fd: AsFd, P2: AsRef<Path>>(
    target: P1,
    dirfd: Fd,
    path: P2,
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd();
    let (target, path) = (target.as_ref(), path.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::symlinkat(
            target.to_c_string().as_ptr(),
            dirfd.as_raw_fd(),
            path.to_c_string().as_ptr(),
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::Symlinkat {
            dirfd: dirfd.into(),
            path: path.into(),
            target: target.into(),
            source: err,
        })
    }
}

/// Wrapper for `renameat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `renameat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn renameat<Fd1: AsFd, P1: AsRef<Path>, Fd2: AsFd, P2: AsRef<Path>>(
    olddirfd: Fd1,
    oldpath: P1,
    newdirfd: Fd2,
    newpath: P2,
) -> Result<(), Error> {
    let (olddirfd, newdirfd) = (olddirfd.as_fd(), newdirfd.as_fd());
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::renameat(
            olddirfd.as_raw_fd(),
            oldpath.to_c_string().as_ptr(),
            newdirfd.as_raw_fd(),
            newpath.to_c_string().as_ptr(),
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::Renameat {
            olddirfd: olddirfd.into(),
            oldpath: oldpath.into(),
            newdirfd: newdirfd.into(),
            newpath: newpath.into(),
            source: err,
        })
    }
}

// MSRV(1.70): Use OnceLock.
// MSRV(1.80): Use LazyLock.
lazy_static! {
    pub(crate) static ref RENAME_FLAGS_SUPPORTED: bool = {
        match renameat2(
            AT_FDCWD,
            ".",
            AT_FDCWD,
            ".",
            libc::RENAME_EXCHANGE,
        ) {
            Ok(_) => true,
            // We expect EBUSY, but just to be safe we only check for ENOSYS.
            Err(err) => err.root_cause().raw_os_error() != Some(libc::ENOSYS),
        }
    };
}

/// Wrapper for `renameat2(2)`.
///
/// This is needed because Rust doesn't provide any interface for `renameat2(2)`
/// (especially not an interface for the dirfd).
pub(crate) fn renameat2<Fd1: AsFd, P1: AsRef<Path>, Fd2: AsFd, P2: AsRef<Path>>(
    olddirfd: Fd1,
    oldpath: P1,
    newdirfd: Fd2,
    newpath: P2,
    flags: c_uint,
) -> Result<(), Error> {
    // Use renameat(2) if no flags are specified.
    if flags == 0 {
        return renameat(olddirfd, oldpath, newdirfd, newpath);
    }

    let (olddirfd, newdirfd) = (olddirfd.as_fd(), newdirfd.as_fd());
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::renameat2(
            olddirfd.as_raw_fd(),
            oldpath.to_c_string().as_ptr(),
            newdirfd.as_raw_fd(),
            newpath.to_c_string().as_ptr(),
            flags,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::Renameat2 {
            olddirfd: olddirfd.into(),
            oldpath: oldpath.into(),
            newdirfd: newdirfd.into(),
            newpath: newpath.into(),
            flags,
            source: err,
        })
    }
}

/// Wrapper for `fstatfs(2)`.
///
/// This is needed because Rust doesn't provide any interface for `fstatfs(2)`.
pub(crate) fn fstatfs<Fd: AsFd>(fd: Fd) -> Result<statfs, Error> {
    // SAFETY: repr(C) struct without internal references is definitely valid. C
    //         callers are expected to zero it as well.
    let mut buf: statfs = unsafe { std::mem::zeroed() };
    let fd = fd.as_fd();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::fstatfs(fd.as_raw_fd(), &mut buf as *mut statfs) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(buf)
    } else {
        Err(Error::Fstatfs {
            fd: fd.into(),
            source: err,
        })
    }
}

/// Wrapper for `fstatat(2)`, which auto-sets `AT_NO_AUTOMOUNT |
/// AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH`.
///
/// This is needed because Rust doesn't provide any interface for `fstatat(2)`.
pub(crate) fn fstatat<Fd: AsFd, P: AsRef<Path>>(dirfd: Fd, path: P) -> Result<stat, Error> {
    // SAFETY: repr(C) struct without internal references is definitely valid. C
    //         callers are expected to zero it as well.
    let mut buf: stat = unsafe { std::mem::zeroed() };
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    let flags = libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::fstatat(
            dirfd.as_raw_fd(),
            path.to_c_string().as_ptr(),
            &mut buf as *mut stat,
            flags,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(buf)
    } else {
        Err(Error::Fstatat {
            dirfd: dirfd.into(),
            path: path.into(),
            flags,
            source: err,
        })
    }
}

pub(crate) fn statx<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    mask: u32,
) -> Result<libc::statx, Error> {
    // SAFETY: repr(C) struct without internal references is definitely valid. C
    //         callers are expected to zero it as well.
    let mut buf: libc::statx = unsafe { std::mem::zeroed() };
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    let flags = libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::statx(
            dirfd.as_raw_fd(),
            path.to_c_string().as_ptr(),
            flags,
            mask,
            &mut buf as *mut _,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(buf)
    } else {
        Err(Error::Statx {
            dirfd: dirfd.into(),
            path: path.into(),
            flags,
            mask,
            source: err,
        })
    }
}

bitflags! {
    /// Wrapper for the underlying `libc`'s `RESOLVE_*` flags.
    ///
    /// The flag values and their meaning is identical to the description in the
    /// [`openat2(2)`] man page.
    ///
    /// [`openat2(2)`]: http://man7.org/linux/man-pages/man2/openat2.2.html
    #[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
    struct ResolveFlags: u64 {
        const RESOLVE_BENEATH = libc::RESOLVE_BENEATH;
        const RESOLVE_IN_ROOT = libc::RESOLVE_IN_ROOT;
        const RESOLVE_NO_MAGICLINKS = libc::RESOLVE_NO_MAGICLINKS;
        const RESOLVE_NO_SYMLINKS = libc::RESOLVE_NO_SYMLINKS;
        const RESOLVE_NO_XDEV = libc::RESOLVE_NO_XDEV;
        const RESOLVE_CACHED = libc::RESOLVE_CACHED;

        // Don't clobber unknown RESOLVE_* bits.
        const _ = !0;
    }
}

/// Arguments for how `openat2` should open the target path.
// TODO: Maybe switch to libc::open_how?
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct OpenHow {
    /// O_* flags (`-EINVAL` on unknown or incompatible flags).
    pub flags: u64,
    /// O_CREAT or O_TMPFILE file mode (must be zero otherwise).
    pub mode: u64,
    /// RESOLVE_* flags (`-EINVAL` on unknown flags).
    pub resolve: u64,
}

impl fmt::Display for OpenHow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ ")?;
        // self.flags
        if let Ok(oflags) = i32::try_from(self.flags) {
            // If the flags can fit inside OpenFlags, pretty-print the flags.
            write!(f, "flags: {:?}, ", OpenFlags::from_bits_retain(oflags))?;
        } else {
            write!(f, "flags: 0x{:x}, ", self.flags)?;
        }
        if self.flags & (libc::O_CREAT | libc::O_TMPFILE) as u64 != 0 {
            write!(f, "mode: 0o{:o}, ", self.mode)?;
        }
        // self.resolve
        write!(
            f,
            "resolve: {:?}",
            ResolveFlags::from_bits_retain(self.resolve)
        )?;
        write!(f, " }}")
    }
}

pub(crate) fn openat2<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    how: &OpenHow,
) -> Result<OwnedFd, Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();

    // Add O_CLOEXEC explicitly. No need for O_NOFOLLOW because
    // RESOLVE_IN_ROOT handles that correctly in a race-free way.
    let mut how = how.clone();
    how.flags |= libc::O_CLOEXEC as u64;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd.as_raw_fd(),
            path.to_c_string().as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    } as RawFd;
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(Error::Openat2 {
            dirfd: dirfd.into(),
            path: path.into(),
            how,
            size: std::mem::size_of::<OpenHow>(),
            source: err,
        })
    }
}

#[cfg(test)]
pub(crate) fn getpid() -> libc::pid_t {
    // SAFETY: Obviously safe libc function.
    unsafe { libc::getpid() }
}

pub(crate) fn gettid() -> libc::pid_t {
    // SAFETY: Obviously safe libc function.
    unsafe { libc::gettid() }
}

pub(crate) fn geteuid() -> libc::uid_t {
    // SAFETY: Obviously safe libc function.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
pub(crate) fn getegid() -> libc::gid_t {
    // SAFETY: Obviously safe libc function.
    unsafe { libc::getegid() }
}

#[cfg(test)]
pub(crate) fn getcwd() -> Result<PathBuf, anyhow::Error> {
    let buffer = Vec::with_capacity(libc::PATH_MAX as usize);
    Ok(OsStr::from_bytes(rustix::process::getcwd(buffer)?.to_bytes()).into())
}

bitflags! {
    #[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
    pub struct FsopenFlags: i32 {
        const FSOPEN_CLOEXEC = 0x1;
    }

    #[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
    pub struct FsmountFlags: i32 {
        const FSMOUNT_CLOEXEC = 0x1;
    }

    #[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
    pub struct OpenTreeFlags: i32 {
        const AT_RECURSIVE = libc::AT_RECURSIVE;
        const OPEN_TREE_CLOEXEC = libc::O_CLOEXEC;
        const OPEN_TREE_CLONE = 0x1;
    }
}

#[repr(i32)]
#[allow(dead_code)]
enum FsconfigCmd {
    SetFlag = 0x0,      // FSCONFIG_SET_FLAG
    SetString = 0x1,    // FSCONFIG_SET_STRING
    SetBinary = 0x2,    // FSCONFIG_SET_BINARY
    SetPath = 0x3,      // FSCONFIG_SET_PATH
    SetPathEmpty = 0x4, // FSCONFIG_SET_PATH_EMPTY
    SetFd = 0x5,        // FSCONFIG_SET_FD
    Create = 0x6,       // FSCONFIG_CREATE
    Reconfigure = 0x7,  // FSCONFIG_RECONFIGURE
}

pub(crate) fn fsopen<S: AsRef<str>>(fstype: S, flags: FsopenFlags) -> Result<OwnedFd, Error> {
    let fstype = fstype.as_ref();
    let c_fstype = CString::new(fstype).expect("fsopen argument should be valid C string");

    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe { libc::syscall(libc::SYS_fsopen, c_fstype.as_ptr(), flags.bits()) } as RawFd;
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(Error::Fsopen {
            fstype: fstype.into(),
            flags,
            source: err,
        })
    }
}

pub(crate) fn fsconfig_set_string<Fd: AsFd, K: AsRef<str>, V: AsRef<str>>(
    sfd: Fd,
    key: K,
    value: V,
) -> Result<(), Error> {
    let sfd = sfd.as_fd();
    let key = key.as_ref();
    let c_key = CString::new(key).expect("fsconfig_set_string key should be valid C string");
    let value = value.as_ref();
    let c_value = CString::new(value).expect("fsconfig_set_string value should be valid C string");

    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            sfd.as_raw_fd(),
            FsconfigCmd::SetString,
            c_key.as_ptr(),
            c_value.as_ptr(),
            0,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::FsconfigSetString {
            sfd: sfd.into(),
            key: key.into(),
            value: value.into(),
            source: err,
        })
    }
}

// clippy doesn't understand that we need to specify a type for ptr::null() here
// because libc::syscall() is variadic.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn fsconfig_create<Fd: AsFd>(sfd: Fd) -> Result<(), Error> {
    let sfd = sfd.as_fd();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            sfd.as_raw_fd(),
            FsconfigCmd::Create,
            ptr::null() as *const (),
            ptr::null() as *const (),
            0,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(Error::FsconfigCreate {
            sfd: sfd.into(),
            source: err,
        })
    }
}

pub(crate) fn fsmount<Fd: AsFd>(
    sfd: Fd,
    flags: FsmountFlags,
    mount_attrs: u64,
) -> Result<OwnedFd, Error> {
    let sfd = sfd.as_fd();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            sfd.as_raw_fd(),
            flags.bits(),
            mount_attrs,
        )
    } as RawFd;
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(Error::Fsmount {
            sfd: sfd.into(),
            flags,
            mount_attrs,
            source: err,
        })
    }
}

pub(crate) fn open_tree<Fd: AsFd, P: AsRef<Path>>(
    dirfd: Fd,
    path: P,
    flags: OpenTreeFlags,
) -> Result<OwnedFd, Error> {
    let dirfd = dirfd.as_fd();
    let path = path.as_ref();
    let c_path = path.to_c_string();

    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            dirfd.as_raw_fd(),
            c_path.as_ptr(),
            flags.bits(),
        )
    } as RawFd;
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        Err(Error::OpenTree {
            dirfd: dirfd.into(),
            path: path.into(),
            flags,
            source: err,
        })
    }
}

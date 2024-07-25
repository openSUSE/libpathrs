/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as pub(crate)lished by the Free
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

// We need to permit unsafe code because we are interacting with libc APIs.
#![allow(unsafe_code)]

use crate::utils::{RawFdExt, ToCString};

use std::{
    backtrace::Backtrace,
    ffi::OsStr,
    fmt,
    fs::File,
    io::Error as IOError,
    os::unix::{
        ffi::OsStrExt,
        io::{FromRawFd, RawFd},
    },
    path::{Path, PathBuf},
};

use libc::{c_int, dev_t, mode_t, stat, statfs};
use snafu::ResultExt;

/// Representation of a file descriptor and its associated path at a given point
/// in time.
///
/// This is primarily used to make pretty-printing syscall arguments much nicer,
/// and users really shouldn't be interacting with this directly.
///
/// # Caveats
/// Note that the file descriptor value is very unlikely to reference a live
/// file descriptor. Its value is only used for informational purposes.
// TODO: Should probably be #[doc(hidden)].
#[derive(Clone, Debug)]
pub struct FrozenFd(c_int, Option<PathBuf>);

// TODO: Should probably be a pub(crate) impl.
impl From<RawFd> for FrozenFd {
    fn from(fd: RawFd) -> Self {
        if fd < 0 {
            FrozenFd(fd, None)
        } else {
            // SAFETY: as_unsafe_path is safe here since it is only used for
            //         pretty-printing error messages and no real logic.
            FrozenFd(fd, fd.as_unsafe_path().ok())
        }
    }
}

impl fmt::Display for FrozenFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            libc::AT_FDCWD => write!(f, "[AT_FDCWD]")?,
            fd => write!(f, "[{}]", fd)?,
        };
        match &self.1 {
            Some(path) => write!(f, "{:?}", path)?,
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
/// [`Error`]: enum.Error.html
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("fcntl({}, F_DUPFD_CLOEXEC, 0): {}", fd, source))]
    FcntlDup {
        fd: FrozenFd,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("fcntl({}, F_GETFD): {}", fd, source))]
    FcntlGetFlags {
        fd: FrozenFd,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("fcntl({}, F_SETFD, 0x{:x}): {}", fd, flags, source))]
    FcntlSetFlags {
        fd: FrozenFd,
        flags: i32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display(
        "openat({}, {:?}, 0x{:x}, 0o{:o}): {}",
        dirfd,
        path,
        flags,
        mode,
        source
    ))]
    Openat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: i32,
        mode: u32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("openat2({}, {:?}, {}, {}): {}", dirfd, path, how, size, source))]
    Openat2 {
        dirfd: FrozenFd,
        path: PathBuf,
        how: OpenHow,
        size: usize,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("readlinkat({}, {:?}): {}", dirfd, path, source))]
    Readlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("mkdirat({}, {:?}, 0o{:o}): {}", dirfd, path, mode, source))]
    Mkdirat {
        dirfd: FrozenFd,
        path: PathBuf,
        mode: u32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display(
        "mknodat({}, {:?}, 0o{:o}, {}:{}): {}",
        dirfd,
        path,
        mode,
        major,
        minor,
        source
    ))]
    Mknodat {
        dirfd: FrozenFd,
        path: PathBuf,
        mode: u32,
        major: u32,
        minor: u32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("unlinkat({}, {:?}, 0x{:x}): {}", dirfd, path, flags, source))]
    Unlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: i32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display(
        "linkat({}, {:?}, {}, {:?}, 0x{:x}): {}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags,
        source
    ))]
    Linkat {
        olddirfd: FrozenFd,
        oldpath: PathBuf,
        newdirfd: FrozenFd,
        newpath: PathBuf,
        flags: i32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("symlinkat({:?}, {}, {:?}): {}", target, dirfd, path, source))]
    Symlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        target: PathBuf,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display(
        "renameat({}, {:?}, {}, {:?}): {}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        source
    ))]
    Renameat {
        olddirfd: FrozenFd,
        oldpath: PathBuf,
        newdirfd: FrozenFd,
        newpath: PathBuf,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display(
        "renameat2({}, {:?}, {}, {:?}, 0x{:x}): {}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags,
        source
    ))]
    Renameat2 {
        olddirfd: FrozenFd,
        oldpath: PathBuf,
        newdirfd: FrozenFd,
        newpath: PathBuf,
        flags: u32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("fstatfs({}): {}", fd, source))]
    Fstatfs {
        fd: FrozenFd,
        source: IOError,
        backtrace: Option<Backtrace>,
    },

    #[snafu(display("fstatat({}, {:?}, 0x{:x}): {}", dirfd, path, flags, source))]
    Fstatat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: i32,
        source: IOError,
        backtrace: Option<Backtrace>,
    },
}

impl Error {
    pub(crate) fn root_cause(&self) -> &IOError {
        // XXX: This should probably be a macro...
        match self {
            Error::FcntlDup { source, .. } => source,
            Error::FcntlGetFlags { source, .. } => source,
            Error::FcntlSetFlags { source, .. } => source,
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
        }
    }
}

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
pub(crate) fn fcntl_dupfd_cloxec(fd: RawFd) -> Result<File, Error> {
    // SAFETY: Obviously safe-to-use Linux syscall.
    let newfd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    let err = IOError::last_os_error();

    if newfd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { File::from_raw_fd(newfd) })
    } else {
        Err(err).context(FcntlDupSnafu { fd })
    }
}

/// Wrapper for `fcntl(F_GETFD)` followed by `fcntl(F_SETFD)`, clearing the
/// `FD_CLOEXEC` bit.
///
/// This is required because Rust automatically sets `O_CLOEXEC` on all new
/// files, so we need to manually unset it when we return certain fds to the C
/// FFI (in fairness, `O_CLOEXEC` is a good default).
pub(crate) fn fcntl_unset_cloexec(fd: RawFd) -> Result<(), Error> {
    // SAFETY: Obviously safe-to-use Linux syscall.
    let old = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let err = IOError::last_os_error();

    if old < 0 {
        return Err(err).context(FcntlGetFlagsSnafu { fd });
    }

    let new = old & !libc::FD_CLOEXEC;
    if new == old {
        return Ok(());
    }

    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, new) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(FcntlSetFlagsSnafu { fd, flags: new })
    }
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOCTTY`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn openat_follow<P: AsRef<Path>>(
    dirfd: RawFd,
    path: P,
    flags: c_int,
    mode: mode_t,
) -> Result<File, Error> {
    let path = path.as_ref();
    let flags = libc::O_CLOEXEC | libc::O_NOCTTY | flags;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe { libc::openat(dirfd, path.to_c_string().as_ptr(), flags, mode) };
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(err).context(OpenatSnafu {
            dirfd,
            path,
            flags,
            mode,
        })
    }
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOCTTY | O_NOFOLLOW`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn openat<P: AsRef<Path>>(
    dirfd: RawFd,
    path: P,
    flags: c_int,
    mode: mode_t,
) -> Result<File, Error> {
    openat_follow(dirfd, path, libc::O_NOFOLLOW | flags, mode)
}

/// Wrapper for `readlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `readlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub(crate) fn readlinkat<P: AsRef<Path>>(dirfd: RawFd, path: P) -> Result<PathBuf, Error> {
    let path = path.as_ref();

    // If the contents of the symlink are larger than this, we raise a
    // SafetyViolation to avoid DoS vectors (because there is no way to get the
    // size of a symlink beforehand, you just have to read it).
    let mut buffer = [0_u8; 32 * libc::PATH_MAX as usize];
    // SAFETY: Obviously safe-to-use Linux syscall.
    let len = unsafe {
        libc::readlinkat(
            dirfd,
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
        Err(err).context(ReadlinkatSnafu { dirfd, path })
    } else {
        let content = OsStr::from_bytes(&buffer[..(len as usize)]);
        Ok(PathBuf::from(content))
    }
}

/// Wrapper for `mkdirat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mkdirat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn mkdirat<P: AsRef<Path>>(dirfd: RawFd, path: P, mode: mode_t) -> Result<(), Error> {
    let path = path.as_ref();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::mkdirat(dirfd, path.to_c_string().as_ptr(), mode) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(MkdiratSnafu { dirfd, path, mode })
    }
}

/// Wrapper for `mknodat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mknodat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn mknodat<P: AsRef<Path>>(
    dirfd: RawFd,
    path: P,
    mode: mode_t,
    dev: dev_t,
) -> Result<(), Error> {
    let path = path.as_ref();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::mknodat(dirfd, path.to_c_string().as_ptr(), mode, dev) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(MknodatSnafu {
            dirfd,
            path,
            mode,
            // SAFETY: Obviously safe-to-use libc function.
            major: unsafe { libc::major(dev) },
            // SAFETY: Obviously safe-to-use libc function.
            minor: unsafe { libc::minor(dev) },
        })
    }
}

/// Wrapper for `unlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `unlinkat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn unlinkat<P: AsRef<Path>>(dirfd: RawFd, path: P, flags: c_int) -> Result<(), Error> {
    let path = path.as_ref();
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::unlinkat(dirfd, path.to_c_string().as_ptr(), flags) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(UnlinkatSnafu { dirfd, path, flags })
    }
}

/// Wrapper for `linkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `linkat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn linkat<P: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P,
    newdirfd: RawFd,
    newpath: P,
    flags: c_int,
) -> Result<(), Error> {
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::linkat(
            olddirfd,
            oldpath.to_c_string().as_ptr(),
            newdirfd,
            newpath.to_c_string().as_ptr(),
            flags,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(LinkatSnafu {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        })
    }
}

/// Wrapper for `symlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `symlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub(crate) fn symlinkat<P: AsRef<Path>>(target: P, dirfd: RawFd, path: P) -> Result<(), Error> {
    let (target, path) = (target.as_ref(), path.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::symlinkat(
            target.to_c_string().as_ptr(),
            dirfd,
            path.to_c_string().as_ptr(),
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(SymlinkatSnafu {
            dirfd,
            path,
            target,
        })
    }
}

/// Wrapper for `renameat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `renameat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn renameat<P: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P,
    newdirfd: RawFd,
    newpath: P,
) -> Result<(), Error> {
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::renameat(
            olddirfd,
            oldpath.to_c_string().as_ptr(),
            newdirfd,
            newpath.to_c_string().as_ptr(),
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err).context(RenameatSnafu {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
        })
    }
}

lazy_static! {
    pub(crate) static ref RENAME_FLAGS_SUPPORTED: bool = {
        match renameat2(
            libc::AT_FDCWD,
            ".",
            libc::AT_FDCWD,
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
pub(crate) fn renameat2<P: AsRef<Path>>(
    olddirfd: RawFd,
    oldpath: P,
    newdirfd: RawFd,
    newpath: P,
    flags: libc::c_uint,
) -> Result<(), Error> {
    let (oldpath, newpath) = (oldpath.as_ref(), newpath.as_ref());
    // SAFETY: Obviously safe-to-use Linux syscall.
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
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        if flags == 0 {
            // Fall back to renameat(2) if possible.
            return renameat(olddirfd, oldpath, newdirfd, newpath);
        }
        Err(err).context(Renameat2Snafu {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        })
    }
}

/// Wrapper for `fstatfs(2)`.
///
/// This is needed because Rust doesn't provide any interface for `fstatfs(2)`.
pub(crate) fn fstatfs(fd: RawFd) -> Result<statfs, Error> {
    // SAFETY: repr(C) struct without internal references is definitely valid. C
    //         callers are expected to zero it as well.
    let mut buf: statfs = unsafe { std::mem::zeroed() };
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::fstatfs(fd, &mut buf as *mut statfs) };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(buf)
    } else {
        Err(err).context(FstatfsSnafu { fd })
    }
}

/// Wrapper for `fstatat(2)`, which auto-sets `AT_NO_AUTOMOUNT |
/// AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH`.
///
/// This is needed because Rust doesn't provide any interface for `fstatat(2)`.
pub(crate) fn fstatat<P: AsRef<Path>>(dirfd: RawFd, path: P) -> Result<stat, Error> {
    // SAFETY: repr(C) struct without internal references is definitely valid. C
    //         callers are expected to zero it as well.
    let mut buf: stat = unsafe { std::mem::zeroed() };
    let path = path.as_ref();
    let flags = libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe {
        libc::fstatat(
            dirfd,
            path.to_c_string().as_ptr(),
            &mut buf as *mut stat,
            flags,
        )
    };
    let err = IOError::last_os_error();

    if ret >= 0 {
        Ok(buf)
    } else {
        Err(err).context(FstatatSnafu { dirfd, path, flags })
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
        // self.flags
        write!(f, "{{ flags: 0x{:x}, ", self.flags)?;
        if self.flags & (libc::O_CREAT | libc::O_TMPFILE) as u64 != 0 {
            write!(f, "mode: 0o{:o}, ", self.mode)?;
        }
        // self.resolve
        write!(f, "resolve: 0x{:x} }}", self.resolve)
    }
}

pub fn openat2<P: AsRef<Path>>(dirfd: RawFd, path: P, how: &OpenHow) -> Result<File, Error> {
    let path = path.as_ref();

    // Add O_CLOEXEC explicitly. No need for O_NOFOLLOW because
    // RESOLVE_IN_ROOT handles that correctly in a race-free way.
    let mut how = how.clone();
    how.flags |= libc::O_CLOEXEC as u64;

    // SAFETY: Obviously safe-to-use Linux syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.to_c_string().as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    } as RawFd;
    let err = IOError::last_os_error();

    if fd >= 0 {
        // SAFETY: We know it's a real file descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(err).context(Openat2Snafu {
            dirfd,
            path,
            how,
            size: std::mem::size_of::<OpenHow>(),
        })
    }
}

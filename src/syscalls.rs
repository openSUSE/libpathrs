// SPDX-License-Identifier: MPL-2.0 OR LGPL-3.0-or-later
/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2025 SUSE LLC
 * Copyright (C) 2026 Aleksa Sarai <cyphar@cyphar.com>
 *
 * == MPL-2.0 ==
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Alternatively, this Source Code Form may also (at your option) be used
 * under the terms of the GNU Lesser General Public License Version 3, as
 * described below:
 *
 * == LGPL-3.0-or-later ==
 *
 *  This program is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License  for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// We need to permit unsafe code because we are interacting with libc APIs.
#![allow(unsafe_code)]

use crate::{
    flags::{OpenFlags, RenameFlags},
    utils::{FdExt, ToCString},
};

use std::{
    borrow::Cow,
    ffi::OsStr,
    fmt,
    io::Error as IOError,
    mem::MaybeUninit,
    os::unix::{
        ffi::OsStrExt,
        io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    },
    path::{Path, PathBuf},
};

use bitflags::bitflags;
use once_cell::sync::Lazy;
use rustix::{
    fs::{
        self as rustix_fs, Access, AtFlags, Dev, FileType, Mode, RawMode, Stat, StatFs, Statx,
        StatxFlags,
    },
    io::Errno,
    mount::{self as rustix_mount, FsMountFlags, FsOpenFlags, MountAttrFlags, OpenTreeFlags},
    process::{self as rustix_process, DumpableBehavior},
    thread as rustix_thread,
};

// TODO: Figure out how we can put a backtrace here (it seems we can't use
//       thiserror's backtrace support without nightly Rust because thiserror
//       wants to be able to derive an Error for Backtrace?). We could add a
//       backtrace to error::Error but if we also add a backtrace to
//       syscalls::Error this might get a little complicated.
// MSRV(1.65): Use std::backtrace::Backtrace.

// SAFETY: AT_FDCWD is always a valid file descriptor.
pub(crate) const AT_FDCWD: BorrowedFd<'static> = rustix_fs::CWD;
// SAFETY: BADFD is not a valid file descriptor, but it's not -1.
pub(crate) const BADFD: BorrowedFd<'static> = unsafe { BorrowedFd::borrow_raw(-libc::EBADF) };

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
pub(crate) struct FrozenFd(RawFd, Option<PathBuf>);

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
            fd => write!(f, "[{fd}]")?,
        };
        match &self.1 {
            Some(path) => write!(f, "<{path:?}>")?,
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
    // NOTE: This is temporary until the issue is fixed in rustix.
    #[error("invalid file descriptor {fd} (see <https://github.com/bytecodealliance/rustix/issues/1187> for more details)")]
    InvalidFd { fd: RawFd, source: Errno },

    #[error("accessat({dirfd}, {path:?}, {access:?}, {flags:?})")]
    Accessat {
        dirfd: FrozenFd,
        path: PathBuf,
        access: Access,
        flags: AtFlags,
        source: Errno,
    },

    #[error("openat({dirfd}, {path:?}, {flags:?}, 0o{mode:o})")]
    Openat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: OpenFlags,
        mode: u32,
        source: Errno,
    },

    #[error("openat2({dirfd}, {path:?}, {how}, {size})")]
    Openat2 {
        dirfd: FrozenFd,
        path: PathBuf,
        how: OpenHow,
        size: usize,
        source: Errno,
    },

    #[error("readlinkat({dirfd}, {path:?})")]
    Readlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        source: Errno,
    },

    #[error("mkdirat({dirfd}, {path:?}, 0o{mode:o})")]
    Mkdirat {
        dirfd: FrozenFd,
        path: PathBuf,
        mode: u32,
        source: Errno,
    },

    #[error("mknodat({dirfd}, {path:?}, 0o{mode:o}, {major}:{minor})")]
    Mknodat {
        dirfd: FrozenFd,
        path: PathBuf,
        mode: u32,
        major: u32,
        minor: u32,
        source: Errno,
    },

    #[error("unlinkat({dirfd}, {path:?}, {flags:?})")]
    Unlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: AtFlags,
        source: Errno,
    },

    #[error("linkat({old_dirfd}, {old_path:?}, {new_dirfd}, {new_path:?}, {flags:?})")]
    Linkat {
        old_dirfd: FrozenFd,
        old_path: PathBuf,
        new_dirfd: FrozenFd,
        new_path: PathBuf,
        flags: AtFlags,
        source: Errno,
    },

    #[error("symlinkat({dirfd}, {path:?}, {target:?})")]
    Symlinkat {
        dirfd: FrozenFd,
        path: PathBuf,
        target: PathBuf,
        source: Errno,
    },

    #[error("renameat({old_dirfd}, {old_path:?}, {new_dirfd}, {new_path:?})")]
    Renameat {
        old_dirfd: FrozenFd,
        old_path: PathBuf,
        new_dirfd: FrozenFd,
        new_path: PathBuf,
        source: Errno,
    },

    #[error("renameat2({old_dirfd}, {old_path:?}, {new_dirfd}, {new_path:?}, {flags:?})")]
    Renameat2 {
        old_dirfd: FrozenFd,
        old_path: PathBuf,
        new_dirfd: FrozenFd,
        new_path: PathBuf,
        flags: RenameFlags,
        source: Errno,
    },

    #[error("fstatfs({fd})")]
    Fstatfs { fd: FrozenFd, source: Errno },

    #[error("fstatat({dirfd}, {path:?}, {flags:?})")]
    Fstatat {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: AtFlags,
        source: Errno,
    },

    #[error("statx({dirfd}, {path:?}, flags={flags:?}, mask={mask:?})")]
    Statx {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: AtFlags,
        mask: StatxFlags,
        source: Errno,
    },

    #[error("fsopen({fstype:?}, {flags:?})")]
    Fsopen {
        fstype: String,
        flags: FsOpenFlags,
        source: Errno,
    },

    #[error("fsconfig({sfd}, FSCONFIG_CMD_CREATE)")]
    FsconfigCreate { sfd: FrozenFd, source: Errno },

    #[error("fsconfig({sfd}, FSCONFIG_SET_STRING, {key:?}, {value:?})")]
    FsconfigSetString {
        sfd: FrozenFd,
        key: String,
        value: String,
        source: Errno,
    },

    #[error("fsmount({sfd}, {flags:?}, {mount_attrs:?})")]
    Fsmount {
        sfd: FrozenFd,
        flags: FsMountFlags,
        mount_attrs: MountAttrFlags,
        source: Errno,
    },

    #[error("open_tree({dirfd}, {path:?}, {flags:?})")]
    OpenTree {
        dirfd: FrozenFd,
        path: PathBuf,
        flags: OpenTreeFlags,
        source: Errno,
    },

    #[error("prctl({get_flag})")]
    PrctlGet {
        get_flag: Cow<'static, str>,
        source: Errno,
    },
}

macro_rules! match_source_errno {
    ($self:expr) => {
        match $self {
            Error::InvalidFd { source, .. }
            | Error::Accessat { source, .. }
            | Error::Openat { source, .. }
            | Error::Openat2 { source, .. }
            | Error::Readlinkat { source, .. }
            | Error::Mkdirat { source, .. }
            | Error::Mknodat { source, .. }
            | Error::Unlinkat { source, .. }
            | Error::Linkat { source, .. }
            | Error::Symlinkat { source, .. }
            | Error::Renameat { source, .. }
            | Error::Renameat2 { source, .. }
            | Error::Fstatfs { source, .. }
            | Error::Fstatat { source, .. }
            | Error::Statx { source, .. }
            | Error::Fsopen { source, .. }
            | Error::FsconfigCreate { source, .. }
            | Error::FsconfigSetString { source, .. }
            | Error::Fsmount { source, .. }
            | Error::OpenTree { source, .. }
            | Error::PrctlGet { source, .. } => source,
        }
    };
}

impl Error {
    pub(crate) fn errno(&self) -> Errno {
        *match_source_errno!(self)
    }

    // TODO: Switch to returning &Errno.
    pub(crate) fn root_cause(&self) -> IOError {
        IOError::from_raw_os_error(self.errno().raw_os_error())
    }
}

/// Rustix will trigger a panic if a [`BorrowedFd`] has a value it deems
/// "unacceptable" (namely, most negative values). In rustix 1.0 they added
/// support for the `-EBADF` pattern, but a user passing a different negative
/// value should not trigger a crash, so we need to add this check to all fd
/// operations using rustix.
///
/// See <https://github.com/bytecodealliance/rustix/issues/1187> for more
/// information about the underlying issue. Note that while the issue is closed,
/// the resolution was to only accept `-EBADF` -- any other negative values
/// (other than `AT_FDCWD`) will still crash the program.
trait CheckRustixFd: Sized {
    fn check_rustix_fd(self) -> Result<Self, Error>;
}

impl<Fd: AsFd + Sized> CheckRustixFd for Fd {
    fn check_rustix_fd(self) -> Result<Self, Error> {
        // We can't use BADFD.as_raw_fd() or (-libc::EBADF as _) in a match arm,
        // instead we need to define a constant that we can then reference.
        const BADFD: RawFd = -libc::EBADF as _;

        match self.as_fd().as_raw_fd() {
            libc::AT_FDCWD | BADFD | 0.. => Ok(self),
            fd => Err(Error::InvalidFd {
                fd,
                source: Errno::BADF,
            }),
        }
    }
}

/// Wrapper for `faccessat(2)`.
pub(crate) fn accessat(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    access: Access,
    mut flags: AtFlags,
) -> Result<(), Error> {
    let (dirfd, path) = (dirfd.as_fd().check_rustix_fd()?, path.as_ref());
    flags |= AtFlags::SYMLINK_NOFOLLOW;

    rustix_fs::accessat(dirfd, path, access, flags).map_err(|errno| Error::Accessat {
        dirfd: dirfd.into(),
        path: path.into(),
        flags,
        access,
        source: errno,
    })
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOCTTY`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn openat_follow(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    mut flags: OpenFlags,
    mode: RawMode, // TODO: Should we take rustix::fs::Mode directly?
) -> Result<OwnedFd, Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();

    // O_CLOEXEC is needed for obvious reasons, and O_NOCTTY ensures that a
    // malicious file won't take control of our terminal.
    flags.insert(OpenFlags::O_CLOEXEC | OpenFlags::O_NOCTTY);

    rustix_fs::openat(
        dirfd,
        path,
        // Emulate E2BIG if we are given a flag that cannot be represented with
        // 32-bit openat(2) flags. openat(2) doesn't normally return E2BIG so
        // this should avoid confusion with real syscall errors.
        // TODO: It would be nice to make this a more descriptive error so that
        // the fact this came from our wrapper and not the syscall itself would
        // be more obvious?
        flags.try_into().map_err(|_| Error::Openat {
            dirfd: dirfd.into(),
            path: path.into(),
            flags,
            mode,
            source: Errno::TOOBIG, // E2BIG
        })?,
        Mode::from_raw_mode(mode),
    )
    .map_err(|errno| Error::Openat {
        dirfd: dirfd.into(),
        path: path.into(),
        flags,
        mode,
        source: errno,
    })
}

/// Wrapper for `openat(2)` which auto-sets `O_CLOEXEC | O_NOCTTY | O_NOFOLLOW`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `openat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn openat(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    mut flags: OpenFlags,
    mode: RawMode, // TODO: Should we take rustix::fs::Mode directly?
) -> Result<OwnedFd, Error> {
    flags.insert(OpenFlags::O_NOFOLLOW);
    openat_follow(dirfd, path, flags, mode)
}

/// Wrapper for `readlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `readlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub(crate) fn readlinkat(dirfd: impl AsFd, path: impl AsRef<Path>) -> Result<PathBuf, Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();

    // If the contents of the symlink are larger than this, we bail out avoid
    // DoS vectors (because there is no way to get the size of a symlink
    // beforehand, you just have to read it).
    // MSRV(1.79): Use const {}?
    let mut linkbuf: [MaybeUninit<u8>; 32 * 4096] =
        [MaybeUninit::uninit(); 32 * libc::PATH_MAX as usize];

    let (target, trailing) =
        rustix_fs::readlinkat_raw(dirfd, path, &mut linkbuf[..]).map_err(|errno| {
            Error::Readlinkat {
                dirfd: dirfd.into(),
                path: path.into(),
                source: match errno {
                    // readlinkat(fd, "") returns ENOENT if the file descriptor
                    // is not a symlink, which is in stark contrast to the
                    // EINVAL you would normally get from readlinkat(dfd, path).
                    // As we know the target file exists at this point (because
                    // resolve_nofollow succeeded), we can just map ENOENT to
                    // EINVAL to reduce user confusion.
                    Errno::NOENT if path.as_os_str().is_empty() => Errno::INVAL,
                    errno => errno,
                },
            }
        })?;

    if trailing.is_empty() {
        // The buffer was too small, return an error.
        Err(Error::Readlinkat {
            dirfd: dirfd.into(),
            path: path.into(),
            source: Errno::NAMETOOLONG,
        })
    } else {
        Ok(PathBuf::from(OsStr::from_bytes(target)))
    }
}

/// Wrapper for `mkdirat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mkdirat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn mkdirat(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    mode: RawMode, // TODO: Should we take rustix::fs::Mode directly?
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();

    rustix_fs::mkdirat(dirfd, path, Mode::from_raw_mode(mode)).map_err(|errno| Error::Mkdirat {
        dirfd: dirfd.into(),
        path: path.into(),
        mode,
        source: errno,
    })
}

pub(crate) fn devmajorminor(dev: Dev) -> (u32, u32) {
    (rustix_fs::major(dev), rustix_fs::minor(dev))
}

/// Wrapper for `mknodat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `mknodat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn mknodat(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    raw_mode: RawMode, // TODO: Should we take rustix::fs::{Mode,FileType} directly?
    dev: Dev,
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();
    let (file_type, mode) = (
        FileType::from_raw_mode(raw_mode),
        Mode::from_raw_mode(raw_mode),
    );

    rustix_fs::mknodat(dirfd, path, file_type, mode, dev).map_err(|errno| {
        let (major, minor) = devmajorminor(dev);
        Error::Mknodat {
            dirfd: dirfd.into(),
            path: path.into(),
            mode: raw_mode,
            major,
            minor,
            source: errno,
        }
    })
}

/// Wrapper for `unlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `unlinkat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn unlinkat(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    flags: AtFlags,
) -> Result<(), Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();

    rustix_fs::unlinkat(dirfd, path, flags).map_err(|errno| Error::Unlinkat {
        dirfd: dirfd.into(),
        path: path.into(),
        flags,
        source: errno,
    })
}

/// Wrapper for `linkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `linkat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn linkat(
    old_dirfd: impl AsFd,
    old_path: impl AsRef<Path>,
    new_dirfd: impl AsFd,
    new_path: impl AsRef<Path>,
    flags: AtFlags,
) -> Result<(), Error> {
    let (old_dirfd, old_path) = (old_dirfd.as_fd().check_rustix_fd()?, old_path.as_ref());
    let (new_dirfd, new_path) = (new_dirfd.as_fd().check_rustix_fd()?, new_path.as_ref());

    rustix_fs::linkat(old_dirfd, old_path, new_dirfd, new_path, flags).map_err(|errno| {
        Error::Linkat {
            old_dirfd: old_dirfd.into(),
            old_path: old_path.into(),
            new_dirfd: new_dirfd.into(),
            new_path: new_path.into(),
            flags,
            source: errno,
        }
    })
}

/// Wrapper for `symlinkat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `symlinkat(2)`. We need the dirfd argument, so we need a
/// wrapper.
pub(crate) fn symlinkat(
    target: impl AsRef<Path>,
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
) -> Result<(), Error> {
    let (dirfd, path) = (dirfd.as_fd().check_rustix_fd()?, path.as_ref());
    let target = target.as_ref();

    rustix_fs::symlinkat(target, dirfd, path).map_err(|errno| Error::Symlinkat {
        dirfd: dirfd.into(),
        path: path.into(),
        target: target.into(),
        source: errno,
    })
}

/// Wrapper for `renameat(2)`.
///
/// This is needed because Rust doesn't provide a way to access the dirfd
/// argument of `renameat(2)`. We need the dirfd argument, so we need a wrapper.
pub(crate) fn renameat(
    old_dirfd: impl AsFd,
    old_path: impl AsRef<Path>,
    new_dirfd: impl AsFd,
    new_path: impl AsRef<Path>,
) -> Result<(), Error> {
    let (old_dirfd, old_path) = (old_dirfd.as_fd().check_rustix_fd()?, old_path.as_ref());
    let (new_dirfd, new_path) = (new_dirfd.as_fd().check_rustix_fd()?, new_path.as_ref());

    rustix_fs::renameat(old_dirfd, old_path, new_dirfd, new_path).map_err(|errno| Error::Renameat {
        old_dirfd: old_dirfd.into(),
        old_path: old_path.into(),
        new_dirfd: new_dirfd.into(),
        new_path: new_path.into(),
        source: errno,
    })
}

// MSRV(1.80): Use LazyLock.
pub(crate) static RENAME_FLAGS_SUPPORTED: Lazy<bool> = Lazy::new(|| {
    match renameat2(AT_FDCWD, ".", AT_FDCWD, ".", RenameFlags::RENAME_EXCHANGE) {
        Ok(_) => true,
        // We expect EBUSY, but just to be safe we only check for ENOSYS.
        Err(err) => err.root_cause().raw_os_error() != Some(libc::ENOSYS),
    }
});

/// Wrapper for `renameat2(2)`.
///
/// This is needed because Rust doesn't provide any interface for `renameat2(2)`
/// (especially not an interface for the dirfd).
pub(crate) fn renameat2(
    old_dirfd: impl AsFd,
    old_path: impl AsRef<Path>,
    new_dirfd: impl AsFd,
    new_path: impl AsRef<Path>,
    flags: RenameFlags,
) -> Result<(), Error> {
    // Use renameat(2) if no flags are specified.
    if flags.is_empty() {
        return renameat(old_dirfd, old_path, new_dirfd, new_path);
    }

    let (old_dirfd, old_path) = (old_dirfd.as_fd().check_rustix_fd()?, old_path.as_ref());
    let (new_dirfd, new_path) = (new_dirfd.as_fd().check_rustix_fd()?, new_path.as_ref());

    rustix_fs::renameat_with(old_dirfd, old_path, new_dirfd, new_path, flags.into()).map_err(
        |errno| Error::Renameat2 {
            old_dirfd: old_dirfd.into(),
            old_path: old_path.into(),
            new_dirfd: new_dirfd.into(),
            new_path: new_path.into(),
            flags,
            source: errno,
        },
    )
}

/// Wrapper for `fstatfs(2)`.
///
/// This is needed because Rust doesn't provide any interface for `fstatfs(2)`.
pub(crate) fn fstatfs(fd: impl AsFd) -> Result<StatFs, Error> {
    let fd = fd.as_fd().check_rustix_fd()?;

    rustix_fs::fstatfs(fd).map_err(|errno| Error::Fstatfs {
        fd: fd.into(),
        source: errno,
    })
}

/// Wrapper for `fstatfs(2)` that only returns the filesystem type
/// (`statfs.f_type`), widened to a [`u64`].
///
/// The exact type of `statfs.f_type` depends on both the architecture and the
/// backend used by rustix, and is not always the same type as
/// [`rustix::fs::FsWord`] (on s390x with musl, `f_type` is a `u32` while
/// `FsWord` is a `u64`), which means that comparing `f_type` against
/// `FsWord`-typed constants (such as [`rustix::fs::PROC_SUPER_MAGIC`]) doesn't
/// compile on all targets. Widening the value to a `u64` lets us compare it
/// against plain `u64` filesystem magic numbers everywhere.
// The filesystem magic numbers we care about all fit inside a u32, so the
// signedness of f_type (it is signed on most targets) is irrelevant here.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn fstatfs_type(fd: impl AsFd) -> Result<u64, Error> {
    fstatfs(fd).map(|statfs| statfs.f_type as u64)
}

/// Wrapper for `fstatat(2)`, which auto-sets `AT_NO_AUTOMOUNT |
/// AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH`.
///
/// This is needed because Rust doesn't provide any interface for `fstatat(2)`.
pub(crate) fn fstatat(dirfd: impl AsFd, path: impl AsRef<Path>) -> Result<Stat, Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();
    let flags = AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW | AtFlags::EMPTY_PATH;

    rustix_fs::statat(dirfd, path, flags).map_err(|errno| Error::Fstatat {
        dirfd: dirfd.into(),
        path: path.into(),
        flags,
        source: errno,
    })
}

pub(crate) fn statx(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    mask: StatxFlags,
) -> Result<Statx, Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();
    let flags = AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW | AtFlags::EMPTY_PATH;

    rustix_fs::statx(dirfd, path, flags, mask).map_err(|errno| Error::Statx {
        dirfd: dirfd.into(),
        path: path.into(),
        flags,
        mask,
        source: errno,
    })
}

pub(crate) mod openat2 {
    use super::*;

    use once_cell::sync::OnceCell;

    /// Caches whether we've ever seen `openat2(2)` fail with trivial arguments.
    ///
    /// This is a one-way toggle.
    ///
    /// If `openat2(2)` fails with trivial arguments then we can reasonably
    /// believe that `openat2(2)` is either unsupported by the running kernel or
    /// is blocked by a seccomp-bpf filter -- neither of which is a reversible
    /// condition.
    ///
    /// Note that we *do not* care if `openat2(2)` has succeeded in the past. A
    /// process can always add seccomp-bpf filters to itself that would cause
    /// `openat2(2)` to start failing.
    // MSRV(1.70): Use OnceLock.
    static SAW_OPENAT2_FAILURE: OnceCell<()> = OnceCell::new();

    /// Returns whether we have seen a trivial failure from `openat2(2)` in the
    /// past. If this returns `false`, that does not meant that `openat2(2)` is
    /// supported (or has ever succeeded).
    pub(crate) fn saw_openat2_failure() -> bool {
        SAW_OPENAT2_FAILURE.get().is_some()
    }

    /// Returns whether trivial `openat2(2)` calls fail and thus `openat2(2)` is
    /// not supported.
    ///
    /// If this function returns `true`, you can safely assume that it will
    /// always return `true`. However, if it returns `false` it is possible for
    /// it to return `true` at some point in the future.
    pub(crate) fn openat2_is_not_supported() -> bool {
        SAW_OPENAT2_FAILURE.get().map_or_else(
            || match openat2(AT_FDCWD, ".", Default::default()) {
                Ok(_) => false,
                Err(_) => {
                    // Stash that we saw a failure, ignore if we lost the race.
                    let _ = SAW_OPENAT2_FAILURE.set(());
                    true
                }
            },
            |_| true, // saw cached failure
        )
    }

    bitflags! {
        /// Wrapper for the underlying `libc`'s `RESOLVE_*` flags.
        ///
        /// The flag values and their meaning is identical to the description in the
        /// [`openat2(2)`] man page.
        ///
        /// [`openat2(2)`]: http://man7.org/linux/man-pages/man2/openat2.2.html
        #[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
        pub(crate) struct ResolveFlags: u64 {
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
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    pub(crate) struct OpenHow {
        /// O_* flags (`-EINVAL` on unknown or incompatible flags).
        pub flags: OpenFlags,
        /// O_CREAT or O_TMPFILE file mode (must be zero otherwise).
        pub mode: u64,
        /// RESOLVE_* flags (`-EINVAL` on unknown flags).
        pub resolve: u64,
    }

    impl fmt::Display for OpenHow {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{{ ")?;
            // self.flags
            write!(f, "flags: {:?}, ", self.flags)?;
            if self
                .flags
                .intersects(OpenFlags::O_CREAT | OpenFlags::O_TMPFILE)
            {
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

    impl OpenHow {
        const fn is_scoped_lookup(&self) -> bool {
            // BitOr is not const fn, so we need to do this with .union()...
            const SCOPED_LOOKUP_FLAGS: ResolveFlags =
                ResolveFlags::RESOLVE_BENEATH.union(ResolveFlags::RESOLVE_IN_ROOT);
            ResolveFlags::from_bits_retain(self.resolve).intersects(SCOPED_LOOKUP_FLAGS)
        }
    }

    /// Wrapper for `openat2(2)` which auto-sets `O_CLOEXEC | O_NOCTTY`.
    // NOTE: rustix's openat2 wrapper is not extensible-friendly so we use our
    // own for now. See <https://github.com/bytecodealliance/rustix/issues/1186>.
    pub(crate) fn openat2_follow(
        dirfd: impl AsFd,
        path: impl AsRef<Path>,
        mut how: OpenHow,
    ) -> Result<OwnedFd, Error> {
        let dirfd = dirfd.as_fd().check_rustix_fd()?;
        let path = path.as_ref();

        // Add O_CLOEXEC and O_NOCTTY explicitly (as we do for openat). However,
        // O_NOCTTY cannot be set if O_PATH is set (openat2 verifies flag
        // arguments).
        how.flags.insert(OpenFlags::O_CLOEXEC);
        if !how.flags.contains(OpenFlags::O_PATH) {
            how.flags.insert(OpenFlags::O_NOCTTY);
        }

        // openat2(2) can fail with -EAGAIN if there was a racing rename or
        // mount *anywhere on the system*. This can happen pretty frequently, so
        // what we do is attempt the openat2(2) a couple of times.
        //
        // Based on some fairly extensive tests, with 128 retries you only have
        // a ~0.1% chance of hitting the error path (even with an attacker
        // pounding on rename on all cores). Users that need stricter retry
        // requirements can do their own higher-level retry loop based on the
        // errno.
        const MAX_RETRIES: u8 = 128;
        let mut tries = 0u8;
        let (fd, err) = loop {
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

            let err = if fd < 0 {
                Some(
                    IOError::last_os_error()
                        .raw_os_error()
                        .map(Errno::from_raw_os_error)
                        .expect("last_os_error must return a raw OS std::io::Error"),
                )
            } else {
                None
            };

            // Success.
            if fd >= 0
                // Not a scoped lookup (no need to retry).
                || !how.is_scoped_lookup()
                // Not a retry-able error.
                || err != Some(Errno::AGAIN)
                 // Too many retries.
                || tries >= MAX_RETRIES
            {
                break (fd, err);
            }
            tries += 1;
        };

        if fd >= 0 {
            // SAFETY: We know it's a real file descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        } else {
            Err(Error::Openat2 {
                dirfd: dirfd.into(),
                path: path.into(),
                how,
                size: std::mem::size_of::<OpenHow>(),
                source: err.expect("syscall failure must result in an error"),
            })
        }
    }

    /// Wrapper for `openat2(2)` which auto-sets `O_CLOEXEC | O_NOCTTY |
    /// O_NOFOLLOW`.
    pub(crate) fn openat2(
        dirfd: impl AsFd,
        path: impl AsRef<Path>,
        mut how: OpenHow,
    ) -> Result<OwnedFd, Error> {
        how.flags.insert(OpenFlags::O_NOFOLLOW);
        openat2_follow(dirfd, path, how)
    }
}

pub(crate) use openat2::{openat2, openat2_follow, OpenHow, ResolveFlags};

#[cfg(test)]
mod personality {
    // musl doesn't expose UNAME26.
    #[cfg(not(target_env = "musl"))]
    pub(crate) const PER_UNAME26: u32 = libc::UNAME26 as _;
    #[cfg(target_env = "musl")]
    pub(crate) const PER_UNAME26: u32 = 0x0020000; /* <linux/personality.h> */

    pub(crate) fn personality(persona: Option<u32>) -> u32 {
        unsafe { libc::personality(persona.unwrap_or(0xFFFF_FFFF) as _) as _ }
    }

    /// Temporarily change the personality of the running thread.
    ///
    /// The personality is reset to the original persona value (i.e., when
    /// [`scoped_personality`] was first called) once the returned `impl Drop`
    /// value is dropped. Note that any threads or subprocesses spawned with
    /// the `scoped_personality` guard held will permanently inherit the
    /// specified persona.
    #[must_use]
    pub(crate) fn scoped_personality(persona: u32) -> impl Drop {
        scopeguard::guard(personality(Some(persona)), |old_persona| {
            personality(Some(old_persona));
        })
    }
}

#[cfg(test)]
pub(crate) use personality::*;

#[cfg(test)]
pub(crate) fn getpid() -> rustix_process::RawPid {
    rustix_process::Pid::as_raw(Some(rustix_process::getpid()))
}

pub(crate) fn gettid() -> rustix_process::RawPid {
    rustix_process::Pid::as_raw(Some(rustix_thread::gettid()))
}

pub(crate) fn geteuid() -> rustix_process::RawUid {
    rustix_process::geteuid().as_raw()
}

#[cfg(test)]
pub(crate) fn getegid() -> rustix_process::RawGid {
    rustix_process::getegid().as_raw()
}

#[cfg(test)]
pub(crate) fn getcwd() -> Result<PathBuf, anyhow::Error> {
    let buffer = Vec::with_capacity(libc::PATH_MAX as usize);
    Ok(OsStr::from_bytes(rustix_process::getcwd(buffer)?.to_bytes()).into())
}

pub(crate) fn prctl_get_dumpable() -> Result<DumpableBehavior, Error> {
    rustix_process::dumpable_behavior().map_err(|errno| Error::PrctlGet {
        get_flag: "PR_GET_DUMPABLE".into(),
        source: errno,
    })
}

pub(crate) fn fsopen(fstype: &str, flags: FsOpenFlags) -> Result<OwnedFd, Error> {
    rustix_mount::fsopen(fstype, flags).map_err(|errno| Error::Fsopen {
        fstype: fstype.into(),
        flags,
        source: errno,
    })
}

pub(crate) fn fsconfig_set_string(sfd: impl AsFd, key: &str, value: &str) -> Result<(), Error> {
    let sfd = sfd.as_fd().check_rustix_fd()?;

    rustix_mount::fsconfig_set_string(sfd, key, value).map_err(|errno| Error::FsconfigSetString {
        sfd: sfd.into(),
        key: key.into(),
        value: value.into(),
        source: errno,
    })
}

pub(crate) fn fsconfig_create(sfd: impl AsFd) -> Result<(), Error> {
    let sfd = sfd.as_fd().check_rustix_fd()?;

    rustix_mount::fsconfig_create(sfd).map_err(|errno| Error::FsconfigCreate {
        sfd: sfd.into(),
        source: errno,
    })
}

pub(crate) fn fsmount(
    sfd: impl AsFd,
    flags: FsMountFlags,
    mount_attrs: MountAttrFlags,
) -> Result<OwnedFd, Error> {
    let sfd = sfd.as_fd().check_rustix_fd()?;

    rustix_mount::fsmount(sfd, flags, mount_attrs).map_err(|errno| Error::Fsmount {
        sfd: sfd.into(),
        flags,
        mount_attrs,
        source: errno,
    })
}

pub(crate) fn open_tree(
    dirfd: impl AsFd,
    path: impl AsRef<Path>,
    flags: OpenTreeFlags,
) -> Result<OwnedFd, Error> {
    let dirfd = dirfd.as_fd().check_rustix_fd()?;
    let path = path.as_ref();

    rustix_mount::open_tree(dirfd, path, flags).map_err(|errno| Error::OpenTree {
        dirfd: dirfd.into(),
        path: path.into(),
        flags,
        source: errno,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs::File,
        os::unix::io::{AsRawFd, BorrowedFd},
    };

    use pretty_assertions::{assert_eq, assert_matches};
    use tempfile::NamedTempFile;

    #[test]
    fn frozen_fd_display() {
        // AT_FDCWD
        let cwd = getcwd().expect("getcwd");
        assert_eq!(
            format!("{}", FrozenFd::from(AT_FDCWD)),
            format!("[AT_FDCWD]<{cwd:?}>"),
            "FrozenFd::from(AT_FDCWD)"
        );

        // Bad fd.
        assert_eq!(
            format!("{}", FrozenFd::from(BADFD)),
            "[-9]<unknown>",
            "FrozenFd::from(-EBADF)"
        );

        // Regular file (still open when displaying FrozenFd).
        let file = NamedTempFile::new().expect("mktemp file");
        assert_eq!(
            format!("{}", FrozenFd::from(file.as_file())),
            format!("[{}]<{:?}>", file.as_file().as_raw_fd(), file.path()),
            "FrozenFd::from(<tempfile>)"
        );

        // Regular file (*closed* when displaying FrozenFd).
        let (frozen_fd, fd, path) = {
            let file = NamedTempFile::new().expect("mktemp file");
            (
                FrozenFd::from(file.as_file()),
                file.as_file().as_raw_fd(),
                file.path().to_path_buf(),
            )
        };
        assert_eq!(
            format!("{}", frozen_fd),
            format!("[{}]<{:?}>", fd, path),
            "FrozenFd::from(<tempfile>) after closing"
        );
    }

    #[test]
    fn check_rustix_fd() {
        assert_matches!(
            AT_FDCWD.check_rustix_fd(),
            Ok(_),
            "AT_FDCWD.check_rustix_fd() should be allowed"
        );

        assert_matches!(
            BADFD.check_rustix_fd(),
            Ok(_),
            "BADFD.check_rustix_fd() should be allowed"
        );

        assert_matches!(
            File::open(".").expect("open .").check_rustix_fd(),
            Ok(_),
            "<fd>.check_rustix_fd() should be allowed"
        );

        // SAFETY: For this one case, constructing a fake BorrowedFd from a bad
        // file descriptor is okay.
        assert_matches!(
            unsafe { BorrowedFd::borrow_raw(-1234) }.check_rustix_fd(),
            Err(Error::InvalidFd { .. }),
            "<-1234>.check_rustix_fd() should fail"
        );
    }
}

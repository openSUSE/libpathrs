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

use crate::{kernel, user, Error, Handle};

use core::convert::TryFrom;
use std::ffi::CString;
use std::io::Error as IOError;
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    io::{AsRawFd, IntoRawFd, RawFd},
};
use std::path::{Path, PathBuf};
use std::{
    fs,
    fs::{OpenOptions, Permissions},
};

use failure::{Error as FailureError, ResultExt};
use libc::dev_t;

lazy_static! {
    static ref KERNEL_SUPPORT: bool = kernel::supported();
}

/// An inode type to be created with [`Root::create`].
///
/// [`Root::create`]: struct.Root.html#method.create
pub enum InodeType<'a> {
    /// Ordinary file, as in [`creat(2)`].
    ///
    /// [`creat(2)`]: http://man7.org/linux/man-pages/man2/creat.2.html
    // XXX: It is possible to support non-O_EXCL O_CREAT with the native
    //      backend. But it's unclear whether we should expose it given it's
    //      only supported on native-kernel systems.
    File(&'a Permissions),

    /// Directory, as in [`mkdir(2)`].
    ///
    /// [`mkdir(2)`]: http://man7.org/linux/man-pages/man2/mkdir.2.html
    Directory(&'a Permissions),

    /// Symlink with the given [`Path`], as in [`symlinkat(2)`].
    ///
    /// Note that symlinks can contain any arbitrary [`CStr`]-style string (it
    /// doesn't need to be a real pathname). We don't do any verification of the
    /// target name.
    ///
    /// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
    /// [`symlinkat(2)`]: http://man7.org/linux/man-pages/man2/symlinkat.2.html
    Symlink(&'a Path),

    /// Hard-link to the given [`Path`], as in [`linkat(2)`].
    ///
    /// The provided [`Path`] is resolved within the [`Root`]. It is currently
    /// not supported to hardlink a file inside the [`Root`]'s tree to a file
    /// outside the [`Root`]'s tree.
    ///
    /// [`linkat(2)`]: http://man7.org/linux/man-pages/man2/linkat.2.html
    /// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
    /// [`Root`]: struct.Root.html
    // XXX: Should we ever support that?
    Hardlink(&'a Path),

    /// Named pipe (aka FIFO), as in [`mkfifo(3)`].
    ///
    /// [`mkfifo(3)`]: http://man7.org/linux/man-pages/man3/mkfifo.3.html
    Fifo(&'a Permissions),

    /// Character device, as in [`mknod(2)`] with `S_IFCHR`.
    ///
    /// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    CharacterDevice(&'a Permissions, dev_t),

    /// Block device, as in [`mknod(2)`] with `S_IFBLK`.
    ///
    /// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    BlockDevice(&'a Permissions, dev_t),
    //// "Detached" unix socket, as in [`mknod(2)`] with `S_IFSOCK`.
    ////
    //// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    // TODO: In principle we could do this safely by doing the `mknod` and then See if we can even do bind(2) safely for a Socket() type.
    //DetachedSocket(),
}

/// Helper to split a Path into its parent directory and trailing path. The
/// trailing component is guaranteed to not contain a directory separator.
fn path_split<'p>(path: &'p Path) -> Result<(&'p Path, &'p str), FailureError> {
    let parent = path.parent().unwrap_or("/".as_ref());

    // Now construct the trailing portion of the target.
    let name = path
        .file_name()
        .ok_or(Error::InvalidArgument("path", "no trailing component"))?
        .to_str()
        .ok_or(Error::InvalidArgument("path", "not a valid Rust string"))?;

    // It's critical we are only touching the final component in the path.
    // If there are any other path components we must bail.
    if name.contains(std::path::MAIN_SEPARATOR) {
        return Err(Error::SafetyViolation(
            "trailing component of pathname contains '/'",
        ))?;
    }
    Ok((parent, name))
}

/// Check whether a given RawFd refers to the given path.
///
/// This is naturally racy, so it's important to only use this with the
/// understanding that it only provides the guarantee that "at some point during
/// execution this was true" and no more.
fn fd_is_path(fd: RawFd, other_path: &Path) -> Result<bool, FailureError> {
    let path = format!("/proc/self/fd/{}", fd);
    let path = fs::read_link(path).context("readlink /proc/self/fd")?;

    Ok(path == other_path)
}

/// A handle to the root of a directory tree.
///
/// # Safety
///
/// At the time of writing, it is considered a **very bad idea** to open a
/// [`Root`] inside a possibly-attacker-controlled directory tree. While we do
/// have protections that should defend against it (for both drivers), it's far
/// more dangerous than just opening a directory tree which is not inside a
/// potentially-untrusted directory.
///
/// # Errors
///
/// If at any point an attack is detected during the execution of a [`Root`]
/// method, an error will be returned. The method of attack detection is
/// multi-layered and operates through explicit `/proc/self/fd` checks as well
/// as (in the case of the native backend) kernel-space checks that will trigger
/// `-EXDEV` in certain attack scenarios.
///
/// Additionally, if this root directory is moved then any subsequent operations
/// will fail with an [`Error::SafetyViolation`] since it's not obvious whether
/// there is an attacker or if the path was moved innocently. This restriction
/// might be relaxed in the future.
///
/// [`Root`]: struct.Root.html
/// [`Error::SafetyViolation`]: enum.Error.html#variant.SafetyViolation
pub struct Root {
    fd: RawFd,
    path: PathBuf,
}

// RawFds aren't auto-dropped in Rust so we need to do it manually. As long as
// nobody has done anything strange with the current process's fds, this will
// not fail.
impl Drop for Root {
    fn drop(&mut self) {
        // Cannot return errors in Drop or panic! in C FFI. So just ignore it.
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for Root {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Root {
    /// Open a [`Root`] handle.
    ///
    /// # Errors
    ///
    /// `path` must be an existing directory, and must (at the moment) be a
    /// fully-resolved pathname with no symlink components. This restriction
    /// might be relaxed in the future.
    ///
    /// [`Root`]: struct.Root.html
    // TODO: We really need to provide a dirfd as a source, though the main
    //       problem here is that it's unclear what the "correct" path is for
    //       the emulated backend to check against. We could just read the dirfd
    //       but now we have more races to deal with. We could ask the user to
    //       provide a backup path to check against, but then why not just use
    //       that path in the first place?
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, FailureError> {
        let path = path.as_ref();

        if path.is_relative() {
            return Err(Error::InvalidArgument("path", "must be an absolute path"))
                .context("open root handle")?;
        }

        let file = OpenOptions::new()
            .read(true) /* Needed to avoid EINVAL by Rust. */
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(path)
            .context("open root handle")?;

        let root = Root {
            fd: file.into_raw_fd(),
            path: path.into(),
        };

        root.check()?;
        Ok(root)
    }

    /// Check whether the Root is still valid.
    fn check(&self) -> Result<(), FailureError> {
        if fd_is_path(self.fd, &self.path)? {
            Ok(())
        } else {
            Err(Error::SafetyViolation(
                "root directory was moved during execution",
            ))?
        }
    }

    /// Within the given [`Root`]'s tree, resolve `path` and return a
    /// [`Handle`]. All symlink path components are scoped to [`Root`].
    ///
    /// # Errors
    ///
    /// If `path` doesn't exist, or an attack was detected during resolution, a
    /// corresponding Error will be returned. If no error is returned, then the
    /// path is guaranteed to have been reachable from the root of the directory
    /// tree and thus have been inside the root at one point in the resolution.
    ///
    /// [`Root`]: struct.Root.html
    /// [`Handle`]: trait.Handle.html
    pub fn resolve(&self, path: &Path) -> Result<Handle, FailureError> {
        self.check()?;
        match *KERNEL_SUPPORT {
            true => kernel::resolve(self, path),
            false => user::resolve(self, path),
        }
    }

    /// Within the [`Root`]'s tree, create an inode at `path` as specified by
    /// `inode_type`.
    ///
    /// # Errors
    ///
    /// If the path already exists (regardless of the type of the existing
    /// inode), an error is returned.
    ///
    /// [`Root`]: struct.Root.html
    pub fn create<P: AsRef<Path>>(
        &self,
        path: P,
        inode_type: &InodeType,
    ) -> Result<(), FailureError> {
        self.check()?;

        // Use create_file if that's the inode_type. We drop the File returned
        // (it was free to create anyway because we used openat(2)).
        if let InodeType::File(perm) = inode_type {
            return self.create_file(path, perm).map(|_| ());
        }

        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) = path_split(path.as_ref())
            .context("split path into (parent, name) for inode creation")?;
        let dirfd = self
            .resolve(parent)
            .context("resolve parent directory for inode creation")?
            .as_raw_fd();
        let name = CString::new(name)
            .context("convert name into CString for FFI")?
            .as_ptr();

        let ret = match inode_type {
            InodeType::File(_) => unreachable!(), /* we dealt with this above */
            InodeType::Directory(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mkdirat(dirfd, name, mode) }
            }
            InodeType::Symlink(target) => {
                let target = target
                    .to_str()
                    .ok_or(Error::InvalidArgument("target", "not a valid Rust string"))?;
                let target = CString::new(target)?.as_ptr();
                unsafe { libc::symlinkat(target, dirfd, name) }
            }
            InodeType::Hardlink(target) => {
                let oldfd = self
                    .resolve(target)
                    .context("resolve target path for hardlink")?
                    .as_raw_fd();
                let empty_path = CString::new("")?.as_ptr();
                unsafe { libc::linkat(oldfd, empty_path, dirfd, name, libc::AT_EMPTY_PATH) }
            }
            InodeType::Fifo(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mknodat(dirfd, name, libc::S_IFIFO | mode, 0) }
            }
            InodeType::CharacterDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mknodat(dirfd, name, libc::S_IFCHR | mode, *dev) }
            }
            InodeType::BlockDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                unsafe { libc::mknodat(dirfd, name, libc::S_IFBLK | mode, *dev) }
            }
        };
        let err: IOError = errno::errno().into();

        if ret.is_negative() {
            return Err(err).context("root inode create failed")?;
        }
        Ok(())
    }

    /// Create an [`InodeType::File`] within the [`Root`]'s tree at `path` with
    /// the mode given by `perm`, and return a [`Handle`] to the newly-created
    /// file.
    ///
    /// However, unlike the trivial way of doing the above:
    ///
    /// ```
    /// root.create(path, inode_type)?;
    /// // What happens if the file is replaced here!?
    /// let handle = root.resolve(path, perm)?;
    /// ```
    ///
    /// [`Root::create_file`] guarantees that the returned [`Handle`] is the
    /// same as the file created by the operation. This is only possible to
    /// guarantee for ordinary files because there is no [`O_CREAT`]-equivalent
    /// for other inode types.
    ///
    /// # Errors
    ///
    /// Identical to [`Root::create`].
    ///
    /// [`Root`]: struct.Root.html
    /// [`Handle`]: trait.Handle.html
    /// [`Root::create`]: struct.Root.html#method.create
    /// [`Root::create_file`]: struct.Root.html#method.create_file
    /// [`InodeType::File`]: enum.InodeType.html#variant.File
    /// [`O_CREAT`]: http://man7.org/linux/man-pages/man2/open.2.html
    pub fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Handle, FailureError> {
        self.check()?;

        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) = path_split(path.as_ref())
            .context("split path into (parent, name) for inode creation")?;
        let dirfd = self
            .resolve(parent)
            .context("resolve parent directory for inode creation")?
            .as_raw_fd();
        let name = CString::new(name)
            .context("convert name into CString for FFI")?
            .as_ptr();

        let fd: RawFd = unsafe {
            libc::openat(
                dirfd,
                name,
                libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                perm.mode(),
            )
        };
        let err: IOError = errno::errno().into();

        if fd.is_negative() {
            return Err(err).context("root file create failed")?;
        }
        Ok(Handle::try_from(fd).context("convert O_CREAT fd to Handle")?)
    }

    /// Within the [`Root`]'s tree, remove the inode at `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist or is a non-empty directory, an error will be
    /// returned. In order to remove a non-empty directory, please use
    /// [`Root::remove_all`].
    ///
    /// [`Root`]: struct.Root.html
    /// [`Handle`]: trait.Handle.html
    /// [`Root::remove_all`]: struct.Root.html#method.remove_all
    pub fn remove<P: AsRef<Path>>(&self, path: P) -> Result<(), FailureError> {
        self.check()?;

        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) = path_split(path.as_ref())?;
        let dirfd = self.resolve(parent)?.as_raw_fd();
        let name = CString::new(name)?.as_ptr();

        // TODO: Handle the lovely "is it a directory or file" problem.
        let ret = unsafe { libc::unlinkat(dirfd, name, 0) };
        let err: IOError = errno::errno().into();

        if ret.is_negative() {
            return Err(err).context("root inode remove failed")?;
        }
        Ok(())
    }

    // TODO: mkdir_all()
    // TODO: remove_all()
}

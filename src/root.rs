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

#![forbid(unsafe_code)]

use crate::{
    error::{Error, ErrorExt, ErrorImpl},
    flags::{OpenFlags, RenameFlags},
    procfs::GLOBAL_PROCFS_HANDLE,
    resolvers::Resolver,
    syscalls::{self, FrozenFd},
    utils::{self, PathIterExt},
    Handle,
};

use std::{
    fs::Permissions,
    io::Error as IOError,
    os::{
        linux::fs::MetadataExt,
        unix::{
            ffi::OsStrExt,
            fs::PermissionsExt,
            io::{AsFd, BorrowedFd, OwnedFd},
        },
    },
    path::{Path, PathBuf},
};

use libc::dev_t;
use rustix::fs::{self as rustix_fs, Dir, SeekFrom};

/// An inode type to be created with [`Root::create`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum InodeType {
    /// Ordinary file, as in [`creat(2)`].
    ///
    /// [`creat(2)`]: http://man7.org/linux/man-pages/man2/creat.2.html
    // XXX: It is possible to support non-O_EXCL O_CREAT with the native
    //      backend. But it's unclear whether we should expose it given it's
    //      only supported on native-kernel systems.
    File(Permissions),

    /// Directory, as in [`mkdir(2)`].
    ///
    /// [`mkdir(2)`]: http://man7.org/linux/man-pages/man2/mkdir.2.html
    Directory(Permissions),

    /// Symlink with the given path, as in [`symlinkat(2)`].
    ///
    /// Note that symlinks can contain any arbitrary `CStr`-style string (it
    /// doesn't need to be a real pathname). We don't do any verification of the
    /// target name.
    ///
    /// [`symlinkat(2)`]: http://man7.org/linux/man-pages/man2/symlinkat.2.html
    Symlink(PathBuf),

    /// Hard-link to the given path, as in [`linkat(2)`].
    ///
    /// The provided path is resolved within the [`Root`]. It is currently
    /// not supported to hardlink a file inside the [`Root`]'s tree to a file
    /// outside the [`Root`]'s tree.
    // XXX: Should we ever support that?
    ///
    /// [`linkat(2)`]: http://man7.org/linux/man-pages/man2/linkat.2.html
    Hardlink(PathBuf),

    /// Named pipe (aka FIFO), as in [`mkfifo(3)`].
    ///
    /// [`mkfifo(3)`]: http://man7.org/linux/man-pages/man3/mkfifo.3.html
    Fifo(Permissions),

    /// Character device, as in [`mknod(2)`] with `S_IFCHR`.
    ///
    /// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    CharacterDevice(Permissions, dev_t),

    /// Block device, as in [`mknod(2)`] with `S_IFBLK`.
    ///
    /// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    BlockDevice(Permissions, dev_t),
    // XXX: Does this really make sense?
    //// "Detached" unix socket, as in [`mknod(2)`] with `S_IFSOCK`.
    ////
    //// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    //DetachedSocket(),
}

/// The inode type for [`RootRef::remove_inode`]. This only used internally
/// within libpathrs.
#[derive(Clone, Copy, Debug)]
enum RemoveInodeType {
    Regular,   // ~AT_REMOVEDIR
    Directory, // AT_REMOVEDIR
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
/// will fail with a `SafetyViolation` error since it's not obvious
/// whether there is an attacker or if the path was moved innocently. This
/// restriction might be relaxed in the future.
// TODO: Fix the SafetyViolation link once we expose ErrorKind.
#[derive(Debug)]
pub struct Root {
    /// The underlying `O_PATH` [`OwnedFd`] for this root handle.
    inner: OwnedFd,

    /// The underlying [`Resolver`] to use for all operations underneath this
    /// root. This affects not just [`resolve`] but also all other methods which
    /// have to implicitly resolve a path underneath `Root`.
    ///
    /// [`resolve`]: Self::resolve
    // TODO: Drop this and switch to builder-pattern...
    pub resolver: Resolver,
}

impl Root {
    /// Open a [`Root`] handle.
    ///
    /// The [`Resolver`] used by this handle is chosen at runtime based on which
    /// resolvers are supported by the running kernel (the default [`Resolver`]
    /// is always `Resolver::default()`). You can change the [`Resolver`] used
    /// by changing `Root.resolver`, though this is not recommended.
    ///
    /// # Errors
    ///
    /// `path` must be an existing directory, and must (at the moment) be a
    /// fully-resolved pathname with no symlink components. This restriction
    /// might be relaxed in the future.
    #[doc(alias = "pathrs_root_open")]
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = syscalls::openat(
            syscalls::AT_FDCWD,
            path,
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )
        .map_err(|err| ErrorImpl::RawOsError {
            operation: "open root handle".into(),
            source: err,
        })?;
        Ok(Self::from_fd_unchecked(file))
    }

    /// Wrap an [`OwnedFd`] into a [`Root`].
    ///
    /// The configuration is set to the system default and should be configured
    /// prior to usage, if appropriate.
    ///
    /// # Safety
    ///
    /// The caller guarantees that the provided file is an `O_PATH` file
    /// descriptor with exactly the same semantics as one created through
    /// [`Root::open`]. This means that this function should usually be used to
    /// convert an [`OwnedFd`] returned from [`OwnedFd::from`] (possibly from
    /// another process) into a [`Root`].
    ///
    /// While this function is not marked as `unsafe` (because the safety
    /// guarantee required is not related to memory-safety), users should still
    /// take great care when using this method because it can cause other kinds
    /// of unsafety.
    // TODO: We should probably have a `Root::from_file` which attempts to
    //       re-open the path with `O_PATH | O_DIRECTORY`, to allow for an
    //       alternative to `Root::open`.
    #[inline]
    pub fn from_fd_unchecked<Fd: Into<OwnedFd>>(fd: Fd) -> Self {
        Self {
            inner: fd.into(),
            resolver: Default::default(),
        }
    }

    /// Borrow this [`Root`] as a [`RootRef`].
    // XXX: We can't use Borrow/Deref for this because HandleRef takes a
    //      lifetime rather than being a pure reference. Ideally we would use
    //      Deref but it seems that won't be possible in standard Rust for a
    //      long time, if ever...
    #[inline]
    pub fn as_ref(&self) -> RootRef<'_> {
        RootRef {
            inner: self.as_fd(),
            resolver: self.resolver,
        }
    }

    /// Create a copy of an existing [`Root`].
    ///
    /// The new handle is completely independent from the original, but
    /// references the same underlying file and has the same configuration.
    #[inline]
    pub fn try_clone(&self) -> Result<Root, Error> {
        self.as_ref().try_clone()
    }

    /// Within the given [`Root`]'s tree, resolve `path` and return a
    /// [`Handle`].
    ///
    /// All symlink path components are scoped to [`Root`]. Trailing symlinks
    /// *are* followed, if you want to get a handle to a symlink use
    /// [`resolve_nofollow`].
    ///
    /// # Errors
    ///
    /// If `path` doesn't exist, or an attack was detected during resolution, a
    /// corresponding [`Error`] will be returned. If no error is returned, then
    /// the path is guaranteed to have been reachable from the root of the
    /// directory tree and thus have been inside the root at one point in the
    /// resolution.
    ///
    /// [`resolve_nofollow`]: Self::resolve_nofollow
    #[doc(alias = "pathrs_resolve")]
    #[inline]
    pub fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.as_ref().resolve(path)
    }

    /// Identical to [`resolve`], except that *trailing* symlinks are *not*
    /// followed.
    ///
    /// If the trailing component is a symlink [`resolve_nofollow`] will return
    /// a handle to the symlink itself. This is effectively equivalent to
    /// `O_NOFOLLOW`.
    ///
    /// [`resolve`]: Self::resolve
    /// [`resolve_nofollow`]: Self::resolve_nofollow
    #[doc(alias = "pathrs_resolve_nofollow")]
    #[inline]
    pub fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.as_ref().resolve_nofollow(path)
    }

    /// Get the target of a symlink within a [`Root`].
    ///
    /// **NOTE**: The returned path is not modified to be "safe" outside of the
    /// root. You should not use this path for doing further path lookups -- use
    /// [`resolve`] instead.
    ///
    /// This method is just shorthand for calling `readlinkat(2)` on the handle
    /// returned by [`resolve_nofollow`].
    ///
    /// [`resolve`]: Self::resolve
    /// [`resolve_nofollow`]: Self::resolve_nofollow
    #[doc(alias = "pathrs_readlink")]
    #[inline]
    pub fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Error> {
        self.as_ref().readlink(path)
    }

    /// Within the [`Root`]'s tree, create an inode at `path` as specified by
    /// `inode_type`.
    ///
    /// # Errors
    ///
    /// If the path already exists (regardless of the type of the existing
    /// inode), an error is returned.
    #[doc(alias = "pathrs_mkdir")]
    #[doc(alias = "pathrs_mknod")]
    #[doc(alias = "pathrs_symlink")]
    #[doc(alias = "pathrs_hardlink")]
    #[inline]
    pub fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Error> {
        self.as_ref().create(path, inode_type)
    }

    /// Create an [`InodeType::File`] within the [`Root`]'s tree at `path` with
    /// the mode given by `perm`, and return a [`Handle`] to the newly-created
    /// file.
    ///
    /// However, unlike the trivial way of doing the above:
    ///
    /// ```dead_code
    /// root.create(path, inode_type)?;
    /// // What happens if the file is replaced here!?
    /// let handle = root.resolve(path, perm)?;
    /// ```
    ///
    /// [`create_file`] guarantees that the returned [`Handle`] is the same as
    /// the file created by the operation. This is only possible to guarantee
    /// for ordinary files because there is no [`O_CREAT`]-equivalent for other
    /// inode types.
    ///
    /// # Errors
    ///
    /// Identical to [`create`].
    ///
    /// [`create`]: Self::create
    /// [`create_file`]: Self::create_file
    /// [`O_CREAT`]: http://man7.org/linux/man-pages/man2/open.2.html
    #[doc(alias = "pathrs_creat")]
    #[doc(alias = "pathrs_create")]
    #[inline]
    pub fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<Handle, Error> {
        self.as_ref().create_file(path, flags, perm)
    }

    /// Within the [`Root`]'s tree, create a directory and any of its parent
    /// component if they are missing. This is effectively equivalent to
    /// [`std::fs::create_dir_all`], Go's [`os.MkdirAll`], or Unix's `mkdir -p`.
    ///
    /// The provided set of [`Permissions`] only applies to path components
    /// created by this function, existing components will not have their
    /// permissions modified. In addition, if the provided path already exists
    /// and is a directory, this function will return successfully.
    ///
    /// The returned [`Handle`] is an `O_DIRECTORY` handle referencing the
    /// created directory (due to kernel limitations, we cannot guarantee that
    /// the handle is the exact directory created and not a similar-looking
    /// directory that was swapped in by an attacker, but we do as much
    /// validation as possible to make sure the directory is functionally
    /// identical to the directory we would've created).
    ///
    /// # Errors
    ///
    /// This method will return an error if any of the path components in the
    /// provided path were invalid (non-directory components or dangling symlink
    /// components) or if certain exchange attacks were detected.
    ///
    /// If an error occurs, it is possible for any number of the directories in
    /// `path` to have been created despite this method returning an error.
    ///
    /// [`os.MkdirAll`]: https://pkg.go.dev/os#MkdirAll
    #[doc(alias = "pathrs_mkdir_all")]
    #[inline]
    pub fn mkdir_all<P: AsRef<Path>>(&self, path: P, perm: &Permissions) -> Result<Handle, Error> {
        self.as_ref().mkdir_all(path, perm)
    }

    /// Within the [`Root`]'s tree, remove the empty directory at `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist, was not actually a directory, or was a
    /// non-empty directory an error will be returned. In order to remove a
    /// directory and all of its children, you can use [`remove_all`].
    ///
    /// [`remove_all`]: Self::remove_all
    #[doc(alias = "pathrs_rmdir")]
    #[inline]
    pub fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.as_ref().remove_dir(path)
    }

    /// Within the [`Root`]'s tree, remove the file (any non-directory inode) at
    /// `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist or was actually a directory an error will be
    /// returned. In order to remove a path regardless of its type (even if it
    /// is a non-empty directory), you can use [`remove_all`].
    ///
    /// [`remove_all`]: Self::remove_all
    #[doc(alias = "pathrs_unlink")]
    #[inline]
    pub fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.as_ref().remove_file(path)
    }

    /// Within the [`Root`]'s tree, recursively delete the provided `path` and
    /// any children it contains if it is a directory. This is effectively
    /// equivalent to [`std::fs::remove_dir_all`], Go's [`os.RemoveAll`], or
    /// Unix's `rm -r`.
    ///
    /// Any existing [`Handle`]s to paths within `path` will continue to work as
    /// before, since Linux does not invalidate file handles to unlinked files
    /// (though, directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist or some other error occurred during the
    /// deletion process an error will be returned.
    ///
    /// [`os.RemoveAll`]: https://pkg.go.dev/os#RemoveAll
    #[doc(alias = "pathrs_remove_all")]
    #[inline]
    pub fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.as_ref().remove_all(path)
    }

    /// Within the [`Root`]'s tree, perform a rename with the given `source` and
    /// `directory`. The `flags` argument is passed directly to
    /// [`renameat2(2)`].
    ///
    /// # Errors
    ///
    /// The error rules are identical to [`renameat2(2)`].
    ///
    /// [`renameat2(2)`]: http://man7.org/linux/man-pages/man2/renameat2.2.html
    #[doc(alias = "pathrs_rename")]
    pub fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Error> {
        self.as_ref().rename(source, destination, rflags)
    }
}

impl From<Root> for OwnedFd {
    /// Unwrap a [`Root`] to reveal the underlying [`OwnedFd`].
    ///
    /// **Note**: This method is primarily intended to allow for file descriptor
    /// passing or otherwise transmitting file descriptor information. It is not
    /// safe to use this [`OwnedFd`] directly to do filesystem operations.
    /// Please use the provided [`Root`] methods.
    fn from(root: Root) -> Self {
        root.inner
    }
}

impl AsFd for Root {
    /// Access the underlying file descriptor for a [`Root`].
    ///
    /// **Note**: This method is primarily intended to allow for tests and other
    /// code to check the status of the underlying [`OwnedFd`] without having to
    /// use [`OwnedFd::from`]. It is not safe to use this [`BorrowedFd`]
    /// directly to do filesystem operations. Please use the provided [`Root`]
    /// methods.
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Borrowed version of [`Root`].
///
/// Unlike [`Root`], when [`RootRef`] is dropped the underlying file descriptor
/// is *not* closed. This is mainly useful for programs and libraries that have
/// to do operations on [`&File`][File]s and [`BorrowedFd`]s passed from
/// elsewhere.
///
/// [File]: std::fs::File
// TODO: Is there any way we can restructure this to use Deref so that we don't
//       need to copy all of the methods into Handle? Probably not... Maybe GATs
//       will eventually support this but we'd still need a GAT-friendly Deref.
#[derive(Copy, Clone, Debug)]
pub struct RootRef<'fd> {
    inner: BorrowedFd<'fd>,
    // TODO: Drop this and switch to builder-pattern.
    pub resolver: Resolver,
}

impl RootRef<'_> {
    /// Wrap a [`BorrowedFd`] into a [`RootRef`]. The lifetime is tied to the
    /// [`BorrowedFd`].
    ///
    /// The configuration is set to the system default and should be configured
    /// prior to usage, if appropriate.
    ///
    /// # Safety
    ///
    /// The caller guarantees that the provided file is an `O_PATH` file
    /// descriptor with exactly the same semantics as one created through
    /// [`Root::open`]. This means that this function should usually be used to
    /// convert a [`BorrowedFd`] returned from [`AsFd::as_fd`] into a
    /// [`RootRef`].
    ///
    /// While this function is not marked as `unsafe` (because the safety
    /// guarantee required is not related to memory-safety), users should still
    /// take great care when using this method because it can cause other kinds
    /// of unsafety.
    // TODO: We should probably have a `Root::from_file` which attempts to
    //       re-open the path with `O_PATH | O_DIRECTORY`, to allow for an
    //       alternative to `Root::open`.
    pub fn from_fd_unchecked(inner: BorrowedFd<'_>) -> RootRef<'_> {
        RootRef {
            inner,
            resolver: Default::default(),
        }
    }

    /// Create a copy of a [`RootRef`].
    ///
    /// Note that (unlike [`BorrowedFd::clone`]) this method creates a full copy
    /// of the underlying file descriptor and thus is more equivalent to
    /// [`BorrowedFd::try_clone_to_owned`].
    ///
    /// To create a shallow copy of a [`RootRef`], you can use [`Clone::clone`]
    /// (or just [`Copy`]).
    pub fn try_clone(&self) -> Result<Root, Error> {
        Ok(Root {
            inner: self
                .as_fd()
                .try_clone_to_owned()
                .map_err(|err| ErrorImpl::OsError {
                    operation: "clone underlying root file".into(),
                    source: err,
                })?,
            resolver: self.resolver,
        })
    }

    /// Within the given [`RootRef`]'s tree, resolve `path` and return a
    /// [`Handle`].
    ///
    /// All symlink path components are scoped to [`RootRef`]. Trailing symlinks
    /// *are* followed, if you want to get a handle to a symlink use
    /// [`resolve_nofollow`].
    ///
    /// # Errors
    ///
    /// If `path` doesn't exist, or an attack was detected during resolution, a
    /// corresponding [`Error`] will be returned. If no error is returned, then
    /// the path is guaranteed to have been reachable from the root of the
    /// directory tree and thus have been inside the root at one point in the
    /// resolution.
    ///
    /// [`resolve_nofollow`]: Self::resolve_nofollow
    #[doc(alias = "pathrs_resolve")]
    #[inline]
    pub fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.resolver.resolve(self, path, false)
    }

    /// Identical to [`resolve`], except that *trailing* symlinks are *not*
    /// followed.
    ///
    /// If the trailing component is a symlink [`resolve_nofollow`] will return
    /// a handle to the symlink itself. This is effectively equivalent to
    /// `O_NOFOLLOW`.
    ///
    /// [`resolve`]: Self::resolve
    /// [`resolve_nofollow`]: Self::resolve_nofollow
    #[doc(alias = "pathrs_resolve_nofollow")]
    #[inline]
    pub fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.resolver.resolve(self, path, true)
    }

    // Used in operations where we need to get a handle to the parent directory.
    fn resolve_parent<'p>(&self, path: &'p Path) -> Result<(OwnedFd, Option<&'p Path>), Error> {
        let (parent, name) = utils::path_split(path).wrap("split path into (parent, name)")?;
        let dir = self
            .resolve(parent)
            .wrap("resolve parent directory")?
            .into();
        Ok((dir, name))
    }

    /// Get the target of a symlink within a [`RootRef`].
    ///
    /// **NOTE**: The returned path is not modified to be "safe" outside of the
    /// root. You should not use this path for doing further path lookups -- use
    /// [`resolve`] instead.
    ///
    /// This method is just shorthand for calling `readlinkat(2)` on the handle
    /// returned by [`resolve_nofollow`].
    ///
    /// [`resolve`]: Self::resolve
    /// [`resolve_nofollow`]: Self::resolve_nofollow
    #[doc(alias = "pathrs_readlink")]
    pub fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Error> {
        let link = self
            .resolve_nofollow(path)
            .wrap("resolve symlink O_NOFOLLOW for readlink")?;
        syscalls::readlinkat(link, "").map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "readlink resolve symlink".into(),
                source: err,
            }
            .into()
        })
    }

    /// Within the [`RootRef`]'s tree, create an inode at `path` as specified by
    /// `inode_type`.
    ///
    /// # Errors
    ///
    /// If the path already exists (regardless of the type of the existing
    /// inode), an error is returned.
    #[doc(alias = "pathrs_mkdir")]
    #[doc(alias = "pathrs_mknod")]
    #[doc(alias = "pathrs_symlink")]
    #[doc(alias = "pathrs_hardlink")]
    pub fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Error> {
        // The path doesn't exist yet, so we need to get a safe reference to the
        // parent and just operate on the final (slashless) component.
        let (dir, name) = self
            .resolve_parent(path.as_ref())
            .wrap("resolve file creation path")?;
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "file creation path has trailing slash".into(),
        })?;

        match inode_type {
            InodeType::File(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dir, name, libc::S_IFREG | mode, 0)
            }
            InodeType::Directory(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mkdirat(dir, name, mode)
            }
            InodeType::Symlink(target) => {
                // No need to touch target.
                syscalls::symlinkat(target, dir, name)
            }
            InodeType::Hardlink(target) => {
                let (olddir, oldname) = self
                    .resolve_parent(target)
                    .wrap("resolve hardlink source path")?;
                let oldname = oldname.ok_or_else(|| ErrorImpl::InvalidArgument {
                    name: "target".into(),
                    description: "hardlink target has trailing slash".into(),
                })?;
                syscalls::linkat(olddir, oldname, dir, name, 0)
            }
            InodeType::Fifo(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dir, name, libc::S_IFIFO | mode, 0)
            }
            InodeType::CharacterDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dir, name, libc::S_IFCHR | mode, *dev)
            }
            InodeType::BlockDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dir, name, libc::S_IFBLK | mode, *dev)
            }
        }
        .map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "pathrs create".into(),
                source: err,
            }
            .into()
        })
    }

    /// Create an [`InodeType::File`] within the [`RootRef`]'s tree at `path`
    /// with the mode given by `perm`, and return a [`Handle`] to the
    /// newly-created file.
    ///
    /// However, unlike the trivial way of doing the above:
    ///
    /// ```dead_code
    /// root.create(path, inode_type)?;
    /// // What happens if the file is replaced here!?
    /// let handle = root.resolve(path, perm)?;
    /// ```
    ///
    /// [`create_file`] guarantees that the returned [`Handle`] is the same as
    /// the file created by the operation. This is only possible to guarantee
    /// for ordinary files because there is no [`O_CREAT`]-equivalent for other
    /// inode types.
    ///
    /// # Errors
    ///
    /// Identical to [`create`].
    ///
    /// [`create`]: Self::create
    /// [`create_file`]: Self::create_file
    /// [`O_CREAT`]: http://man7.org/linux/man-pages/man2/open.2.html
    #[doc(alias = "pathrs_creat")]
    #[doc(alias = "pathrs_create")]
    pub fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        mut flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<Handle, Error> {
        // The path doesn't exist yet, so we need to get a safe reference to the
        // parent and just operate on the final (slashless) component.
        let (dir, name) = self
            .resolve_parent(path.as_ref())
            .wrap("resolve file creation path")?;
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "file creation path has trailing slash".into(),
        })?;

        // XXX: openat2(2) supports doing O_CREAT on trailing symlinks without
        // O_NOFOLLOW. We might want to expose that here, though because it
        // can't be done with the emulated backend that might be a bad idea.
        flags.insert(OpenFlags::O_CREAT);
        let fd = syscalls::openat(dir, name, flags.bits(), perm.mode()).map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "pathrs create_file".into(),
                source: err,
            }
        })?;

        Ok(Handle::from_fd_unchecked(fd))
    }

    /// Within the [`RootRef`]'s tree, create a directory and any of its parent
    /// component if they are missing.
    ///
    /// This is effectively equivalent to [`std::fs::create_dir_all`], Go's
    /// [`os.MkdirAll`], or Unix's `mkdir -p`.
    ///
    /// The provided set of [`Permissions`] only applies to path components
    /// created by this function, existing components will not have their
    /// permissions modified. In addition, if the provided path already exists
    /// and is a directory, this function will return successfully.
    ///
    /// The returned [`Handle`] is an `O_DIRECTORY` handle referencing the
    /// created directory (due to kernel limitations, we cannot guarantee that
    /// the handle is the exact directory created and not a similar-looking
    /// directory that was swapped in by an attacker, but we do as much
    /// validation as possible to make sure the directory is functionally
    /// identical to the directory we would've created).
    ///
    /// # Errors
    ///
    /// This method will return an error if any of the path components in the
    /// provided path were invalid (non-directory components or dangling symlink
    /// components) or if certain exchange attacks were detected.
    ///
    /// If an error occurs, it is possible for any number of the directories in
    /// `path` to have been created despite this method returning an error.
    ///
    /// [`os.MkdirAll`]: https://pkg.go.dev/os#MkdirAll
    #[doc(alias = "pathrs_mkdir_all")]
    pub fn mkdir_all<P: AsRef<Path>>(&self, path: P, perm: &Permissions) -> Result<Handle, Error> {
        if perm.mode() & !0o7777 != 0 {
            Err(ErrorImpl::InvalidArgument {
                name: "perm".into(),
                description: "mode cannot contain non-0o7777 bits".into(),
            })?
        }
        // Linux silently ignores S_IS[UG]ID if passed to mkdirat(2), and a lot
        // of libraries just ignore these flags. However, ignoring them as a new
        // library seems less than ideal -- users shouldn't set flags that are
        // no-ops because they might not notice they are no-ops.
        if perm.mode() & !0o1777 != 0 {
            Err(ErrorImpl::InvalidArgument {
                name: "perm".into(),
                description:
                    "mode contains setuid or setgid bits that are silently ignored by mkdirat"
                        .into(),
            })?
        }

        let (handle, remaining) = self
            .resolver
            .resolve_partial(self, path.as_ref(), false)
            .and_then(TryInto::try_into)?;

        // Re-open the handle with O_DIRECTORY to make sure it's a directory we
        // can use as well as to make sure we return an O_DIRECTORY regardless
        // of whether there are any remaining components (for consistency).
        let mut current = handle
            .reopen(OpenFlags::O_DIRECTORY)
            .with_wrap(|| format!("cannot create directories in {}", FrozenFd::from(handle)))?;

        // For the remaining
        let remaining_parts = remaining
            .iter()
            .flat_map(PathIterExt::raw_components)
            .map(|p| p.to_os_string())
            // Skip over no-op entries.
            .filter(|part| !part.is_empty() && part.as_bytes() != b".")
            .collect::<Vec<_>>();

        // If the path contained ".." components after the end of the "real"
        // components, we simply error out. We could try to safely resolve ".."
        // here but that would add a bunch of extra logic for something that
        // it's not clear even needs to be supported.
        //
        // We also can't just do something like filepath.Clean(), because ".."
        // could erase dangling symlinks and produce a path that doesn't match
        // what the user asked for.
        if remaining_parts.iter().any(|part| part.as_bytes() == b"..") {
            Err(ErrorImpl::OsError {
                operation: "mkdir_all remaining components".into(),
                source: IOError::from_raw_os_error(libc::ENOENT),
            })
            .with_wrap(|| {
                format!("yet-to-be-created path {remaining:?} contains '..' components")
            })?
        }

        // Calculate what properties we expect each newly created directory to
        // have. Note that we need to manually calculate the effect of the umask
        // (we default to 0o022 since that's what almost everyone uses in
        // practice).
        //
        // NOTE: Another thread (or process with CLONE_FS) could change our
        // umask after this check. This would at worst result in spurious
        // errors, but it seems to me that a multithreaded program setting its
        // own umask() is probably not safe in general anyway. umask() is meant
        // to be used for shells when spawning subprocesses.
        let (want_uid, want_gid, want_mode) = {
            let want_uid = syscalls::geteuid();
            let mut want_gid = syscalls::getegid();
            let mut want_mode = libc::S_IFDIR
                | (perm.mode() & !utils::get_umask(Some(&GLOBAL_PROCFS_HANDLE)).unwrap_or(0o022));

            // The setgid bit is inherited to child directories and affects the
            // group owner of any inodes created in said directory, so if the
            // starting directory has it set we need to adjust our expected mode
            // and owner to match.
            let dir_meta = current.metadata().map_err(|err| ErrorImpl::OsError {
                operation: "get starting directory metadata".into(),
                source: err,
            })?;
            if dir_meta.st_mode() & libc::S_ISGID == libc::S_ISGID {
                want_gid = dir_meta.st_gid();
                want_mode |= libc::S_ISGID;
            }
            (want_uid, want_gid, want_mode)
        };

        // For the remaining components, create a each component one-by-one.
        for part in remaining_parts {
            // NOTE: mkdirat(2) does not follow trailing symlinks (even if it is
            // a dangling symlink with only a trailing component missing), so we
            // can safely create the final component without worrying about
            // symlink-exchange attacks.
            syscalls::mkdirat(&current, &part, perm.mode()).map_err(|err| {
                ErrorImpl::RawOsError {
                    operation: "create next directory component".into(),
                    source: err,
                }
            })?;

            // Get a handle to the directory we just created. Unfortunately we
            // can't do an atomic create+open (a-la O_CREAT) with mkdirat(), so
            // a separate O_NOFOLLOW is the best we can do.
            let next = self
                .resolver
                .resolve(&current, &part, true)
                .and_then(|handle| handle.reopen(OpenFlags::O_DIRECTORY))
                .wrap("failed to open newly-created directory with O_DIRECTORY")?;

            // Do some extra verification that the next handle looks like the
            // directory we just created. There is no way to be absolutely sure
            // it wasn't a swapped directory, but we can try to make sure that
            // it looks as-close-to-identical-as-you-can-get.
            //
            // These protections probably don't protect against serious attacks
            // in practice, but it's better to be safe than sorry. The main goal
            // is to ensure that a less-privileged process cannot trick us into
            // creating directories inside directories we don't expect. In
            // fairness, the semantics of mkdir_all are kind of loose in general
            // so it's not really clear how necessary this is.

            // Verify that the (uid, gid, mode) match what we expect.
            let meta = next.metadata().map_err(|err| ErrorImpl::OsError {
                operation: "fstat next directory component".into(),
                source: err,
            })?;

            let (got_uid, got_gid) = (meta.st_uid(), meta.st_gid());
            let got_mode = meta.st_mode();
            if (got_uid, got_gid, got_mode) != (want_uid, want_gid, want_mode) {
                Err(ErrorImpl::SafetyViolation {
                    description: format!("newly-created directory {part:?} appears to have been swapped (expected owner {want_uid}:{want_gid} mode 0o{want_mode:o}, got owner {got_uid}:{got_gid} mode 0o{got_mode:o})").into(),
                })?
            }

            // Make sure the directory is empty. Obviously, an attacker could
            // create entries in the directory after this call (if they have
            // sufficient privileges) but if the attacker can create entries in
            // this directory (that has the same owner and permission bits as
            // the directory we created) then they could've done so in the
            // directory we created as well.
            let has_children = {
                // NOTE: Unfortunately, this creates a new internal copy of the
                // file for fs::Dir. At the moment we can't use fs::RawDir
                // (which can take a BorrowedFd) because it doesn't implement
                // Iterator and so filtering out the "." and ".." entries will
                // be quite ugly.
                // TODO: Switch back to RawDir once they fix that issue, or
                // create our own wrapper that implements Iterator.
                // Unfortunately because RawDir takes AsFd, it seems likely we
                // won't be able to express the right lifetime bounds...
                let mut dir = Dir::read_from(&next)
                    .map_err(|err| ErrorImpl::OsError {
                        operation: "create directory iterator".into(),
                        source: err.into(),
                    })
                    .with_wrap(|| format!("scan newly-created directory {part:?}"))?;

                // Is there is any entry in the directory?
                dir
                    // Get the first non-"."/".." entry.
                    .find(|res| {
                        !matches!(
                            res.as_ref().map(|dentry| dentry.file_name().to_bytes()),
                            Ok(b".") | Ok(b"..")
                        )
                    })
                    // Handle errors.
                    // TODO: Use try_find() once it's stabilised.
                    // <https://github.com/rust-lang/rust/issues/63178>
                    .transpose()
                    .map_err(|err| ErrorImpl::OsError {
                        operation: "readdir".into(),
                        source: err.into(),
                    })
                    .with_wrap(|| format!("scan newly-created directory {part:?}"))?
                    // We only care if there was an entry, not its details.
                    .is_some()
            };
            if has_children {
                Err(ErrorImpl::SafetyViolation {
                    description: format!(
                        "newly-created directory {part:?} is not an empty directory"
                    )
                    .into(),
                })?
            }
            // Rewind the directory so that the caller doesn't end up with a
            // half-read directory iterator. We have to do this manually rather
            // than using Dir::rewind() because Dir::rewind() just marks the
            // iterator so it is rewinded when the next iteration happens.
            rustix_fs::seek(&next, SeekFrom::Start(0)).map_err(|err| ErrorImpl::OsError {
                operation: "reset offset of directory handle".into(),
                source: err.into(),
            })?;

            // Keep walking.
            current = next;
        }

        Ok(Handle::from_fd_unchecked(current))
    }

    /// Within the [`RootRef`]'s tree, remove the inode of type `inode_type` at
    /// `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist, was not actually `inode_type`, or was a
    /// non-empty directory an error will be returned. In order to remove a path
    /// regardless of whether it exists, its type, or if it it's a non-empty
    /// directory, you can use [`remove_all`].
    ///
    /// [`remove_all`]: Self::remove_all
    fn remove_inode(&self, path: &Path, inode_type: RemoveInodeType) -> Result<(), Error> {
        // unlinkat(2) doesn't let us remove an inode using just a handle (for
        // obvious reasons -- on Unix hardlinks mean that "unlink this file"
        // doesn't make sense without referring to a specific directory entry).
        let (dir, name) = self
            .resolve_parent(path.as_ref())
            .wrap("resolve file removal path")?;
        // TODO: rmdir() lets you use trailing slashes. We should probably allow
        //       that too...
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "file removal path has trailing slash".into(),
        })?;

        let flags = match inode_type {
            RemoveInodeType::Regular => 0,
            RemoveInodeType::Directory => libc::AT_REMOVEDIR,
        };
        syscalls::unlinkat(dir, name, flags).map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "pathrs remove".into(),
                source: err,
            }
            .into()
        })
    }

    /// Within the [`RootRef`]'s tree, remove the empty directory at `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist, was not actually a directory, or was a
    /// non-empty directory an error will be returned. In order to remove a
    /// directory and all of its children, you can use [`remove_all`].
    ///
    /// [`remove_all`]: Self::remove_all
    #[doc(alias = "pathrs_rmdir")]
    #[inline]
    pub fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.remove_inode(path.as_ref(), RemoveInodeType::Directory)
    }

    /// Within the [`RootRef`]'s tree, remove the file (any non-directory inode)
    /// at `path`.
    ///
    /// Any existing [`Handle`]s to `path` will continue to work as before,
    /// since Linux does not invalidate file handles to unlinked files (though,
    /// directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist or was actually a directory an error will be
    /// returned. In order to remove a path regardless of its type (even if it
    /// is a non-empty directory), you can use [`remove_all`].
    ///
    /// [`remove_all`]: Self::remove_all
    #[doc(alias = "pathrs_unlink")]
    #[inline]
    pub fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        self.remove_inode(path.as_ref(), RemoveInodeType::Regular)
    }

    /// Within the [`RootRef`]'s tree, recursively delete the provided `path`
    /// and any children it contains if it is a directory. This is effectively
    /// equivalent to [`std::fs::remove_dir_all`], Go's [`os.RemoveAll`], or
    /// Unix's `rm -r`.
    ///
    /// Any existing [`Handle`]s to paths within `path` will continue to work as
    /// before, since Linux does not invalidate file handles to unlinked files
    /// (though, directory handling is not as simple).
    ///
    /// # Errors
    ///
    /// If the path does not exist or some other error occurred during the
    /// deletion process an error will be returned.
    ///
    /// [`os.RemoveAll`]: https://pkg.go.dev/os#RemoveAll
    #[doc(alias = "pathrs_remove_all")]
    pub fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let (dir, name) = self
            .resolve_parent(path.as_ref())
            .wrap("resolve remove-all path")?;
        // TODO: rmdir() lets you use trailing slashes. We should probably allow
        //       that too...
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "file removal path has trailing slash".into(),
        })?;

        utils::remove_all(&dir, name)
    }

    /// Within the [`RootRef`]'s tree, perform a rename with the given `source`
    /// and `directory`. The `flags` argument is passed directly to
    /// [`renameat2(2)`].
    ///
    /// # Errors
    ///
    /// The error rules are identical to [`renameat2(2)`].
    ///
    /// [`renameat2(2)`]: http://man7.org/linux/man-pages/man2/renameat2.2.html
    #[doc(alias = "pathrs_rename")]
    pub fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Error> {
        // renameat2(2) doesn't let us rename paths using just handles. In
        // addition, the target path might not exist (except in the case of
        // RENAME_EXCHANGE and clobbering).
        let (src_dir, src_name) = self
            .resolve_parent(source.as_ref())
            .wrap("resolve rename source path")?;
        let src_name = src_name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "source".into(),
            description: "rename source path has trailing slash".into(),
        })?;
        let (dst_dir, dst_name) = self
            .resolve_parent(destination.as_ref())
            .wrap("resolve rename destination path")?;
        let dst_name = dst_name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "destination".into(),
            description: "rename destination path has trailing slash".into(),
        })?;

        syscalls::renameat2(src_dir, src_name, dst_dir, dst_name, rflags.bits()).map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "pathrs rename".into(),
                source: err,
            }
            .into()
        })
    }
}

impl AsFd for RootRef<'_> {
    /// Access the underlying file descriptor for a [`RootRef`].
    ///
    /// **Note**: This method is primarily intended to allow for tests and other
    /// code to check the status of the underlying file descriptor. It is not
    /// safe to use this [`BorrowedFd`] directly to do filesystem operations.
    /// Please use the provided [`RootRef`] methods.
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Root, RootRef};

    use std::os::unix::io::{AsFd, AsRawFd};

    use anyhow::Error;
    use pretty_assertions::assert_eq;

    #[test]
    fn from_fd_unchecked() -> Result<(), Error> {
        let root = Root::open(".")?;
        let root_ref1 = root.as_ref();
        let root_ref2 = RootRef::from_fd_unchecked(root.as_fd());

        assert_eq!(
            root.as_fd().as_raw_fd(),
            root_ref1.as_fd().as_raw_fd(),
            "Root::as_ref should have the same underlying fd"
        );
        assert_eq!(
            root.as_fd().as_raw_fd(),
            root_ref2.as_fd().as_raw_fd(),
            "RootRef::from_fd_unchecked should have the same underlying fd"
        );

        Ok(())
    }
}

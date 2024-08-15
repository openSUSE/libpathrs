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
    procfs::PROCFS_HANDLE,
    resolvers::Resolver,
    syscalls::{self, FrozenFd},
    utils::{self, PathIterExt},
    Handle,
};

use std::{
    fs::{File, Permissions},
    io::Error as IOError,
    os::{
        linux::fs::MetadataExt,
        unix::{ffi::OsStrExt, fs::PermissionsExt, io::AsRawFd},
    },
    path::{Path, PathBuf},
};

use libc::dev_t;
use rustix::fs::{self, Dir, SeekFrom};

/// An inode type to be created with [`Root::create`].
///
/// [`Root::create`]: struct.Root.html#method.create
#[derive(Clone, Debug)]
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

    /// Symlink with the given [`Path`], as in [`symlinkat(2)`].
    ///
    /// Note that symlinks can contain any arbitrary `CStr`-style string (it
    /// doesn't need to be a real pathname). We don't do any verification of the
    /// target name.
    ///
    /// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
    /// [`symlinkat(2)`]: http://man7.org/linux/man-pages/man2/symlinkat.2.html
    Symlink(PathBuf),

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
#[derive(Debug)]
pub struct Root {
    /// The underlying `O_PATH` `File` for this root handle.
    inner: File,

    /// The underlying [`Resolver`] to use for all operations underneath this
    /// root. This affects not just [`Root::resolve`] but also all other methods
    /// which have to implicitly resolve a path underneath `Root`.
    ///
    /// [`Resolver`]: struct.Resolver.html
    /// [`Root::resolve`]: #method.resolve
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
    ///
    /// [`Root`]: struct.Root.html
    /// [`Resolver`]: struct.Resolver.html
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = syscalls::openat(libc::AT_FDCWD, path, libc::O_PATH | libc::O_DIRECTORY, 0)
            .map_err(|err| ErrorImpl::RawOsError {
                operation: "open root handle".into(),
                source: err,
            })?;
        Ok(Root::from_file_unchecked(file))
    }

    /// Create a copy of an existing [`Root`].
    ///
    /// The new handle is completely independent from the original, but
    /// references the same underlying file and has the same configuration.
    ///
    /// [`Root`]: struct.Root.html
    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(Self {
            inner: self
                .as_file()
                .try_clone()
                .map_err(|err| ErrorImpl::OsError {
                    operation: "clone underlying root file".into(),
                    source: err,
                })?,
            resolver: self.resolver,
        })
    }

    /// Unwrap a [`Root`] to reveal the underlying [`File`].
    ///
    /// **Note**: This method is primarily intended to allow for file descriptor
    /// passing or otherwise transmitting file descriptor information. It is not
    /// safe to use this [`File`] directly to do filesystem operations. Please
    /// use the provided [`Root`] methods.
    ///
    /// [`Root`]: struct.Root.html
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    pub fn into_file(self) -> File {
        self.inner
    }

    /// Access the underlying [`File`] for a [`Root`].
    ///
    /// **Note**: This method is primarily intended to allow for tests and other
    /// code to check the status of the underlying [`File`] without having to
    /// use [`Root::into_file`]. It is not safe to use this [`File`] directly
    /// to do filesystem operations. Please use the provided [`Root`] methods.
    ///
    /// [`Root`]: struct.Root.html
    /// [`Root::into_file`]: struct.Root.html#method.into_file
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    pub fn as_file(&self) -> &File {
        &self.inner
    }

    /// Wrap a [`File`] into a [`Root`].
    ///
    /// The configuration is set to the system default and should be configured
    /// prior to usage, if appropriate.
    ///
    /// # Safety
    ///
    /// The caller guarantees that the provided file is an `O_PATH` file
    /// descriptor with exactly the same semantics as one created through
    /// [`Root::open`]. This means that this function should usually be used to
    /// convert a [`File`] returned from [`Root::into_file`] (possibly from
    /// another process) into a [`Root`].
    ///
    /// While this function is not marked as `unsafe` (because the safety
    /// guarantee required is not related to memory-safety), users should still
    /// take great care when using this method because it can cause other kinds
    /// of unsafety.
    ///
    /// [`Root`]: struct.Root.html
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    /// [`Root::open`]: struct.Root.html#method.open
    /// [`Root::into_file`]: struct.Root.html#method.into_file
    // TODO: We should probably have a `Root::from_file` which attempts to
    //       re-open the path with `O_PATH | O_DIRECTORY`, to allow for an
    //       alternative to `Root::open`.
    pub fn from_file_unchecked(inner: File) -> Self {
        Self {
            inner,
            resolver: Default::default(),
        }
    }

    /// Within the given [`Root`]'s tree, resolve `path` and return a
    /// [`Handle`]. All symlink path components are scoped to [`Root`]. Trailing
    /// symlinks *are* followed, if you want to get a handle to a symlink use
    /// [`Root::resolve_nofollow`].
    ///
    /// # Errors
    ///
    /// If `path` doesn't exist, or an attack was detected during resolution, a
    /// corresponding [`Error`] will be returned. If no error is returned, then
    /// the path is guaranteed to have been reachable from the root of the
    /// directory tree and thus have been inside the root at one point in the
    /// resolution.
    ///
    /// [`Root`]: struct.Root.html
    /// [`Handle`]: trait.Handle.html
    /// [`Error`]: error/struct.Error.html
    /// [`Root::resolve_nofollow`]: struct.Root.html#method.resolve_nofollow
    #[inline]
    pub fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.resolver.resolve(&self.inner, path, false)
    }

    /// Identical to [`Root::resolve`], except that *trailing* symlinks are
    /// *not* followed and if the trailing component is a symlink
    /// `Root::resolve_nofollow` will return a handle to the symlink itself.
    ///
    /// [`Root::resolve`]: struct.Root.html#method.resolve
    #[inline]
    pub fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.resolver.resolve(&self.inner, path, true)
    }

    /// Get the target of a symlink within a [`Root`].
    ///
    /// **NOTE**: The returned path is not modified to be "safe" outside of the
    /// root. You should not use this path for doing further path lookups -- use
    /// [`Root::resolve`] instead.
    ///
    /// This method is just shorthand for calling `readlinkat(2)` on the handle
    /// returned by [`Root::resolve_nofollow`].
    ///
    /// [`Root`]: struct.Root.html
    /// [`Root::resolve`]: struct.Root.html#method.resolve
    /// [`Root::resolve_nofollow`]: struct.Root.html#method.resolve_nofollow
    pub fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Error> {
        let link = self
            .resolve_nofollow(path)
            .wrap("resolve symlink O_NOFOLLOW for readlink")?;
        syscalls::readlinkat(link.as_file().as_raw_fd(), "").map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "readlink resolve symlink".into(),
                source: err,
            }
            .into()
        })
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
    pub fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Error> {
        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) =
            utils::path_split(path.as_ref()).wrap("split target path into (parent, name)")?;
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "create path has trailing slash".into(),
        })?;

        let dir = self
            .resolve(parent)
            .wrap("resolve target parent directory for inode creation")?
            .into_file();
        let dirfd = dir.as_raw_fd();

        match inode_type {
            InodeType::File(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dirfd, name, libc::S_IFREG | mode, 0)
            }
            InodeType::Directory(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mkdirat(dirfd, name, mode)
            }
            InodeType::Symlink(target) => {
                // No need to touch target.
                syscalls::symlinkat(target, dirfd, name)
            }
            InodeType::Hardlink(target) => {
                let (oldparent, oldname) = utils::path_split(target)
                    .wrap("split hardlink source path into (parent, name)")?;
                let oldname = oldname.ok_or_else(|| ErrorImpl::InvalidArgument {
                    name: "target".into(),
                    description: "hardlink target has trailing slash".into(),
                })?;
                let olddir = self
                    .resolve(oldparent)
                    .wrap("resolve hardlink source parent for hardlink")?
                    .into_file();
                let olddirfd = olddir.as_raw_fd();
                syscalls::linkat(olddirfd, oldname, dirfd, name, 0)
            }
            InodeType::Fifo(perm) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dirfd, name, libc::S_IFIFO | mode, 0)
            }
            InodeType::CharacterDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dirfd, name, libc::S_IFCHR | mode, *dev)
            }
            InodeType::BlockDevice(perm, dev) => {
                let mode = perm.mode() & !libc::S_IFMT;
                syscalls::mknodat(dirfd, name, libc::S_IFBLK | mode, *dev)
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
        mut flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<Handle, Error> {
        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) =
            utils::path_split(path.as_ref()).wrap("split target path into (parent, name)")?;
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "create_file path has trailing slash".into(),
        })?;
        let dir = self
            .resolve(parent)
            .wrap("resolve target parent directory for inode creation")?
            .into_file();
        let dirfd = dir.as_raw_fd();

        // XXX: openat2(2) supports doing O_CREAT on trailing symlinks without
        // O_NOFOLLOW. We might want to expose that here, though because it
        // can't be done with the emulated backend that might be a bad idea.
        flags.insert(OpenFlags::O_CREAT);
        let file = syscalls::openat(dirfd, name, flags.bits(), perm.mode()).map_err(|err| {
            ErrorImpl::RawOsError {
                operation: "pathrs create_file".into(),
                source: err,
            }
        })?;

        Ok(Handle::from_file_unchecked(file))
    }

    /// Within the [`Root`]'s tree, create a directory and any of its parent
    /// component if they are missing. This is effectively equivalent to
    /// [`fs::create_dir_all`], Go's [`os.MkdirAll`], or Unix's `mkdir -p`.
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
    /// [`Root`]: struct.Root.html
    /// [`Handle`]: struct.Handle.html
    /// [`Permissions`]: https://doc.rust-lang.org/stable/std/fs/struct.Permissions.html
    /// [`fs::create_dir_all`]: https://doc.rust-lang.org/stable/std/fs/fn.create_dir_all.html
    /// [`os.MkdirAll`]: https://pkg.go.dev/os#MkdirAll
    pub fn mkdir_all<P: AsRef<Path>>(&self, path: P, perm: &Permissions) -> Result<Handle, Error> {
        if perm.mode() & !0o7777 != 0 {
            Err(ErrorImpl::InvalidArgument {
                name: "perm".into(),
                description: "mode cannot contain non-0o7777 bits".into(),
            })?
        }

        let (handle, remaining) = self
            .resolver
            .resolve_partial(&self.inner, path.as_ref(), false)
            .and_then(TryInto::try_into)?;

        // Re-open the handle with O_DIRECTORY to make sure it's a directory we
        // can use as well as to make sure we return
        // directoriy
        let mut current = handle.reopen(OpenFlags::O_DIRECTORY).with_wrap(|| {
            format!(
                "cannot create directories in {}",
                FrozenFd::from(handle.as_file().as_raw_fd())
            )
        })?;

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
        let (want_uid, want_gid) = (syscalls::geteuid(), syscalls::getegid());
        let want_mode = libc::S_IFDIR
            | (perm.mode() & !utils::get_umask(Some(&PROCFS_HANDLE)).unwrap_or(0o022));

        // For the remaining components, create a each component one-by-one.
        for part in remaining_parts {
            // NOTE: mkdirat(2) does not follow trailing symlinks (even if it is
            // a dangling symlink with only a trailing component missing), so we
            // can safely create the final component without worrying about
            // symlink-exchange attacks.
            syscalls::mkdirat(current.as_raw_fd(), &part, perm.mode()).map_err(|err| {
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
            fs::seek(&next, SeekFrom::Start(0)).map_err(|err| ErrorImpl::OsError {
                operation: "reset offset of directory handle".into(),
                source: err.into(),
            })?;

            // Keep walking.
            current = next;
        }

        Ok(Handle::from_file_unchecked(current))
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
    pub fn remove<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        // Get a handle for the lexical parent of the target path. It must
        // already exist, and once we have it we're safe from rename races in
        // the parent.
        let (parent, name) =
            utils::path_split(path.as_ref()).wrap("split target path into (parent, name)")?;
        let name = name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "path".into(),
            description: "remove path has trailing slash".into(),
        })?;
        let dir = self
            .resolve(parent)
            .wrap("resolve target parent directory for inode creation")?
            .into_file();
        let dirfd = dir.as_raw_fd();

        // There is no kernel API to "just remove this inode please". You need
        // to know ahead-of-time what inode type it is. So we will try a couple
        // of times and bail if we managed to hit an inode-type race multiple
        // times.
        let mut last_error: Option<syscalls::Error> = None;
        for _ in 0..16 {
            // XXX: A try-block would be super useful here but that's not a
            //     thing in Rust unfortunately. So we need to manage last_error
            //     ourselves the old fashioned way.

            let stat = match syscalls::fstatat(dirfd, name) {
                Ok(stat) => stat,
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            };

            let mut flags = 0;
            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                flags |= libc::AT_REMOVEDIR;
            }

            match syscalls::unlinkat(dirfd, name, flags) {
                Ok(_) => return Ok(()),
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            }
        }

        Err(ErrorImpl::RawOsError {
            operation: "pathrs remove".into(),
            // If we ever are here, then last_error must be Some.
            source: last_error.expect("unlinkat loop failed so last_error must exist"),
        })?
    }

    /// Within the [`Root`]'s tree, perform a rename with the given `source` and
    /// `directory`. The `flags` argument is passed directly to
    /// [`renameat2(2)`].
    ///
    /// # Errors
    ///
    /// The error rules are identical to [`renameat2(2)`].
    ///
    /// [`Root`]: struct.Root.html
    /// [`renameat2(2)`]: http://man7.org/linux/man-pages/man2/renameat2.2.html
    pub fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Error> {
        let (src_parent, src_name) =
            utils::path_split(source.as_ref()).wrap("split source path into (parent, name)")?;
        let src_name = src_name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "source".into(),
            description: "rename source path has trailing slash".into(),
        })?;
        let (dst_parent, dst_name) = utils::path_split(destination.as_ref())
            .wrap("split target path into (parent, name)")?;
        let dst_name = dst_name.ok_or_else(|| ErrorImpl::InvalidArgument {
            name: "source".into(),
            description: "rename destination path has trailing slash".into(),
        })?;

        let src_dir = self
            .resolve(src_parent)
            .wrap("resolve source path for rename")?
            .into_file();
        let src_dirfd = src_dir.as_raw_fd();
        let dst_dir = self
            .resolve(dst_parent)
            .wrap("resolve target path for rename")?
            .into_file();
        let dst_dirfd = dst_dir.as_raw_fd();

        syscalls::renameat2(src_dirfd, src_name, dst_dirfd, dst_name, rflags.bits()).map_err(
            |err| {
                ErrorImpl::RawOsError {
                    operation: "pathrs rename".into(),
                    source: err,
                }
                .into()
            },
        )
    }

    // TODO: remove_all()

    // TODO: implement a way to duplicate (and even serialise) Roots so that you
    //       can send them between processes (presumably with SCM_RIGHTS).
}

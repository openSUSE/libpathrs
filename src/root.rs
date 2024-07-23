/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

#![forbid(unsafe_code)]

use crate::{
    error::{self, Error, ErrorExt},
    resolvers::Resolver,
    syscalls,
    utils::RawFdExt,
    Handle, OpenFlags,
};

use std::{
    fs::{File, Permissions},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, io::AsRawFd},
    path::Path,
};

use libc::dev_t;
use snafu::{OptionExt, ResultExt};

/// An inode type to be created with [`Root::create`].
///
/// [`Root::create`]: struct.Root.html#method.create
#[derive(Copy, Clone, Debug)]
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
    /// Note that symlinks can contain any arbitrary `CStr`-style string (it
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
    // XXX: Does this really make sense?
    //// "Detached" unix socket, as in [`mknod(2)`] with `S_IFSOCK`.
    ////
    //// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    //DetachedSocket(),
}

/// Helper to split a Path into its parent directory and trailing path. The
/// trailing component is guaranteed to not contain a directory separator.
fn path_split(path: &'_ Path) -> Result<(&'_ Path, &'_ Path), Error> {
    // Get the parent path.
    let parent = path.parent().unwrap_or_else(|| "/".as_ref());

    // Now construct the trailing portion of the target.
    let name = path.file_name().context(error::InvalidArgumentSnafu {
        name: "path",
        description: "no trailing component",
    })?;

    // It's critical we are only touching the final component in the path.
    // If there are any other path components we must bail.
    ensure!(
        !name.as_bytes().contains(&b'/'),
        error::SafetyViolationSnafu {
            description: "trailing component of split pathname contains '/'",
        }
    );
    Ok((parent, name.as_ref()))
}

/// Wrapper for the underlying `libc`'s `RENAME_*` flags.
///
/// The flag values and their meaning is identical to the description in the
/// [`renameat2(2)`] man page.
///
/// [`renameat2(2)`] might not not be supported on your kernel -- in which
/// case [`Root::rename`] will fail if you specify any RenameFlags. You can
/// verify whether [`renameat2(2)`] flags are supported by calling
/// [`RenameFlags::supported`].
///
/// [`renameat2(2)`]: http://man7.org/linux/man-pages/man2/rename.2.html
/// [`Root::rename`]: struct.Root.html#method.rename
/// [`RenameFlags::supported`]: struct.RenameFlags.html#method.supported
// TODO: Switch to bitflags!.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RenameFlags(pub u32);

impl RenameFlags {
    /// Is this set of RenameFlags supported by the running kernel?
    pub fn supported(self) -> bool {
        self.0 == 0 || *syscalls::RENAME_FLAGS_SUPPORTED
    }
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
            .context(error::RawOsSnafu {
                operation: "open root handle",
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
            inner: self.inner.try_clone_hotfix()?,
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
    #[inline]
    pub fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Handle, Error> {
        self.resolver.resolve(&self.inner, path)
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
            path_split(path.as_ref()).wrap("split target path into (parent, name)")?;
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
                // I have no idea why &name is required here. it might be a
                // compiler bug (the last argument seems to always be &&Path
                // even if you switch around the argument order).
                syscalls::symlinkat(target, dirfd, &name)
            }
            InodeType::Hardlink(target) => {
                let (oldparent, oldname) =
                    path_split(target).wrap("split hardlink source path into (parent, name)")?;
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
        .context(error::RawOsSnafu {
            operation: "pathrs create",
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
            path_split(path.as_ref()).wrap("split target path into (parent, name)")?;
        let dir = self
            .resolve(parent)
            .wrap("resolve target parent directory for inode creation")?
            .into_file();
        let dirfd = dir.as_raw_fd();

        // XXX: openat2(2) supports doing O_CREAT on trailing symlinks without
        // O_NOFOLLOW. We might want to expose that here, though because it
        // can't be done with the emulated backend that might be a bad idea.
        flags.insert(OpenFlags::O_CREAT);
        let file = syscalls::openat(dirfd, name, flags.bits(), perm.mode()).context(
            error::RawOsSnafu {
                operation: "pathrs create_file",
            },
        )?;

        Ok(Handle::from_file_unchecked(file))
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
            path_split(path.as_ref()).wrap("split target path into (parent, name)")?;
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

        // If we ever are here, then last_error must be Some.
        Err(last_error.expect("unlinkat loop failed so last_error must exist")).context(
            error::RawOsSnafu {
                operation: "pathrs remove",
            },
        )
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
        flags: RenameFlags,
    ) -> Result<(), Error> {
        let (src_parent, src_name) =
            path_split(source.as_ref()).wrap("split source path into (parent, name)")?;
        let (dst_parent, dst_name) =
            path_split(destination.as_ref()).wrap("split target path into (parent, name)")?;

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

        syscalls::renameat2(src_dirfd, src_name, dst_dirfd, dst_name, flags.0).context(
            error::RawOsSnafu {
                operation: "pathrs rename",
            },
        )
    }

    // TODO: mkdir_all()

    // TODO: remove_all()

    // TODO: implement a way to duplicate (and even serialise) Roots so that you
    //       can send them between processes (presumably with SCM_RIGHTS).
}

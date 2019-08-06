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

use crate::{
    kernel, syscalls, user,
    utils::{RawFdExt, PATH_SEPARATOR},
};
use crate::{Error, Handle};

use core::convert::TryFrom;
use std::fs::{File, Permissions};
use std::ops::Deref;
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, io::AsRawFd};
use std::path::{Path, PathBuf};

use failure::{Error as FailureError, ResultExt};
use libc::{c_int, dev_t};

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
    // XXX: Does this really make sense?
    //// "Detached" unix socket, as in [`mknod(2)`] with `S_IFSOCK`.
    ////
    //// [`mknod(2)`]: http://man7.org/linux/man-pages/man2/mknod.2.html
    //DetachedSocket(),
}

/// The backend used for path resolution within a [`Root`] to get a [`Handle`].
///
/// We don't generally recommend specifying this, since libpathrs will
/// automatically detect the best backend for your platform (which is the value
/// returned by [`Resolver::default`]). However, this can be useful for testing.
///
/// [`Root`]: struct.Root.html
/// [`Handle`]: struct.Handle.html
/// [`Resolver::default`]: enum.Resolver.html
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Resolver {
    /// Use the native `openat2(2)` backend (requires kernel support).
    Kernel,
    /// Use the userspace "emulated" backend.
    Emulated,
    // TODO: Implement a HardcoreEmulated which does pivot_root(2) and all the
    //       rest of it. It'd be useful to compare against and for some
    //       hyper-concerned users.
}

lazy_static! {
    static ref DEFAULT_RESOLVER: Resolver = match *kernel::IS_SUPPORTED {
        true => Resolver::Kernel,
        false => Resolver::Emulated,
    };
}

impl Default for Resolver {
    fn default() -> Self {
        *DEFAULT_RESOLVER
    }
}

impl Resolver {
    /// Is this resolver supported by the current platform?
    pub fn supported(&self) -> bool {
        match self {
            Resolver::Kernel => *kernel::IS_SUPPORTED,
            Resolver::Emulated => true,
        }
    }
}

/// Helper to split a Path into its parent directory and trailing path. The
/// trailing component is guaranteed to not contain a directory separator.
fn path_split<'p>(path: &'p Path) -> Result<(&'p Path, &'p Path), FailureError> {
    // Get the parent path.
    let parent = path.parent().unwrap_or("/".as_ref());

    // Now construct the trailing portion of the target.
    let name = path
        .file_name()
        .ok_or(Error::InvalidArgument("path", "no trailing component"))?;

    // It's critical we are only touching the final component in the path.
    // If there are any other path components we must bail.
    if name.as_bytes().contains(&PATH_SEPARATOR) {
        return Err(Error::SafetyViolation(
            "trailing component of pathname contains '/'",
        ))?;
    }
    Ok((parent, name.as_ref()))
}

/// Wrapper for the underlying `libc`'s `RENAME_*` flags. The flag values and
/// their meaning is identical to the description in the [`renameat2(2)`] man
/// page.
///
/// [`renameat2(2)`] might not not be supported on your kernel -- in which
/// case [`Root::rename`] will fail if you specify any RenameFlags. You can
/// verify whether [`renameat2(2)`] flags are supported by calling
/// [`RenameFlags::supported`].
///
/// [`renameat2(2)`]: http://man7.org/linux/man-pages/man2/rename.2.html
/// [`Root::rename`]: struct.Root.html#method.rename
/// [`RenameFlags::supported`]: struct.RenameFlags.html#method.supported
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenameFlags(pub c_int);

impl RenameFlags {
    /// Is this set of RenameFlags supported by the running kernel?
    pub fn supported(&self) -> bool {
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
pub struct Root {
    inner: File,
    resolver: Resolver,
    path: PathBuf,
}

// Only used internally by libpathrs.
#[doc(hidden)]
impl AsRef<Path> for Root {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}

// Only used internally by libpathrs.
#[doc(hidden)]
impl Deref for Root {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Root {
    /// Open a [`Root`] handle.
    ///
    /// The [`Resolver`] used by this handle is chosen at runtime based on which
    /// resolvers are supported by the running kernel (the default [`Resolver`]
    /// is always `Resolver::default()`). You can change the [`Resolver`] used
    /// with [`Root::with_resolver`], though this is not recommended.
    ///
    /// # Errors
    ///
    /// `path` must be an existing directory, and must (at the moment) be a
    /// fully-resolved pathname with no symlink components. This restriction
    /// might be relaxed in the future.
    ///
    /// [`Root`]: struct.Root.html
    /// [`Root::with_resolver`]: struct.Root.html#method.with_resolver
    /// [`Resolver`]: enum.Resolver.html
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

        let file = syscalls::openat(libc::AT_FDCWD, path, libc::O_PATH | libc::O_DIRECTORY, 0)?;

        let root = Root {
            inner: file,
            resolver: Default::default(),
            path: path.into(),
        };

        root.check().context("double-check new root is valid")?;
        Ok(root)
    }

    /// Change the [`Resolver`] used by this [`Root`] instance.
    ///
    /// Using this option is not recommended, but it can be useful for testing
    /// or specifically ensuring that a particular backend is used to work
    /// around issues in another backend.
    ///
    /// [`Root`]: struct.Root.html
    /// [`Root::with_resolver`]: struct.Root.html#method.with_resolver
    /// [`Resolver`]: enum.Resolver.html
    pub fn with_resolver(&mut self, resolver: Resolver) -> &mut Self {
        self.resolver = resolver;
        self
    }

    /// Check whether the Root is still valid.
    #[doc(hidden)]
    pub fn check(&self) -> Result<(), FailureError> {
        // as_unsafe_path is safe here because we are just comparing the string,
        // and it is being done as part of a larger security check.
        if self.inner.as_unsafe_path()? == self.path {
            Ok(())
        } else {
            Err(Error::SafetyViolation(
                "root directory doesn't match original path",
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
    pub fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Handle, FailureError> {
        self.check()?;
        match self.resolver {
            Resolver::Kernel => kernel::resolve(self, path),
            Resolver::Emulated => user::resolve(self, path),
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
        let (parent, name) = path_split(path.as_ref()).context("split path into (parent, name)")?;
        let dirfd = self
            .resolve(parent)
            .context("resolve parent directory for inode creation")?
            .as_raw_fd();

        match inode_type {
            InodeType::File(_) => unreachable!(), /* We dealt with this above. */
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
                    path_split(target).context("split hardlink target into (parent, name)")?;
                let olddirfd = self
                    .resolve(oldparent)
                    .context("resolve target parent for hardlink")?
                    .as_raw_fd();
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

        let file = syscalls::openat(dirfd, name, libc::O_CREAT | libc::O_EXCL, perm.mode())?;
        Ok(Handle::try_from(file).context("convert O_CREAT fd to Handle")?)
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

        // TODO: Handle the lovely "is it a directory or file" problem.
        syscalls::unlinkat(dirfd, name, 0)
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
    ) -> Result<(), FailureError> {
        let (src_parent, src_name) = path_split(source.as_ref())?;
        let (dst_parent, dst_name) = path_split(destination.as_ref())?;

        let src_dirfd = self.resolve(src_parent)?.as_raw_fd();
        let dst_dirfd = self.resolve(dst_parent)?.as_raw_fd();

        syscalls::renameat2(src_dirfd, src_name, dst_dirfd, dst_name, flags.0)
    }

    // TODO: mkdir_all()
    // TODO: remove_all()
}

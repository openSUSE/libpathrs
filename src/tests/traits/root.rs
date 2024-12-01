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
    error::Error,
    flags::{OpenFlags, RenameFlags},
    resolvers::Resolver,
    tests::traits::{ErrorImpl, HandleImpl},
    Handle, InodeType, Root, RootRef,
};

use std::{
    fs::{File, Permissions},
    os::unix::io::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

pub(in crate::tests) trait RootImpl: AsFd + std::fmt::Debug + Sized {
    type Cloned: RootImpl<Error = Self::Error> + Into<OwnedFd>;
    type Handle: HandleImpl<Error = Self::Error> + Into<OwnedFd>;
    type Error: ErrorImpl;

    // NOTE:: Not part of the actual API, only used for tests!
    fn resolver(&self) -> Resolver;

    // NOTE: We return Self::Cloned so that we can share types with RootRef.
    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned;

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error>;

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error>;

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error>;

    fn open_subpath<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        path: P,
        flags: F,
    ) -> Result<File, Self::Error>;

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Self::Error>;

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Self::Error>;

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, Self::Error>;

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Self::Handle, Self::Error>;

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Self::Error>;
}

impl RootImpl for Root {
    type Cloned = Root;
    type Handle = Handle;
    type Error = Error;

    fn resolver(&self) -> Resolver {
        Resolver {
            backend: self.resolver_backend(),
            flags: self.resolver_flags(),
        }
    }

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
            .with_resolver_backend(resolver.backend)
            .with_resolver_flags(resolver.flags)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        self.try_clone().map_err(From::from)
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        self.resolve(path)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        self.resolve_nofollow(path)
    }

    fn open_subpath<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        path: P,
        flags: F,
    ) -> Result<File, Self::Error> {
        self.open_subpath(path, flags)
    }

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Self::Error> {
        self.readlink(path)
    }

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Self::Error> {
        self.create(path, inode_type)
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, Self::Error> {
        self.create_file(path, flags, perm)
    }

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Self::Handle, Self::Error> {
        self.mkdir_all(path, perm)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.remove_dir(path)
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.remove_file(path)
    }

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.remove_all(path)
    }

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Self::Error> {
        self.rename(source, destination, rflags)
    }
}

impl RootImpl for &Root {
    type Cloned = Root;
    type Handle = Handle;
    type Error = Error;

    fn resolver(&self) -> Resolver {
        Resolver {
            backend: self.resolver_backend(),
            flags: self.resolver_flags(),
        }
    }

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
            .with_resolver_backend(resolver.backend)
            .with_resolver_flags(resolver.flags)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        Root::try_clone(self).map_err(From::from)
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        Root::resolve(self, path)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        Root::resolve_nofollow(self, path)
    }

    fn open_subpath<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        path: P,
        flags: F,
    ) -> Result<File, Self::Error> {
        Root::open_subpath(self, path, flags)
    }

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Self::Error> {
        Root::readlink(self, path)
    }

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Self::Error> {
        Root::create(self, path, inode_type)
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, Self::Error> {
        Root::create_file(self, path, flags, perm)
    }

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Self::Handle, Self::Error> {
        Root::mkdir_all(self, path, perm)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        Root::remove_dir(self, path)
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        Root::remove_file(self, path)
    }

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        Root::remove_all(self, path)
    }

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Self::Error> {
        Root::rename(self, source, destination, rflags)
    }
}

impl RootImpl for RootRef<'_> {
    type Cloned = Root;
    type Handle = Handle;
    type Error = Error;

    fn resolver(&self) -> Resolver {
        Resolver {
            backend: self.resolver_backend(),
            flags: self.resolver_flags(),
        }
    }

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
            .with_resolver_backend(resolver.backend)
            .with_resolver_flags(resolver.flags)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        self.try_clone().map_err(From::from)
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        self.resolve(path)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        self.resolve_nofollow(path)
    }

    fn open_subpath<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        path: P,
        flags: F,
    ) -> Result<File, Self::Error> {
        self.open_subpath(path, flags)
    }

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Self::Error> {
        self.readlink(path)
    }

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Self::Error> {
        self.create(path, inode_type)
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, Self::Error> {
        self.create_file(path, flags, perm)
    }

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Self::Handle, Self::Error> {
        self.mkdir_all(path, perm)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.remove_dir(path)
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.remove_file(path)
    }

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.remove_all(path)
    }

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Self::Error> {
        self.rename(source, destination, rflags)
    }
}

impl RootImpl for &RootRef<'_> {
    type Cloned = Root;
    type Handle = Handle;
    type Error = Error;

    fn resolver(&self) -> Resolver {
        Resolver {
            backend: self.resolver_backend(),
            flags: self.resolver_flags(),
        }
    }

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
            .with_resolver_backend(resolver.backend)
            .with_resolver_flags(resolver.flags)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        RootRef::try_clone(self).map_err(From::from)
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        RootRef::resolve(self, path)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        RootRef::resolve_nofollow(self, path)
    }

    fn open_subpath<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        path: P,
        flags: F,
    ) -> Result<File, Self::Error> {
        RootRef::open_subpath(self, path, flags)
    }

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Self::Error> {
        RootRef::readlink(self, path)
    }

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Self::Error> {
        RootRef::create(self, path, inode_type)
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, Self::Error> {
        RootRef::create_file(self, path, flags, perm)
    }

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Self::Handle, Self::Error> {
        RootRef::mkdir_all(self, path, perm)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        RootRef::remove_dir(self, path)
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        RootRef::remove_file(self, path)
    }

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        RootRef::remove_all(self, path)
    }

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Self::Error> {
        RootRef::rename(self, source, destination, rflags)
    }
}

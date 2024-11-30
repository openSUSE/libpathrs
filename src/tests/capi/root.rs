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
    capi,
    flags::{OpenFlags, RenameFlags},
    resolvers::Resolver,
    tests::{
        capi::{
            utils::{self as capi_utils, CapiError},
            CapiHandle,
        },
        traits::{HandleImpl, RootImpl},
    },
    InodeType,
};

use std::{
    fs::{File, Permissions},
    os::unix::{
        fs::PermissionsExt,
        io::{AsFd, BorrowedFd, OwnedFd},
    },
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub(in crate::tests) struct CapiRoot {
    inner: OwnedFd,
}

impl CapiRoot {
    pub(in crate::tests) fn open<P: AsRef<Path>>(path: P) -> Result<Self, CapiError> {
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_fd(|| unsafe { capi::core::pathrs_open_root(path.as_ptr()) })
            .map(Self::from_fd)
    }

    pub(in crate::tests) fn from_fd<Fd: Into<OwnedFd>>(fd: Fd) -> Self {
        Self { inner: fd.into() }
    }

    fn try_clone(&self) -> Result<Self, anyhow::Error> {
        Ok(Self::from_fd(self.inner.try_clone()?))
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<CapiHandle, CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_fd(|| unsafe {
            capi::core::pathrs_inroot_resolve(root_fd.into(), path.as_ptr())
        })
        .map(CapiHandle::from_fd)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<CapiHandle, CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_fd(|| unsafe {
            capi::core::pathrs_inroot_resolve_nofollow(root_fd.into(), path.as_ptr())
        })
        .map(CapiHandle::from_fd)
    }

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_readlink(|linkbuf, linkbuf_size| unsafe {
            capi::core::pathrs_inroot_readlink(root_fd.into(), path.as_ptr(), linkbuf, linkbuf_size)
        })
    }

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_zst(|| unsafe {
            match inode_type {
                InodeType::File(perm) => capi::core::pathrs_inroot_mknod(
                    root_fd.into(),
                    path.as_ptr(),
                    libc::S_IFREG | perm.mode(),
                    0,
                ),
                InodeType::Directory(perm) => {
                    capi::core::pathrs_inroot_mkdir(root_fd.into(), path.as_ptr(), perm.mode())
                }
                InodeType::Symlink(target) => {
                    let target = capi_utils::path_to_cstring(target);
                    capi::core::pathrs_inroot_symlink(
                        root_fd.into(),
                        path.as_ptr(),
                        target.as_ptr(),
                    )
                }
                InodeType::Hardlink(target) => {
                    let target = capi_utils::path_to_cstring(target);
                    capi::core::pathrs_inroot_hardlink(
                        root_fd.into(),
                        path.as_ptr(),
                        target.as_ptr(),
                    )
                }
                InodeType::Fifo(perm) => capi::core::pathrs_inroot_mknod(
                    root_fd.into(),
                    path.as_ptr(),
                    libc::S_IFIFO | perm.mode(),
                    0,
                ),
                InodeType::CharacterDevice(perm, dev) => capi::core::pathrs_inroot_mknod(
                    root_fd.into(),
                    path.as_ptr(),
                    libc::S_IFCHR | perm.mode(),
                    *dev,
                ),
                InodeType::BlockDevice(perm, dev) => capi::core::pathrs_inroot_mknod(
                    root_fd.into(),
                    path.as_ptr(),
                    libc::S_IFBLK | perm.mode(),
                    *dev,
                ),
            }
        })
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_fd(|| unsafe {
            capi::core::pathrs_inroot_creat(
                root_fd.into(),
                path.as_ptr(),
                flags.bits(),
                perm.mode(),
            )
        })
        .map(File::from)
    }

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<CapiHandle, CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_fd(|| unsafe {
            capi::core::pathrs_inroot_mkdir_all(root_fd.into(), path.as_ptr(), perm.mode())
        })
        .map(CapiHandle::from_fd)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_zst(|| unsafe {
            capi::core::pathrs_inroot_rmdir(root_fd.into(), path.as_ptr())
        })
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_zst(|| unsafe {
            capi::core::pathrs_inroot_unlink(root_fd.into(), path.as_ptr())
        })
    }

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), CapiError> {
        let root_fd = self.inner.as_fd();
        let path = capi_utils::path_to_cstring(path);

        capi_utils::call_capi_zst(|| unsafe {
            capi::core::pathrs_inroot_remove_all(root_fd.into(), path.as_ptr())
        })
    }

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), CapiError> {
        let root_fd = self.inner.as_fd();
        let source = capi_utils::path_to_cstring(source);
        let destination = capi_utils::path_to_cstring(destination);

        capi_utils::call_capi_zst(|| unsafe {
            capi::core::pathrs_inroot_rename(
                root_fd.into(),
                source.as_ptr(),
                destination.as_ptr(),
                rflags.bits(),
            )
        })
    }
}

impl AsFd for CapiRoot {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl From<CapiRoot> for OwnedFd {
    fn from(root: CapiRoot) -> Self {
        root.inner
    }
}

impl RootImpl for CapiRoot {
    type Cloned = CapiRoot;
    type Handle = CapiHandle;
    // NOTE: We can't use anyhow::Error here.
    // <https://github.com/dtolnay/anyhow/issues/25>
    type Error = CapiError;

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned {
        assert_eq!(
            resolver,
            Resolver::default(),
            "cannot use non-default Resolver with capi"
        );
        Self::Cloned::from_fd(fd)
    }

    fn resolver(&self) -> Resolver {
        Resolver::default()
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        self.try_clone()
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        self.resolve(path)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        self.resolve_nofollow(path)
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

impl RootImpl for &CapiRoot {
    type Cloned = CapiRoot;
    type Handle = CapiHandle;
    // NOTE: We can't use anyhow::Error here.
    // <https://github.com/dtolnay/anyhow/issues/25>
    type Error = CapiError;

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd, resolver: Resolver) -> Self::Cloned {
        assert_eq!(
            resolver,
            Resolver::default(),
            "cannot use non-default Resolver with capi"
        );
        Self::Cloned::from_fd(fd)
    }

    fn resolver(&self) -> Resolver {
        Resolver::default()
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        CapiRoot::try_clone(self)
    }

    fn resolve<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        CapiRoot::resolve(self, path)
    }

    fn resolve_nofollow<P: AsRef<Path>>(&self, path: P) -> Result<Self::Handle, Self::Error> {
        CapiRoot::resolve_nofollow(self, path)
    }

    fn readlink<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf, Self::Error> {
        CapiRoot::readlink(self, path)
    }

    fn create<P: AsRef<Path>>(&self, path: P, inode_type: &InodeType) -> Result<(), Self::Error> {
        CapiRoot::create(self, path, inode_type)
    }

    fn create_file<P: AsRef<Path>>(
        &self,
        path: P,
        flags: OpenFlags,
        perm: &Permissions,
    ) -> Result<File, Self::Error> {
        CapiRoot::create_file(self, path, flags, perm)
    }

    fn mkdir_all<P: AsRef<Path>>(
        &self,
        path: P,
        perm: &Permissions,
    ) -> Result<Self::Handle, Self::Error> {
        CapiRoot::mkdir_all(self, path, perm)
    }

    fn remove_dir<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        CapiRoot::remove_dir(self, path)
    }

    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        CapiRoot::remove_file(self, path)
    }

    fn remove_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        CapiRoot::remove_all(self, path)
    }

    fn rename<P: AsRef<Path>>(
        &self,
        source: P,
        destination: P,
        rflags: RenameFlags,
    ) -> Result<(), Self::Error> {
        CapiRoot::rename(self, source, destination, rflags)
    }
}

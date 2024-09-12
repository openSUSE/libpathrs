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
    capi::{self, procfs::CProcfsBase},
    flags::OpenFlags,
    procfs::ProcfsBase,
    tests::{
        capi::utils::{self as capi_utils, CapiError},
        traits::ProcfsHandleImpl,
    },
};

use std::{
    fs::File,
    path::{Path, PathBuf},
};

// NOTE: The C API only lets us access the global GLOBAL_PROCFS_HANDLE
// reference.
#[derive(Debug)]
pub struct CapiProcfsHandle;

impl CapiProcfsHandle {
    fn open_follow<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        oflags: F,
    ) -> Result<File, CapiError> {
        let base: CProcfsBase = base.into();
        let subpath = capi_utils::path_to_cstring(subpath);
        let oflags = oflags.into();

        capi_utils::call_capi_fd(|| unsafe {
            capi::procfs::pathrs_proc_open(base, subpath.as_ptr(), oflags.bits())
        })
        .map(File::from)
    }

    fn open<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        oflags: F,
    ) -> Result<File, CapiError> {
        // The C API exposes ProcfsHandle::open using O_NOFOLLOW.
        self.open_follow(base, subpath, oflags.into() | OpenFlags::O_NOFOLLOW)
    }

    fn readlink<P: AsRef<Path>>(&self, base: ProcfsBase, subpath: P) -> Result<PathBuf, CapiError> {
        let base: CProcfsBase = base.into();
        let subpath = capi_utils::path_to_cstring(subpath);

        capi_utils::call_capi_readlink(|linkbuf, linkbuf_size| unsafe {
            capi::procfs::pathrs_proc_readlink(base, subpath.as_ptr(), linkbuf, linkbuf_size)
        })
    }
}

impl ProcfsHandleImpl for CapiProcfsHandle {
    type Error = CapiError;

    fn open_follow<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        flags: F,
    ) -> Result<File, Self::Error> {
        self.open_follow(base, subpath, flags)
    }

    fn open<P: AsRef<Path>, F: Into<OpenFlags>>(
        &self,
        base: ProcfsBase,
        subpath: P,
        flags: F,
    ) -> Result<File, Self::Error> {
        self.open(base, subpath, flags)
    }

    fn readlink<P: AsRef<Path>>(
        &self,
        base: ProcfsBase,
        subpath: P,
    ) -> Result<PathBuf, Self::Error> {
        self.readlink(base, subpath)
    }
}

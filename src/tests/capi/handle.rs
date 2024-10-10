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
    flags::OpenFlags,
    tests::{
        capi::utils::{self as capi_utils, CapiError},
        traits::HandleImpl,
    },
};

use std::{
    fs::File,
    os::unix::io::{AsFd, BorrowedFd, OwnedFd},
};

#[derive(Debug)]
pub struct CapiHandle {
    inner: OwnedFd,
}

impl CapiHandle {
    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd) -> Self {
        Self { inner: fd.into() }
    }

    fn try_clone(&self) -> Result<Self, anyhow::Error> {
        Ok(Self::from_fd(self.inner.try_clone()?))
    }

    fn reopen<F: Into<OpenFlags>>(&self, flags: F) -> Result<File, CapiError> {
        let fd = self.inner.as_fd();
        let flags = flags.into();

        capi_utils::call_capi_fd(|| capi::core::pathrs_reopen(fd.into(), flags.bits()))
            .map(File::from)
    }
}

impl AsFd for CapiHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl From<CapiHandle> for OwnedFd {
    fn from(handle: CapiHandle) -> Self {
        handle.inner
    }
}

impl HandleImpl for CapiHandle {
    type Cloned = CapiHandle;
    type Error = CapiError;

    // C implementation *DOES NOT* set O_CLOEXEC by default.
    const FORCED_CLOEXEC: bool = false;

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        self.try_clone().map_err(From::from)
    }

    fn reopen<F: Into<OpenFlags>>(&self, flags: F) -> Result<File, Self::Error> {
        self.reopen(flags)
    }
}

impl HandleImpl for &CapiHandle {
    type Cloned = CapiHandle;
    type Error = CapiError;

    // C implementation *DOES NOT* set O_CLOEXEC by default.
    const FORCED_CLOEXEC: bool = false;

    fn from_fd<Fd: Into<OwnedFd>>(fd: Fd) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        CapiHandle::try_clone(self).map_err(From::from)
    }

    fn reopen<F: Into<OpenFlags>>(&self, flags: F) -> Result<File, Self::Error> {
        CapiHandle::reopen(self, flags)
    }
}

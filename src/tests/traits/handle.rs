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

use crate::{error::Error, flags::OpenFlags, tests::traits::ErrorImpl, Handle, HandleRef};

use std::{
    fs::File,
    os::unix::io::{AsFd, OwnedFd},
};

pub(in crate::tests) trait HandleImpl: AsFd + std::fmt::Debug + Sized {
    type Cloned: HandleImpl<Error = Self::Error> + Into<OwnedFd>;
    type Error: ErrorImpl;

    // NOTE: We return Self::Cloned so that we can share types with HandleRef.
    fn from_fd(fd: impl Into<OwnedFd>) -> Self::Cloned;

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error>;

    fn reopen(&self, flags: impl Into<OpenFlags>) -> Result<File, Self::Error>;
}

impl HandleImpl for Handle {
    type Cloned = Handle;
    type Error = Error;

    fn from_fd(fd: impl Into<OwnedFd>) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        self.as_ref().try_clone().map_err(From::from)
    }

    fn reopen(&self, flags: impl Into<OpenFlags>) -> Result<File, Self::Error> {
        self.as_ref().reopen(flags)
    }
}

impl HandleImpl for &Handle {
    type Cloned = Handle;
    type Error = Error;

    fn from_fd(fd: impl Into<OwnedFd>) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        Handle::try_clone(self).map_err(From::from)
    }

    fn reopen(&self, flags: impl Into<OpenFlags>) -> Result<File, Self::Error> {
        Handle::reopen(self, flags)
    }
}

impl HandleImpl for HandleRef<'_> {
    type Cloned = Handle;
    type Error = Error;

    fn from_fd(fd: impl Into<OwnedFd>) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        self.try_clone().map_err(From::from)
    }

    fn reopen(&self, flags: impl Into<OpenFlags>) -> Result<File, Self::Error> {
        self.reopen(flags)
    }
}

impl HandleImpl for &HandleRef<'_> {
    type Cloned = Handle;
    type Error = Error;

    fn from_fd(fd: impl Into<OwnedFd>) -> Self::Cloned {
        Self::Cloned::from_fd(fd)
    }

    fn try_clone(&self) -> Result<Self::Cloned, anyhow::Error> {
        HandleRef::try_clone(self).map_err(From::from)
    }

    fn reopen(&self, flags: impl Into<OpenFlags>) -> Result<File, Self::Error> {
        HandleRef::reopen(self, flags)
    }
}

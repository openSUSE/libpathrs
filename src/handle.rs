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

use crate::Error;

use core::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};

use failure::{Error as FailureError, ResultExt};

/// A handle to an existing inode within a [`Root`].
///
/// This handle references an already-resolved path which can be used for the
/// purpose of "re-opening" the handle and get an actual [`File`] which can be
/// used for ordinary operations.
///
/// # Safety
///
/// It is critical for the safety of this library that **at no point** do you
/// use interfaces like [`libc::openat`] directly on any [`RawFd`]s you might
/// extract from the [`File`] you get from this [`Handle`]. **You must always do
/// operations through a valid [`Root`].**
///
/// [`Root`]: struct.Root.html
/// [`Handle`]: trait.Handle.html
/// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
/// [`RawFd`]: https://doc.rust-lang.org/std/os/unix/io/type.RawFd.html
/// [`libc::openat`]: https://docs.rs/libc/latest/libc/fn.openat.html
pub struct Handle(RawFd);

// RawFds aren't auto-dropped in Rust so we need to do it manually. As long as
// nobody has done anything strange with the current process's fds, this will
// not fail.
impl Drop for Handle {
    fn drop(&mut self) {
        // Cannot return errors in Drop or panic! in C FFI. So just ignore it.
        unsafe { libc::close(self.0) };
    }
}

impl TryFrom<RawFd> for Handle {
    type Error = FailureError;
    fn try_from(fd: RawFd) -> Result<Self, Self::Error> {
        if fd.is_negative() {
            return Err(Error::InvalidArgument("fd", "must be positive"))
                .context("convert fd into Handle")?;
        }
        // TODO: Check if the fd is valid.
        Ok(Handle(fd))
    }
}

// Not super-safe to use since the Handle might be dropped after getting the
// RawFd (meaning you end up with EBADF. But it's much more ergonomic than
// Into<RawFd>.
#[doc(hidden)]
impl AsRawFd for Handle {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Handle {
    /// "Upgrade" the handle to a usable [`File`] handle suitable for reading
    /// and writing, as though the file was opened with `OpenOptions`.
    ///
    /// This does not consume the original handle (allowing for it to be used
    /// many times). It is recommended to `use` [`OpenOptionsExt`].
    ///
    /// [`File`]: https://doc.rust-lang.org/std/fs/struct.File.html
    /// [`OpenOptions`]: https://doc.rust-lang.org/std/fs/struct.OpenOptions.html
    /// [`Root::create`]: struct.Root.html#method.create
    /// [`OpenOptionsExt`]: https://doc.rust-lang.org/std/os/unix/fs/trait.OpenOptionsExt.html
    pub fn reopen(&self, options: &OpenOptions) -> Result<File, FailureError> {
        // TODO: Implement re-opening with O_EMPTYPATH if it's supported.
        let fd_path = format!("/proc/self/fd/{}", self.as_raw_fd());
        let file = options
            .open(fd_path)
            .context("reopen handle through /proc/self/fd")?;
        Ok(file)
    }

    // TODO: bind(). This might be safe to do (set the socket path to
    //       /proc/self/fd/...) but I'm a bit sad it'd be separate from
    //       Handle::reopen().
}

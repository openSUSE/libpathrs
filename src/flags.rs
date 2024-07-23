/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
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

bitflags! {
    /// Wrapper for the underlying `libc`'s `O_*` flags.
    ///
    /// The flag values and their meaning is identical to the description in the
    /// `open(2)` man page.
    ///
    /// # Caveats
    ///
    /// For historical reasons, the first three bits of `open(2)`'s flags are for
    /// the access mode and are actually treated as a 2-bit number. So, it is
    /// incorrect to attempt to do any checks on the access mode without masking it
    /// correctly. So some helpers were added to make usage more ergonomic.
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct OpenFlags: libc::c_int {
        const O_EXCL = libc::O_EXCL;
        const O_PATH = libc::O_PATH;
        const O_RDWR = libc::O_RDWR;
        const O_SYNC = libc::O_SYNC;
        const O_ASYNC = libc::O_ASYNC;
        const O_CREAT = libc::O_CREAT;
        const O_DSYNC = libc::O_DSYNC;
        const O_FSYNC = libc::O_FSYNC;
        const O_RSYNC = libc::O_RSYNC;
        const O_TRUNC = libc::O_TRUNC;
        const O_APPEND = libc::O_APPEND;
        const O_DIRECT = libc::O_DIRECT;
        const O_NDELAY = libc::O_NDELAY;
        const O_NOCTTY = libc::O_NOCTTY;
        const O_RDONLY = libc::O_RDONLY;
        const O_WRONLY = libc::O_WRONLY;
        const O_ACCMODE = libc::O_ACCMODE;
        const O_CLOEXEC = libc::O_CLOEXEC;
        const O_NOATIME = libc::O_NOATIME;
        const O_TMPFILE = libc::O_TMPFILE;
        const O_NOFOLLOW = libc::O_NOFOLLOW;
        const O_NONBLOCK = libc::O_NONBLOCK;
        const O_DIRECTORY = libc::O_DIRECTORY;
        //const O_LARGEFILE = libc::O_LARGEFILE;
        const _ = !0;
    }
}

impl OpenFlags {
    /// Grab the access mode bits from the flags.
    #[inline]
    pub fn access_mode(self) -> libc::c_int {
        self.bits() & libc::O_ACCMODE
    }

    /// Does the access mode imply read access?
    #[inline]
    pub fn wants_read(self) -> bool {
        let acc = self.access_mode();
        acc == libc::O_RDONLY || acc == libc::O_RDWR
    }

    /// Does the access mode imply write access? Note that there are several
    /// other bits (such as `O_TRUNC`) which imply write access but are not part
    /// of the access mode, and thus a `false` value from `.wants_write()` does
    /// not guarantee that the kernel will not do a `MAY_WRITE` check.
    #[inline]
    pub fn wants_write(self) -> bool {
        let acc = self.access_mode();
        acc == libc::O_WRONLY || acc == libc::O_RDWR
    }
}

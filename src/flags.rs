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
    ///
    /// Also, if you wish to check for `O_TMPFILE`, make sure to use `contains`.
    /// `O_TMPFILE` includes `O_DIRECTORY`, so doing `intersection` will match
    /// `O_DIRECTORY` as well.
    #[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
    pub struct OpenFlags: libc::c_int {
        // Access modes (including O_PATH).
        const O_RDWR = libc::O_RDWR;
        const O_RDONLY = libc::O_RDONLY;
        const O_WRONLY = libc::O_WRONLY;
        const O_PATH = libc::O_PATH;

        // Fd flags.
        const O_CLOEXEC = libc::O_CLOEXEC;

        // Control lookups.
        const O_NOFOLLOW = libc::O_NOFOLLOW;
        const O_DIRECTORY = libc::O_DIRECTORY;
        const O_NOCTTY = libc::O_NOCTTY;

        // NOTE: This flag contains O_DIRECTORY!
        const O_TMPFILE = libc::O_TMPFILE;

        // File creation.
        const O_CREAT = libc::O_CREAT;
        const O_EXCL = libc::O_EXCL;
        const O_TRUNC = libc::O_TRUNC;
        const O_APPEND = libc::O_APPEND;

        // Sync.
        const O_SYNC = libc::O_SYNC;
        const O_ASYNC = libc::O_ASYNC;
        const O_DSYNC = libc::O_DSYNC;
        const O_FSYNC = libc::O_FSYNC;
        const O_RSYNC = libc::O_RSYNC;
        const O_DIRECT = libc::O_DIRECT;
        const O_NDELAY = libc::O_NDELAY;
        const O_NOATIME = libc::O_NOATIME;
        const O_NONBLOCK = libc::O_NONBLOCK;

        // NOTE: This is effectively a kernel-internal flag (auto-set on systems
        //       with large offset support). glibc defines it as 0, and it is
        //       also architecture-specific.
        //const O_LARGEFILE = libc::O_LARGEFILE;
        const _ = !0;
    }
}

impl OpenFlags {
    /// Grab the access mode bits from the flags.
    ///
    /// If the flags contain `O_PATH`, this returns `None`.
    #[inline]
    pub fn access_mode(self) -> Option<libc::c_int> {
        if self.contains(OpenFlags::O_PATH) {
            None
        } else {
            Some(self.bits() & libc::O_ACCMODE)
        }
    }

    /// Does the access mode imply read access?
    ///
    /// Returns false for `O_PATH`.
    #[inline]
    pub fn wants_read(self) -> bool {
        match self.access_mode() {
            None => false, // O_PATH
            Some(acc) => acc == libc::O_RDONLY || acc == libc::O_RDWR,
        }
    }

    /// Does the access mode imply write access? Note that there are several
    /// other bits in OpenFlags that imply write acces other than `O_WRONLY` and
    /// `O_RDWR`. This function checks those bits as well.
    ///
    /// Returns false for `O_PATH`.
    #[inline]
    pub fn wants_write(self) -> bool {
        match self.access_mode() {
            None => false, // O_PATH
            Some(acc) => {
                acc == libc::O_WRONLY
                    || acc == libc::O_RDWR
                    || !self
                        // O_CREAT and O_TRUNC are silently ignored with O_PATH.
                        .intersection(OpenFlags::O_TRUNC | OpenFlags::O_CREAT)
                        .is_empty()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OpenFlags;

    macro_rules! openflags_tests {
        ($($test_name:ident ( $($flag:ident)|+ ) == {accmode: $accmode:expr, read: $wants_read:expr, write: $wants_write:expr} );+ $(;)?) => {
            $(
                paste::paste! {
                    #[test]
                    fn [<openflags_ $test_name _access_mode>]() {
                        let flags = $(OpenFlags::$flag)|*;
                        let accmode: Option<i32> = $accmode;
                        assert_eq!(flags.access_mode(), accmode, "{:?} access mode should be {:?}", flags, accmode.map(OpenFlags::from_bits_retain));
                    }

                    #[test]
                    fn [<openflags_ $test_name _wants_read>]() {
                        let flags = $(OpenFlags::$flag)|*;
                        assert_eq!(flags.wants_read(), $wants_read, "{:?} wants_read should be {:?}", flags, $wants_read);
                    }

                    #[test]
                    fn [<openflags_ $test_name _wants_write>]() {
                        let flags = $(OpenFlags::$flag)|*;
                        assert_eq!(flags.wants_write(), $wants_write, "{:?} wants_write should be {:?}", flags, $wants_write);
                    }
                }
            )*
        }
    }

    openflags_tests! {
        plain_rdonly(O_RDONLY) == {accmode: Some(libc::O_RDONLY), read: true, write: false};
        plain_wronly(O_WRONLY) == {accmode: Some(libc::O_WRONLY), read: false, write: true};
        plain_rdwr(O_RDWR) == {accmode: Some(libc::O_RDWR), read: true, write: true};
        plain_opath(O_PATH) == {accmode: None, read: false, write: false};
        rdwr_opath(O_RDWR|O_PATH) == {accmode: None, read: false, write: false};
        wronly_opath(O_WRONLY|O_PATH) == {accmode: None, read: false, write: false};

        trunc_rdonly(O_RDONLY|O_TRUNC) == {accmode: Some(libc::O_RDONLY), read: true, write: true};
        trunc_wronly(O_WRONLY|O_TRUNC) == {accmode: Some(libc::O_WRONLY), read: false, write: true};
        trunc_rdwr(O_RDWR|O_TRUNC) == {accmode: Some(libc::O_RDWR), read: true, write: true};
        trunc_path(O_PATH|O_TRUNC) == {accmode: None, read: false, write: false};

        creat_rdonly(O_RDONLY|O_CREAT) == {accmode: Some(libc::O_RDONLY), read: true, write: true};
        creat_wronly(O_WRONLY|O_CREAT) == {accmode: Some(libc::O_WRONLY), read: false, write: true};
        creat_rdwr(O_RDWR|O_CREAT) == {accmode: Some(libc::O_RDWR), read: true, write: true};
        creat_path(O_PATH|O_CREAT) == {accmode: None, read: false, write: false};
    }
}

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
    error::{self, Error},
    procfs::{ProcfsBase, ProcfsHandle},
    syscalls, OpenFlags,
};

use std::{
    collections::VecDeque,
    ffi::{CString, OsStr, OsString},
    fs::{self, File},
    os::unix::{
        ffi::OsStrExt,
        io::{AsRawFd, RawFd},
    },
    path::{Path, PathBuf},
};

use snafu::ResultExt;

// Private trait necessary to work around the "orphan trait" restriction.
pub(crate) trait ToCString {
    /// Convert to a CStr.
    fn to_c_string(&self) -> CString;
}

impl ToCString for OsStr {
    fn to_c_string(&self) -> CString {
        let filtered: Vec<_> = self
            .as_bytes()
            .iter()
            .copied()
            .take_while(|&c| c != b'\0')
            .collect();
        CString::new(filtered).expect("nul bytes should've been excluded")
    }
}

impl ToCString for Path {
    fn to_c_string(&self) -> CString {
        self.as_os_str().to_c_string()
    }
}

/// Helper to strip trailing / components from a path.
pub(crate) fn path_strip_trailing_slash(path: &Path) -> (&Path, bool) {
    let path_bytes = path.as_os_str().as_bytes();
    let idx = match path_bytes.iter().rposition(|c| *c != b'/') {
        Some(idx) => idx,
        None => {
            if path_bytes.len() > 1 {
                // Nothing but b'/' components -- return a single /.
                return (Path::new("/"), true);
            } else {
                // Either "/" or "".
                return (path, false);
            }
        }
    };
    if idx == path_bytes.len() - 1 {
        // No slashes to strip.
        (path, false)
    } else {
        // Strip trailing slashes.
        (Path::new(OsStr::from_bytes(&path_bytes[..=idx])), true)
    }
}

/// Helper to split a Path into its parent directory and trailing path. The
/// trailing component is guaranteed to not contain a directory separator.
pub(crate) fn path_split(path: &'_ Path) -> Result<(&'_ Path, Option<&'_ Path>), Error> {
    let path_bytes = path.as_os_str().as_bytes();
    // Find the last /.
    let idx = match memchr::memrchr(b'/', path_bytes) {
        Some(idx) => idx,
        None => {
            return Ok((
                Path::new("."),
                if !path_bytes.is_empty() {
                    Some(path)
                } else {
                    None
                },
            ));
        }
    };
    // Split the path. A trailing / gives a None base.
    let (dir_bytes, base_bytes) = match path_bytes.split_at(idx) {
        // TODO: There must be a way to simplify this.
        (b"", b"/") => (&b"/"[..], None),
        (dir, b"/") => (dir, None),
        (b"", base) => (&b"/"[..], Some(&base[1..])),
        (dir, base) => (dir, Some(&base[1..])),
    };

    // It's critical we are only touching the final component in the path.
    // If there are any other path components we must bail.
    if let Some(base_bytes) = base_bytes {
        ensure!(
            base_bytes != b"",
            error::SafetyViolationSnafu {
                description: "trailing component of split pathname is ''",
            }
        );
        ensure!(
            !base_bytes.contains(&b'/'),
            error::SafetyViolationSnafu {
                description: "trailing component of split pathname contains '/'",
            }
        );
    }

    Ok((
        Path::new(OsStr::from_bytes(dir_bytes)),
        base_bytes.map(OsStr::from_bytes).map(Path::new),
    ))
}

pub(crate) trait RawFdExt {
    /// Re-open a file descriptor.
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<File, Error>;

    /// Get the path this RawFd is referencing.
    ///
    /// This is done through `readlink(/proc/self/fd)` and is naturally racy
    /// (hence the name "unsafe"), so it's important to only use this with the
    /// understanding that it only provides the guarantee that "at some point
    /// during execution this was the path the fd pointed to" and
    /// no more.
    ///
    /// NOTE: This method uses a [`procfs::ProcfsHandle`] to
    ///
    /// [`procfs::ProcfsHandle`]: procfs/struct.ProcfsHandle.html
    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error>;

    /// Like [`as_unsafe_path`], except that the lookup is done using the basic
    /// host `/proc` mount. This is not safe against various races, and thus
    /// MUST ONLY be used in codepaths that
    ///
    /// Currently this should only be used by the `syscall::FrozenFd` logic
    /// which saves the path a file descriptor references.
    ///
    /// [`as_unsafe_path`]: #method.as_unsafe_path
    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error>;

    /// This is a fixed version of the Rust stdlib's `File::try_clone()` which
    /// works on `O_PATH` file descriptors, added to [work around an upstream
    /// bug][bug62314]. The [fix for this bug was merged][pr62425] and will be
    /// available in Rust 1.37.0.
    ///
    /// [bug62314]: https://github.com/rust-lang/rust/issues/62314
    /// [pr62425]: https://github.com/rust-lang/rust/pull/62425
    fn try_clone_hotfix(&self) -> Result<File, Error>;
}

fn proc_subpath(fd: RawFd) -> Result<String, Error> {
    if fd == libc::AT_FDCWD {
        Ok("cwd".to_string())
    } else if fd.is_positive() {
        Ok(format!("fd/{}", fd))
    } else {
        error::InvalidArgumentSnafu {
            name: "fd",
            description: "must be positive or AT_FDCWD",
        }
        .fail()
    }
}

impl RawFdExt for RawFd {
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<File, Error> {
        // TODO: We should look into using O_EMPTYPATH if it's available to
        //       avoid the /proc dependency -- though then again, as_unsafe_path
        //       necessarily requires /proc.
        procfs.open_follow(ProcfsBase::ProcThreadSelf, proc_subpath(*self)?, flags)
    }

    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error> {
        procfs.readlink(ProcfsBase::ProcThreadSelf, proc_subpath(*self)?)
    }

    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error> {
        // "/proc/thread-self/fd/$n"
        let fd_path = PathBuf::from("/proc")
            .join(ProcfsBase::ProcThreadSelf.into_path(None))
            .join(proc_subpath(*self)?);

        // Because this code is used within syscalls, we can't even check the
        // filesystem type of /proc (unless we were to copy the logic here).
        fs::read_link(&fd_path).context(error::OsSnafu {
            operation: format!("readlink fd magic-link {:?}", fd_path),
        })
    }

    fn try_clone_hotfix(&self) -> Result<File, Error> {
        syscalls::fcntl_dupfd_cloxec(*self).context(error::RawOsSnafu {
            operation: "clone fd",
        })
    }
}

// XXX: We can't use <T: AsRawFd> here, because Rust tells us that RawFd might
//      have an AsRawFd in the future (and thus produce a conflicting
//      implementations error) and so we have to manually define it for the
//      types we are going to be using.

impl RawFdExt for File {
    fn reopen(&self, procfs: &ProcfsHandle, flags: OpenFlags) -> Result<File, Error> {
        self.as_raw_fd().reopen(procfs, flags)
    }

    fn as_unsafe_path(&self, procfs: &ProcfsHandle) -> Result<PathBuf, Error> {
        // SAFETY: Caller guarantees that as_unsafe_path usage is safe.
        self.as_raw_fd().as_unsafe_path(procfs)
    }

    fn as_unsafe_path_unchecked(&self) -> Result<PathBuf, Error> {
        // SAFETY: Caller guarantees that as_unsafe_path usage is safe.
        self.as_raw_fd().as_unsafe_path_unchecked()
    }

    fn try_clone_hotfix(&self) -> Result<File, Error> {
        self.as_raw_fd().try_clone_hotfix()
    }
}

pub(crate) trait FileExt {
    /// Check if the File is on a "dangerous" filesystem that might contain
    /// magic-links.
    fn is_dangerous(&self) -> Result<bool, Error>;
}

lazy_static! {
    /// Set of filesystems' magic numbers that are considered "dangerous" (in
    /// that they can contain magic-links). This list should hopefully be
    /// exhaustive, but there's no real way of being sure since `nd_jump_link()`
    /// can be used by any non-mainline filesystem.
    // XXX: This list is only correct for Linux 5.4. We should go back into old
    //      kernel versions to see who else used nd_jump_link() in the past.
    static ref DANGEROUS_FILESYSTEMS: Vec<i64> = vec![
        libc::PROC_SUPER_MAGIC,             // procfs
        0x5a3c_69f0 /* libc::AAFS_MAGIC */, // apparmorfs
    ];
}

impl FileExt for File {
    fn is_dangerous(&self) -> Result<bool, Error> {
        // There isn't a marker on a filesystem level to indicate whether
        // nd_jump_link() is used internally. So, we just have to make an
        // educated guess based on which mainline filesystems expose
        // magic-links.
        let stat = syscalls::fstatfs(self.as_raw_fd()).context(error::RawOsSnafu {
            operation: "check fstype of fd",
        })?;
        Ok(DANGEROUS_FILESYSTEMS.contains(&stat.f_type))
    }
}

pub(crate) fn fetch_mnt_id<P: AsRef<Path>>(dirfd: &File, path: P) -> Result<Option<u64>, Error> {
    // NOTE: stx.stx_mnt_id is fairly new (added in Linux 5.8[1]) so this check
    // might not work on quite a few kernels and so we have to fallback to not
    // checking the mount ID (removing some protections).
    //
    // In theory, name_to_handle_at(2) also lets us get the mount of a
    // handle in a race-free way (and would be a useful fallback for pre-statx
    // kernels -- name_to_handle_at(2) was added in Linux 2.6.39[2]).
    //
    // Unfortunately, before AT_HANDLE_FID (added in Linux 6.7[3]) procfs did
    // not permit the export of file handles. name_to_handle_at(2) does return
    // the mount ID in most error cases, but for -EOPNOTSUPP it doesn't and so
    // we can't use it for pre-statx kernels.
    //
    // The only other alternative would be to scan /proc/self/mountinfo, but
    // since we are worried about procfs attacks there isn't much point (an
    // attacker could bind-mount /proc/self/environ over /proc/$pid/mountinfo
    // and simply change their environment to make the mountinfo look
    // reasonable.
    //
    // So we have to live with limited protection for pre-5.8 kernels.
    //
    // [1]: Linux commit fa2fcf4f1df1 ("statx: add mount ID")
    // [2]: Linux commit 990d6c2d7aee ("vfs: Add name to file handle conversion support")
    // [3]: Linux commit 64343119d7b8 ("exportfs: support encoding non-decodeable file handles by default")

    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
    let want_mask = libc::STATX_MNT_ID | STATX_MNT_ID_UNIQUE;

    match syscalls::statx(dirfd.as_raw_fd(), path, want_mask) {
        Ok(stx) => Ok(if stx.stx_mask & want_mask != 0 {
            Some(stx.stx_mnt_id)
        } else {
            None
        }),
        Err(err) => match err.root_cause().raw_os_error() {
            // We have to handle STATX_MNT_ID not being supported on pre-5.8
            // kernels, so treat an ENOSYS or EINVAL the same so that we can
            // work on pre-4.11 (pre-statx) kernels as well.
            Some(libc::ENOSYS) | Some(libc::EINVAL) => Ok(None),
            _ => Err(err).context(error::RawOsSnafu {
                operation: "check mnt_id of filesystem",
            })?,
        },
    }
}

/// RawComponents is like [`std::path::Components`] execpt that no normalisation
/// is done for any path components ([`std::path::Components`] normalises "/./"
/// components), and all of the components are simply [`std::ffi::OsStr`].
///
/// [`std::path::Components`]: https://doc.rust-lang.org/std/path/struct.Components.html
/// [`std::ffi::OsStr`]: https://doc.rust-lang.org/std/ffi/struct.OsStr.html
pub(crate) struct RawComponents<'a> {
    inner: Option<&'a OsStr>,
}

impl<'a> Iterator for RawComponents<'a> {
    type Item = &'a OsStr;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            None => None,
            Some(inner) => {
                let (next, remaining) = match memchr::memchr(b'/', inner.as_bytes()) {
                    None => (inner, None),
                    Some(idx) => {
                        let (head, mut tail) = inner.as_bytes().split_at(idx);
                        tail = &tail[1..]; // strip slash
                        (OsStrExt::from_bytes(head), Some(OsStrExt::from_bytes(tail)))
                    }
                };
                self.inner = remaining;
                assert!(
                    !next.as_bytes().contains(&b'/'),
                    "individual path component {:?} contains '/'",
                    next
                );
                Some(next)
            }
        }
    }
}

impl<'a> DoubleEndedIterator for RawComponents<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.inner {
            None => None,
            Some(inner) => {
                let (next, remaining) = match memchr::memrchr(b'/', inner.as_bytes()) {
                    None => (inner, None),
                    Some(idx) => {
                        let (head, mut tail) = inner.as_bytes().split_at(idx);
                        tail = &tail[1..]; // strip slash
                        (OsStrExt::from_bytes(tail), Some(OsStrExt::from_bytes(head)))
                    }
                };
                self.inner = remaining;
                assert!(
                    !next.as_bytes().contains(&b'/'),
                    "individual path component {:?} contains '/'",
                    next
                );
                Some(next)
            }
        }
    }
}

impl RawComponents<'_> {
    pub(crate) fn prepend(&mut self, deque: &mut VecDeque<OsString>) {
        self.map(|p| p.to_os_string())
            // VecDeque doesn't have an amortized way of prepending a
            // Vec, so we need to do this manually. We need to rev() the
            // iterator since we're pushing to the front each time.
            .rev()
            .for_each(|p| deque.push_front(p));
    }
}

pub(crate) trait RawComponentsIter {
    fn raw_components(&self) -> RawComponents<'_>;
}

impl<P: AsRef<Path>> RawComponentsIter for P {
    fn raw_components(&self) -> RawComponents<'_> {
        RawComponents {
            inner: Some(self.as_ref().as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{path_split, path_strip_trailing_slash};

    use std::path::{Path, PathBuf};

    use anyhow::{Context, Error};

    // TODO: Add propcheck tests?

    macro_rules! path_strip_slash_tests {
        // path_strip_slash_tests! {
        //      abc("a/b" => "a/b");
        //      xyz("/foo/bar///" => "/foo/bar");
        //      xyz("//" => "/");
        // }
        ($($test_name:ident ($path:expr => $stripped:expr, $trailing:expr));* $(;)? ) => {
            paste::paste! {
                $(
                    #[test]
                    fn [<path_strip_slash_ $test_name>]() {
                        let path: PathBuf = $path.into();
                        let (got_path, got_trailing) = path_strip_trailing_slash(&path);

                        let want_path: PathBuf = $stripped.into();
                        let want_trailing = $trailing;

                        assert_eq!(
                            got_path.as_os_str(), want_path.as_os_str(),
                            "stripping {:?} produced wrong result -- got {:?}",
                            path, got_path,
                        );
                        assert_eq!(
                            got_trailing, want_trailing,
                            "expected {:?} to have trailing_slash={}",
                            path, want_trailing,
                        );
                    }
                )*
            }
        };
    }

    path_strip_slash_tests! {
        empty("" => "", false);
        dot("." => ".", false);
        root("/" => "/", false);

        regular_notrailing1("/foo/bar/baz" => "/foo/bar/baz", false);
        regular_notrailing2("../../a/b/c" => "../../a/b/c", false);
        regular_notrailing3("/a" => "/a", false);

        regular_trailing1("/foo/bar/baz/" => "/foo/bar/baz", true);
        regular_trailing2("../../a/b/c/" => "../../a/b/c", true);
        regular_trailing3("/a/" => "/a", true);

        trailing_dot1("/foo/." => "/foo/.", false);
        trailing_dot2("foo/../bar/../." => "foo/../bar/../.", false);

        root_multi1("////////" => "/", true);
        root_multi2("//" => "/", true);

        complex1("foo//././bar/baz//./" => "foo//././bar/baz//.", true);
        complex2("//a/.///b/../../" => "//a/.///b/../..", true);
        complex3("../foo/bar/.///" => "../foo/bar/.", true);
    }

    macro_rules! path_split_tests {
        // path_tests! {
        //      abc("a/b" => "a", Some("b"));
        //      xyz("/foo/bar/baz" => "/foo/bar", Some("baz"));
        //      xyz("/" => "/", None);
        // }
        ($($test_name:ident ($path:expr => $dir:expr, $file:expr));* $(;)? ) => {
            paste::paste! {
                $(
                    #[test]
                    fn [<path_split_ $test_name>]() -> Result<(), Error> {
                        let path: PathBuf = $path.into();
                        let (got_dir, got_file) = path_split(&path)
                            .with_context(|| format!("path_split({:?})", path))?;

                        let want_dir: PathBuf = $dir.into();
                        let want_file = {
                            let file: Option<&str> = $file;
                            file.map(PathBuf::from)
                        };

                        assert_eq!(
                            (got_dir.as_os_str(), got_file.map(Path::as_os_str)),
                            (want_dir.as_os_str(), want_file.as_ref().map(|p| p.as_os_str()))
                        );
                        Ok(())
                    }
                )*
            }
        };
    }

    path_split_tests! {
        empty("" => ".", None);
        root("/" => "/", None);

        single1("single" => ".", Some("single"));
        single2("./single" => ".", Some("single"));
        single_root1("/single" => "/", Some("single"));

        multi1("foo/bar" => "foo", Some("bar"));
        multi2("foo/bar/baz" => "foo/bar", Some("baz"));
        multi3("./foo/bar/baz" => "./foo/bar", Some("baz"));
        multi_root1("/foo/bar" => "/foo", Some("bar"));
        multi_root2("/foo/bar/baz" => "/foo/bar", Some("baz"));

        trailing_dot1("/foo/." => "/foo", Some("."));
        trailing_dot2("foo/../bar/../." => "foo/../bar/..", Some("."));

        trailing_slash1("/foo/" => "/foo", None);
        trailing_slash2("foo/bar///" => "foo/bar//", None);
        trailing_slash3("./" => ".", None);
        trailing_slash4("//" => "/", None);

        complex1("foo//././bar/baz//./xyz" => "foo//././bar/baz//.", Some("xyz"));
        complex2("//a/.///b/../../xyz" => "//a/.///b/../..", Some("xyz"));
        complex3("../foo/bar/.///baz" => "../foo/bar/.//", Some("baz"));
    }
}

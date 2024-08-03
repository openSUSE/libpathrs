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

use crate::error::{self, Error};

use std::{
    collections::VecDeque,
    ffi::{CString, OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
};

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
    use crate::{
        procfs::PROCFS_HANDLE,
        syscalls,
        utils::{path_split, path_strip_trailing_slash, RawFdExt},
    };

    use std::{
        fs::File,
        os::fd::{AsRawFd, RawFd},
        path::{Path, PathBuf},
    };

    use anyhow::{Context, Error};
    use tempfile::TempDir;

    fn check_as_unsafe_path<P: AsRef<Path>>(fd: RawFd, want_path: P) -> Result<(), Error> {
        let want_path = want_path.as_ref();

        // Plain /proc/... lookup.
        let got_path = fd.as_unsafe_path_unchecked()?;
        assert_eq!(
            got_path, want_path,
            "expected as_unsafe_path_unchecked to give the correct path"
        );
        // ProcfsHandle-based lookup.
        let got_path = fd.as_unsafe_path(&PROCFS_HANDLE)?;
        assert_eq!(
            got_path, want_path,
            "expected as_unsafe_path to give the correct path"
        );
        Ok(())
    }

    #[test]
    fn as_unsafe_path_cwd() -> Result<(), Error> {
        let real_cwd = syscalls::getcwd()?;
        check_as_unsafe_path(libc::AT_FDCWD, real_cwd)
    }

    #[test]
    fn as_unsafe_path_fd() -> Result<(), Error> {
        let real_tmpdir = TempDir::new()?;
        let file = File::open(&real_tmpdir)?;
        check_as_unsafe_path(file.as_raw_fd(), real_tmpdir)
    }

    #[test]
    fn as_unsafe_path_badfd() {
        let bad_fd: RawFd = -1;

        assert!(
            bad_fd.as_unsafe_path_unchecked().is_err(),
            "as_unsafe_path_unchecked should fail for bad file descriptor"
        );
        assert!(
            bad_fd.as_unsafe_path(&PROCFS_HANDLE).is_err(),
            "as_unsafe_path should fail for bad file descriptor"
        );
    }

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

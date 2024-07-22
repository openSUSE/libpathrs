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

use std::fs::File;

use crate::{Handle, ResolverBackend, ResolverFlags, Root};
use utils::ExpectedResult;

use anyhow::Error;

macro_rules! resolve_tests {
    // resolve_tests! {
    //     abc("foo") => ExpectedResult::Err(..);
    //     xyz("baz") => ExpectedResult::Ok{..};
    // }
    ($($test_name:ident ( $unsafe_path:expr ) => $expected:expr);+ $(;)*) => {
        paste::paste! {
            $(
                #[test]
                fn [<test_root_default_ $test_name>]() -> Result<(), Error> {
                    let root_dir = super::common::create_basic_tree()?;
                    let root = Root::open(&root_dir)?;
                    let expected = $expected;
                    utils::check_resolve_in_root(&root, $unsafe_path, &expected)?;

                    // Make sure root_dir is not dropped earlier.
                    let _root_dir = root_dir;

                    Ok(())
                }

                #[test]
                fn [<test_root_opath_ $test_name>]() -> Result<(), Error> {
                    let root_dir = super::common::create_basic_tree()?;
                    let mut root = Root::open(&root_dir)?;
                    root.resolver.backend = ResolverBackend::EmulatedOpath;

                    let expected = $expected;
                    utils::check_resolve_in_root(&root, $unsafe_path, &expected)?;

                    // Make sure root_dir is not dropped earlier.
                    let _root_dir = root_dir;

                    Ok(())
                }

                #[test]
                fn [<test_root_openat2_ $test_name>]() -> Result<(), Error> {
                    if !*$crate::resolvers::openat2::IS_SUPPORTED {
                        // skip test
                        return Ok(());
                    }

                    let root_dir = super::common::create_basic_tree()?;
                    let mut root = Root::open(&root_dir)?;
                    root.resolver.backend = ResolverBackend::KernelOpenat2;

                    let expected = $expected;
                    utils::check_resolve_in_root(&root, $unsafe_path, &expected)?;

                    // Make sure root_dir is not dropped earlier.
                    let _root_dir = root_dir;

                    Ok(())
                }

                #[test]
                fn [<test_opath_ $test_name>]() -> Result<(), Error> {
                    let root_dir = super::common::create_basic_tree()?;
                    let root = File::open(&root_dir)?;

                    let expected = $expected;
                    utils::check_resolve_fn(
                        |file, subpath| {
                            $crate::resolvers::opath::resolve(file, subpath, ResolverFlags::default())
                                .map(Handle::into_file)
                        },
                        &root,
                        $unsafe_path,
                        &expected,
                    )?;

                    // Make sure root_dir is not dropped earlier.
                    let _root_dir = root_dir;

                    Ok(())
                }

                #[test]
                fn [<test_openat2_ $test_name>]() -> Result<(), Error> {
                    if !*$crate::resolvers::openat2::IS_SUPPORTED {
                        // skip test
                        return Ok(());
                    }

                    let root_dir = super::common::create_basic_tree()?;
                    let root = File::open(&root_dir)?;

                    let expected = $expected;
                    utils::check_resolve_fn(
                        |file, subpath| {
                            $crate::resolvers::openat2::resolve(file, subpath, ResolverFlags::default())
                                .map(Handle::into_file)
                        },
                        &root,
                        $unsafe_path,
                        &expected,
                    )?;

                    // Make sure root_dir is not dropped earlier.
                    let _root_dir = root_dir;

                    Ok(())
                }
            )*
        }
    }
}

resolve_tests! {
    // Complete lookups.
    complete_dir1("a") => ExpectedResult::Ok { real_path: "/a", file_type: libc::S_IFDIR };
    complete_dir2("b/c/d/e/f") => ExpectedResult::Ok { real_path: "/b/c/d/e/f", file_type: libc::S_IFDIR };
    complete_file("b/c/file") => ExpectedResult::Ok { real_path: "/b/c/file", file_type: libc::S_IFREG };
    complete_file_link("b-file") => ExpectedResult::Ok { real_path: "/b/c/file", file_type: libc::S_IFREG };
    complete_fifo("b/fifo") => ExpectedResult::Ok { real_path: "/b/fifo", file_type: libc::S_IFIFO };
    complete_sock("b/sock") => ExpectedResult::Ok { real_path: "/b/sock", file_type: libc::S_IFSOCK };
    // Partial lookups.
    partial_dir_basic("a/b/c/d/e/f/g/h") => ExpectedResult::Err(libc::ENOENT);
    partial_dir_dotdot("a/foo/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    // Complete lookups of non_lexical symlinks.
    nonlexical_basic_complete("target") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_basic_partial("target/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_basic_partial_dotdot("target/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level1_abs_complete("link1/target_abs") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level1_abs_partial("link1/target_abs/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level1_abs_partial_dotdot("link1/target_abs/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level1_rel_complete("link1/target_rel") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level1_rel_partial("link1/target_rel/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level1_rel_partial_dotdot("link1/target_rel/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_abs_abs_complete("link2/link1_abs/target_abs") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level2_abs_abs_partial("link2/link1_abs/target_abs/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_abs_abs_partial_dotdot("link2/link1_abs/target_abs/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_abs_rel_complete("link2/link1_abs/target_rel") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level2_abs_rel_partial("link2/link1_abs/target_rel/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_abs_rel_partial_dotdot("link2/link1_abs/target_rel/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_abs_open_complete("link2/link1_abs/../target") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level2_abs_open_partial("link2/link1_abs/../target/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_abs_open_partial_dotdot("link2/link1_abs/../target/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_rel_abs_complete("link2/link1_rel/target_abs") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level2_rel_abs_partial("link2/link1_rel/target_abs/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_rel_abs_partial_dotdot("link2/link1_rel/target_abs/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_rel_rel_complete("link2/link1_rel/target_rel") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level2_rel_rel_partial("link2/link1_rel/target_rel/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_rel_rel_partial_dotdot("link2/link1_rel/target_rel/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_rel_open_complete("link2/link1_rel/../target") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level2_rel_open_partial("link2/link1_rel/../target/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level2_rel_open_partial_dotdot("link2/link1_rel/../target/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level3_abs_complete("link3/target_abs") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level3_abs_partial("link3/target_abs/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level3_abs_partial_dotdot("link3/target_abs/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level3_rel_complete("link3/target_rel") => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
    nonlexical_level3_rel_partial("link3/target_rel/foo") => ExpectedResult::Err(libc::ENOENT);
    nonlexical_level3_rel_partial_dotdot("link3/target_rel/../target/foo/bar/../baz") => ExpectedResult::Err(libc::ENOENT);
    // Partial lookups due to hitting a non_directory.
    partial_nondir_dot("b/c/file/.") => ExpectedResult::Err(libc::ENOTDIR);
    partial_nondir_dotdot1("b/c/file/..") => ExpectedResult::Err(libc::ENOTDIR);
    partial_nondir_dotdot2("b/c/file/../foo/bar") => ExpectedResult::Err(libc::ENOTDIR);
    partial_nondir_symlink_dot("b-file/.") => ExpectedResult::Err(libc::ENOTDIR);
    partial_nondir_symlink_dotdot1("b-file/..") => ExpectedResult::Err(libc::ENOTDIR);
    partial_nondir_symlink_dotdot2("b-file/../foo/bar") => ExpectedResult::Err(libc::ENOTDIR);
    partial_fifo_dot("b/fifo/.") => ExpectedResult::Err(libc::ENOTDIR);
    partial_fifo_dotdot1("b/fifo/..") => ExpectedResult::Err(libc::ENOTDIR);
    partial_fifo_dotdot2("b/fifo/../foo/bar") => ExpectedResult::Err(libc::ENOTDIR);
    partial_sock_dot("b/sock/.") => ExpectedResult::Err(libc::ENOTDIR);
    partial_sock_dotdot1("b/sock/..") => ExpectedResult::Err(libc::ENOTDIR);
    partial_sock_dotdot2("b/sock/../foo/bar") => ExpectedResult::Err(libc::ENOTDIR);
    // Dangling symlinks are treated as though they are non_existent.
    dangling1_inroot_trailing("a-fake1") => ExpectedResult::Err(libc::ENOENT);
    dangling1_inroot_partial("a-fake1/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling1_inroot_partial_dotdot("a-fake1/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    dangling1_sub_trailing("c/a-fake1") => ExpectedResult::Err(libc::ENOENT);
    dangling1_sub_partial("c/a-fake1/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling1_sub_partial_dotdot("c/a-fake1/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    dangling2_inroot_trailing("a-fake2") => ExpectedResult::Err(libc::ENOENT);
    dangling2_inroot_partial("a-fake2/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling2_inroot_partial_dotdot("a-fake2/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    dangling2_sub_trailing("c/a-fake2") => ExpectedResult::Err(libc::ENOENT);
    dangling2_sub_partial("c/a-fake2/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling2_sub_partial_dotdot("c/a-fake2/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    dangling3_inroot_trailing("a-fake3") => ExpectedResult::Err(libc::ENOENT);
    dangling3_inroot_partial("a-fake3/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling3_inroot_partial_dotdot("a-fake3/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    dangling3_sub_trailing("c/a-fake3") => ExpectedResult::Err(libc::ENOENT);
    dangling3_sub_partial("c/a-fake3/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling3_sub_partial_dotdot("c/a-fake3/../bar/baz") => ExpectedResult::Err(libc::ENOENT);
    // Tricky dangling symlinks.
    dangling_tricky1_trailing("link3/deep_dangling1") => ExpectedResult::Err(libc::ENOENT);
    dangling_tricky1_partial("link3/deep_dangling1/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling_tricky1_partial_dotdot("link3/deep_dangling1/..") => ExpectedResult::Err(libc::ENOENT);
    dangling_tricky2_trailing("link3/deep_dangling2") => ExpectedResult::Err(libc::ENOENT);
    dangling_tricky2_partial("link3/deep_dangling2/foo") => ExpectedResult::Err(libc::ENOENT);
    dangling_tricky2_partial_dotdot("link3/deep_dangling2/..") => ExpectedResult::Err(libc::ENOENT);
    // Really deep dangling links.
    deep_dangling1("dangling/a") => ExpectedResult::Err(libc::ENOENT);
    deep_dangling2("dangling/b/c") => ExpectedResult::Err(libc::ENOENT);
    deep_dangling3("dangling/c") => ExpectedResult::Err(libc::ENOENT);
    deep_dangling4("dangling/d/e") => ExpectedResult::Err(libc::ENOENT);
    deep_dangling5("dangling/e") => ExpectedResult::Err(libc::ENOENT);
    deep_dangling6("dangling/g") => ExpectedResult::Err(libc::ENOENT);
    deep_dangling_fileasdir1("dangling-file/a") => ExpectedResult::Err(libc::ENOTDIR);
    deep_dangling_fileasdir2("dangling-file/b/c") => ExpectedResult::Err(libc::ENOTDIR);
    deep_dangling_fileasdir3("dangling-file/c") => ExpectedResult::Err(libc::ENOTDIR);
    deep_dangling_fileasdir4("dangling-file/d/e") => ExpectedResult::Err(libc::ENOTDIR);
    deep_dangling_fileasdir5("dangling-file/e") => ExpectedResult::Err(libc::ENOTDIR);
    deep_dangling_fileasdir6("dangling-file/g") => ExpectedResult::Err(libc::ENOTDIR);
    // Symlink loops.
    loop1("loop/link") => ExpectedResult::Err(libc::ELOOP);
    loop_basic1("loop/basic-loop1") => ExpectedResult::Err(libc::ELOOP);
    loop_basic2("loop/basic-loop2") => ExpectedResult::Err(libc::ELOOP);
    loop_basic3("loop/basic-loop3") => ExpectedResult::Err(libc::ELOOP);
}

mod utils {
    use std::{fs::File, io, os::linux::fs::MetadataExt, path::Path};

    use crate::{error::Error as PathrsError, utils::RawFdExt, Handle, OpenFlags, Root};

    use anyhow::Error;
    use errno::Errno;

    // TODO: Remove when raw_os_error_ty is stabilised.
    //       <https://github.com/rust-lang/rust/issues/107792>
    pub(super) type RawOsError = i32;

    fn errno_description(err: RawOsError) -> String {
        format!("{:?} ({})", err, Errno(err))
    }

    pub(super) fn check_reopen<F: Into<OpenFlags>>(
        handle: &Handle,
        flags: F,
        expected_error: Option<RawOsError>,
    ) -> Result<(), Error> {
        let file = match (handle.reopen(flags), expected_error) {
            (Ok(f), None) => f,
            (Err(e), None) => anyhow::bail!("unexpected error '{}'", e),
            (Ok(f), Some(expected)) => anyhow::bail!(
                "expected to get io::Error {} but instead got file {}",
                errno_description(expected),
                f.as_unsafe_path()?.display(),
            ),
            (Err(err), Some(want_err)) => {
                assert_eq!(
                    err.root_cause()
                        .downcast_ref::<io::Error>()
                        .map(io::Error::raw_os_error)
                        .flatten(),
                    Some(want_err),
                    "expected io::Error {}, got '{}'",
                    errno_description(want_err),
                    err,
                );
                return Ok(());
            }
        };

        let real_handle_path = handle.as_file().as_unsafe_path()?;
        let real_reopen_path = file.as_unsafe_path()?;

        assert_eq!(
            real_handle_path, real_reopen_path,
            "reopened handle should be equivalent to old handle",
        );

        // TODO: Check fd flags.

        Ok(())
    }

    pub(super) enum ExpectedResult<'a> {
        Ok {
            real_path: &'a str,
            file_type: libc::mode_t,
        },
        Err(RawOsError),
    }

    fn check_resolve<R, P, Q, F>(
        lookup: F,
        root: R,
        root_dir: P,
        unsafe_path: Q,
        expected: &ExpectedResult,
    ) -> Result<(), Error>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        F: FnOnce(R, Q) -> Result<Handle, PathrsError>,
    {
        let (handle, expected_path, expected_file_type) =
            match (lookup(root, unsafe_path), expected) {
                (
                    Ok(h),
                    ExpectedResult::Ok {
                        real_path,
                        file_type,
                    },
                ) => (h, *real_path, *file_type),

                (Err(e), ExpectedResult::Ok { real_path, .. }) => {
                    anyhow::bail!("unexpected error '{}', expected file {}", e, real_path)
                }
                (Ok(h), ExpectedResult::Err(want_err)) => anyhow::bail!(
                    "expected to get io::Error {} but instead got file {}",
                    errno_description(*want_err),
                    h.as_file().as_unsafe_path()?.display(),
                ),

                (Err(err), ExpectedResult::Err(want_err)) => {
                    assert_eq!(
                        err.root_cause()
                            .downcast_ref::<io::Error>()
                            .map(io::Error::raw_os_error)
                            .flatten(),
                        Some(*want_err),
                        "expected io::Error {}, got '{}'",
                        errno_description(*want_err),
                        err,
                    );
                    return Ok(());
                }
            };

        let expected_path = expected_path.trim_start_matches('/');
        let real_handle_path = handle.as_file().as_unsafe_path()?;
        assert_eq!(
            real_handle_path,
            root_dir.as_ref().join(expected_path),
            "handle path mismatch",
        );

        let meta = handle.as_file().metadata()?;
        let real_file_type = meta.st_mode() & libc::S_IFMT;
        assert_eq!(real_file_type, expected_file_type, "file type mismatch",);

        match real_file_type {
            libc::S_IFDIR => {
                check_reopen(&handle, libc::O_RDONLY, None)?;
                check_reopen(&handle, libc::O_DIRECTORY, None)?;
            }
            libc::S_IFREG => {
                check_reopen(&handle, libc::O_RDWR, None)?;
                check_reopen(&handle, libc::O_DIRECTORY, Some(libc::ENOTDIR))?;
            }
            _ => {
                check_reopen(&handle, libc::O_PATH, None)?;
                check_reopen(
                    &handle,
                    libc::O_PATH | libc::O_DIRECTORY,
                    Some(libc::ENOTDIR),
                )?;
            }
        }

        Ok(())
    }

    pub(super) fn check_resolve_fn<P, F>(
        lookup: F,
        root: &File,
        unsafe_path: P,
        expected: &ExpectedResult,
    ) -> Result<(), Error>
    where
        P: AsRef<Path>,
        F: FnOnce(&File, P) -> Result<File, PathrsError>,
    {
        check_resolve(
            |root: &File, unsafe_path: P| {
                lookup(root, unsafe_path)
                    .map(Handle::from_file_unchecked)
                    .map_err(Into::into)
            },
            root,
            root.as_unsafe_path()?,
            unsafe_path,
            expected,
        )
    }

    pub(super) fn check_resolve_in_root<P>(
        root: &Root,
        unsafe_path: P,
        expected: &ExpectedResult,
    ) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        check_resolve(
            |root: &Root, unsafe_path: P| root.resolve(unsafe_path).map_err(Into::into),
            root,
            root.as_file().as_unsafe_path()?,
            unsafe_path,
            expected,
        )
    }
}

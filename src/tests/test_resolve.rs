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

use std::{fs::File, path::Path};

use crate::{
    resolvers::{opath, openat2},
    syscalls,
    tests::common as tests_common,
    Handle, ResolverBackend, ResolverFlags, Root,
};
use utils::ExpectedResult;

use anyhow::Error;

macro_rules! resolve_tests {
    // resolve_tests! {
    //     abc("foo") => ExpectedResult::Err(..);
    //     xyz("baz") => ExpectedResult::Ok{..};
    // }
    ($(let $root_dir_var:ident = $root_dir:expr => @reopen_tests:$reopen_tests:ident { $($test_name:ident ( $unsafe_path:expr, $rflags:expr ) => $expected:expr);+ $(;)? });* $(;)?) => {
        paste::paste! {
            $( $(
                #[test]
                fn [<root_default_ $test_name>]() -> Result<(), Error> {
                    let $root_dir_var = $root_dir;
                    let mut root = Root::open(&$root_dir_var)?;
                    root.resolver.flags = $rflags;
                    let expected = $expected;
                    let reopen_tests: bool = $reopen_tests;
                    utils::check_resolve_in_root(
                        &root,
                        $unsafe_path,
                        &expected,
                        reopen_tests,
                    )?;

                    // Make sure $root_dir_var is not dropped earlier.
                    let _root_dir_var = $root_dir_var;

                    Ok(())
                }

                #[test]
                fn [<root_opath_ $test_name>]() -> Result<(), Error> {
                    let $root_dir_var = $root_dir;
                    let mut root = Root::open(&$root_dir_var)?;
                    root.resolver.flags = $rflags;
                    root.resolver.backend = ResolverBackend::EmulatedOpath;

                    let expected = $expected;
                    let reopen_tests: bool = $reopen_tests;
                    utils::check_resolve_in_root(
                        &root,
                        $unsafe_path,
                        &expected,
                        reopen_tests,
                    )?;

                    // Make sure $root_dir_var is not dropped earlier.
                    let _root_dir_var = $root_dir_var;

                    Ok(())
                }

                #[test]
                fn [<root_openat2_ $test_name>]() -> Result<(), Error> {
                    let $root_dir_var = $root_dir;
                    let mut root = Root::open(&$root_dir_var)?;
                    root.resolver.flags = $rflags;
                    root.resolver.backend = ResolverBackend::KernelOpenat2;

                    if !root.resolver.backend.supported() {
                        // skip test
                        return Ok(());
                    }

                    let expected = $expected;
                    let reopen_tests: bool = $reopen_tests;
                    utils::check_resolve_in_root(
                        &root,
                        $unsafe_path,
                        &expected,
                        reopen_tests,
                    )?;

                    // Make sure $root_dir_var is not dropped earlier.
                    let _root_dir_var = $root_dir_var;

                    Ok(())
                }

                #[test]
                fn [<opath_ $test_name>]() -> Result<(), Error> {
                    let $root_dir_var = $root_dir;
                    let root = File::open(&$root_dir_var)?;
                    let rflags = $rflags;

                    let expected = $expected;
                    let reopen_tests: bool = $reopen_tests;
                    utils::check_resolve_fn(
                        |file, subpath| {
                            opath::resolve(file, subpath, rflags)
                                .map(Handle::into_file)
                        },
                        &root,
                        $unsafe_path,
                        &expected,
                        reopen_tests,
                    )?;

                    // Make sure $root_dir_var is not dropped earlier.
                    let _root_dir_var = $root_dir_var;

                    Ok(())
                }

                #[test]
                fn [<openat2_ $test_name>]() -> Result<(), Error> {
                    if !*$crate::syscalls::OPENAT2_IS_SUPPORTED {
                        // skip test
                        return Ok(());
                    }

                    let $root_dir_var = $root_dir;
                    let root = File::open(&$root_dir_var)?;
                    let rflags = $rflags;

                    let expected = $expected;
                    let reopen_tests: bool = $reopen_tests;
                    utils::check_resolve_fn(
                        |file, subpath| {
                            openat2::resolve(file, subpath, rflags)
                                .map(Handle::into_file)
                        },
                        &root,
                        $unsafe_path,
                        &expected,
                        reopen_tests,
                    )?;

                    // Make sure $root_dir_var is not dropped earlier.
                    let _root_dir_var = $root_dir_var;

                    Ok(())
                }
            )* )*
        }
    }
}

resolve_tests! {
    let proc_root_dir = Path::new("/proc") => @reopen_tests:false {
        proc_pseudo_magiclink("self/status", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: &*format!("{}/status", syscalls::getpid()), file_type: libc::S_IFREG };
        proc_pseudo_magiclink_nosym1("self", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Err(libc::ELOOP);
        proc_pseudo_magiclink_nosym2("self/status", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Err(libc::ELOOP);
        proc_pseudo_magiclink_nofollow1("self", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: "self", file_type: libc::S_IFLNK };
        proc_pseudo_magiclink_nofollow2("self/status", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: &*format!("{}/status", syscalls::getpid()), file_type: libc::S_IFREG };

        proc_magiclink("self/exe", ResolverFlags::empty()) => ExpectedResult::Err(libc::ELOOP);
        proc_magiclink_nofollow("self/exe", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: &*format!("{}/exe", syscalls::getpid()), file_type: libc::S_IFLNK };
        proc_magiclink_component_nofollow("self/root/etc/passwd", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Err(libc::ELOOP);
    };

    // Complete lookups.
    let root_dir = tests_common::create_basic_tree()? => @reopen_tests:true {
        complete_root1("/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/", file_type: libc::S_IFDIR };
        complete_root2("/../../../../../..", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/", file_type: libc::S_IFDIR };
        complete_root_link1("root-link1", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/", file_type: libc::S_IFDIR };
        complete_root_link2("root-link2", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/", file_type: libc::S_IFDIR };
        complete_root_link3("root-link3", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/", file_type: libc::S_IFDIR };
        complete_dir1("a", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/a", file_type: libc::S_IFDIR };
        complete_dir2("b/c/d/e/f", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/b/c/d/e/f", file_type: libc::S_IFDIR };
        complete_dir3("b///././c////.//d/./././///e////.//./f//././././", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/b/c/d/e/f", file_type: libc::S_IFDIR };
        complete_file("b/c/file", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/b/c/file", file_type: libc::S_IFREG };
        complete_file_link("b-file", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/b/c/file", file_type: libc::S_IFREG };
        complete_fifo("b/fifo", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/b/fifo", file_type: libc::S_IFIFO };
        complete_sock("b/sock", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/b/sock", file_type: libc::S_IFSOCK };
        // Partial lookups.
        partial_dir_basic("a/b/c/d/e/f/g/h", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        partial_dir_dotdot("a/foo/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        // Complete lookups of non_lexical symlinks.
        nonlexical_basic_complete("target", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_basic_complete1("target/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_basic_complete2("target//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_basic_partial("target/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_basic_partial_dotdot("target/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level1_abs_complete1("link1/target_abs", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level1_abs_complete2("link1/target_abs/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level1_abs_complete3("link1/target_abs//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level1_abs_partial("link1/target_abs/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level1_abs_partial_dotdot("link1/target_abs/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level1_rel_complete1("link1/target_rel", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level1_rel_complete2("link1/target_rel/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level1_rel_complete3("link1/target_rel//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level1_rel_partial("link1/target_rel/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level1_rel_partial_dotdot("link1/target_rel/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_abs_abs_complete1("link2/link1_abs/target_abs", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_abs_complete2("link2/link1_abs/target_abs/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_abs_complete3("link2/link1_abs/target_abs//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_abs_partial("link2/link1_abs/target_abs/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_abs_abs_partial_dotdot("link2/link1_abs/target_abs/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_abs_rel_complete1("link2/link1_abs/target_rel", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_rel_complete2("link2/link1_abs/target_rel/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_rel_complete3("link2/link1_abs/target_rel//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_rel_partial("link2/link1_abs/target_rel/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_abs_rel_partial_dotdot("link2/link1_abs/target_rel/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_abs_open_complete1("link2/link1_abs/../target", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_open_complete2("link2/link1_abs/../target/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_open_complete3("link2/link1_abs/../target//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_abs_open_partial("link2/link1_abs/../target/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_abs_open_partial_dotdot("link2/link1_abs/../target/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_rel_abs_complete1("link2/link1_rel/target_abs", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_abs_complete2("link2/link1_rel/target_abs/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_abs_complete3("link2/link1_rel/target_abs//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_abs_partial("link2/link1_rel/target_abs/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_rel_abs_partial_dotdot("link2/link1_rel/target_abs/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_rel_rel_complete1("link2/link1_rel/target_rel", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_rel_complete2("link2/link1_rel/target_rel/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_rel_complete3("link2/link1_rel/target_rel//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_rel_partial("link2/link1_rel/target_rel/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_rel_rel_partial_dotdot("link2/link1_rel/target_rel/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_rel_open_complete1("link2/link1_rel/../target", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_open_complete2("link2/link1_rel/../target/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_open_complete3("link2/link1_rel/../target//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level2_rel_open_partial("link2/link1_rel/../target/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level2_rel_open_partial_dotdot("link2/link1_rel/../target/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level3_abs_complete1("link3/target_abs", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level3_abs_complete2("link3/target_abs/", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level3_abs_complete3("link3/target_abs//", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level3_abs_partial("link3/target_abs/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level3_abs_partial_dotdot("link3/target_abs/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level3_rel_complete("link3/target_rel", ResolverFlags::empty()) => ExpectedResult::Ok { real_path: "/target", file_type: libc::S_IFDIR };
        nonlexical_level3_rel_partial("link3/target_rel/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        nonlexical_level3_rel_partial_dotdot("link3/target_rel/../target/foo/bar/../baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        // Partial lookups due to hitting a non_directory.
        partial_nondir_slash1("b/c/file/", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_slash2("b/c/file//", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_dot("b/c/file/.", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_dotdot1("b/c/file/..", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_dotdot2("b/c/file/../foo/bar", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_symlink_slash1("b-file/", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_symlink_slash2("b-file//", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_symlink_dot("b-file/.", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_symlink_dotdot1("b-file/..", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_nondir_symlink_dotdot2("b-file/../foo/bar", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_fifo_slash1("b/fifo/", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_fifo_slash2("b/fifo//", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_fifo_dot("b/fifo/.", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_fifo_dotdot1("b/fifo/..", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_fifo_dotdot2("b/fifo/../foo/bar", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_sock_slash1("b/sock/", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_sock_slash2("b/sock//", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_sock_dot("b/sock/.", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_sock_dotdot1("b/sock/..", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        partial_sock_dotdot2("b/sock/../foo/bar", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        // Dangling symlinks are treated as though they are non_existent.
        dangling1_inroot_trailing("a-fake1", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling1_inroot_partial("a-fake1/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling1_inroot_partial_dotdot("a-fake1/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling1_sub_trailing("c/a-fake1", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling1_sub_partial("c/a-fake1/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling1_sub_partial_dotdot("c/a-fake1/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling2_inroot_trailing("a-fake2", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling2_inroot_partial("a-fake2/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling2_inroot_partial_dotdot("a-fake2/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling2_sub_trailing("c/a-fake2", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling2_sub_partial("c/a-fake2/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling2_sub_partial_dotdot("c/a-fake2/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling3_inroot_trailing("a-fake3", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling3_inroot_partial("a-fake3/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling3_inroot_partial_dotdot("a-fake3/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling3_sub_trailing("c/a-fake3", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling3_sub_partial("c/a-fake3/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling3_sub_partial_dotdot("c/a-fake3/../bar/baz", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        // Tricky dangling symlinks.
        dangling_tricky1_trailing("link3/deep_dangling1", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling_tricky1_partial("link3/deep_dangling1/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling_tricky1_partial_dotdot("link3/deep_dangling1/..", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling_tricky2_trailing("link3/deep_dangling2", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling_tricky2_partial("link3/deep_dangling2/foo", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        dangling_tricky2_partial_dotdot("link3/deep_dangling2/..", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        // Really deep dangling links.
        deep_dangling1("dangling/a", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        deep_dangling2("dangling/b/c", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        deep_dangling3("dangling/c", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        deep_dangling4("dangling/d/e", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        deep_dangling5("dangling/e", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        deep_dangling6("dangling/g", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOENT);
        deep_dangling_fileasdir1("dangling-file/a", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        deep_dangling_fileasdir2("dangling-file/b/c", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        deep_dangling_fileasdir3("dangling-file/c", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        deep_dangling_fileasdir4("dangling-file/d/e", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        deep_dangling_fileasdir5("dangling-file/e", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        deep_dangling_fileasdir6("dangling-file/g", ResolverFlags::empty()) => ExpectedResult::Err(libc::ENOTDIR);
        // Symlink loops.
        loop1("loop/link", ResolverFlags::empty()) => ExpectedResult::Err(libc::ELOOP);
        loop_basic1("loop/basic-loop1", ResolverFlags::empty()) => ExpectedResult::Err(libc::ELOOP);
        loop_basic2("loop/basic-loop2", ResolverFlags::empty()) => ExpectedResult::Err(libc::ELOOP);
        loop_basic3("loop/basic-loop3", ResolverFlags::empty()) => ExpectedResult::Err(libc::ELOOP);
        // NO_FOLLOW.
        symlink_nofollow("link3/target_abs", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: "link3/target_abs", file_type: libc::S_IFLNK };
        symlink_component_nofollow1("e/f", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: "b/c/d/e/f", file_type: libc::S_IFDIR };
        symlink_component_nofollow2("link2/link1_abs/target_rel", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: "link1/target_rel", file_type: libc::S_IFLNK };
        loop_nofollow("loop/link", ResolverFlags::NO_FOLLOW_TRAILING) => ExpectedResult::Ok { real_path: "loop/link", file_type: libc::S_IFLNK };
        // RESOLVE_NO_SYMLINKS.
        dir_nosym("b/c/d/e", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Ok { real_path: "b/c/d/e", file_type: libc::S_IFDIR };
        symlink_nosym("link3/target_abs", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Err(libc::ELOOP);
        symlink_component_nosym1("e/f", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Err(libc::ELOOP);
        symlink_component_nosym2("link2/link1_abs/target_rel", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Err(libc::ELOOP);
        loop_nosym("loop/link", ResolverFlags::NO_SYMLINKS) => ExpectedResult::Err(libc::ELOOP);
    }
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

    pub(super) fn check_reopen(
        handle: &Handle,
        flags: OpenFlags,
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
                        .and_then(io::Error::raw_os_error),
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
        reopen_tests: bool,
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
                            .and_then(io::Error::raw_os_error),
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

        if reopen_tests {
            match real_file_type {
                libc::S_IFDIR => {
                    check_reopen(&handle, OpenFlags::O_RDONLY, None)?;
                    check_reopen(&handle, OpenFlags::O_DIRECTORY, None)?;
                }
                libc::S_IFREG => {
                    check_reopen(&handle, OpenFlags::O_RDWR, None)?;
                    check_reopen(&handle, OpenFlags::O_DIRECTORY, Some(libc::ENOTDIR))?;
                }
                _ => {
                    check_reopen(&handle, OpenFlags::O_PATH, None)?;
                    check_reopen(
                        &handle,
                        OpenFlags::O_PATH | OpenFlags::O_DIRECTORY,
                        Some(libc::ENOTDIR),
                    )?;
                }
            }
        }

        Ok(())
    }

    pub(super) fn check_resolve_fn<P, F>(
        lookup: F,
        root: &File,
        unsafe_path: P,
        expected: &ExpectedResult,
        reopen_tests: bool,
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
            reopen_tests,
        )
    }

    pub(super) fn check_resolve_in_root<P>(
        root: &Root,
        unsafe_path: P,
        expected: &ExpectedResult,
        reopen_tests: bool,
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
            reopen_tests,
        )
    }
}

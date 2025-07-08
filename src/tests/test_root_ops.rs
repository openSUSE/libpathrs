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

#[cfg(feature = "capi")]
use crate::tests::capi;
use crate::{
    error::ErrorKind,
    flags::{OpenFlags, RenameFlags},
    resolvers::ResolverBackend,
    tests::common as tests_common,
    InodeType, Root,
};

use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use anyhow::Error;

macro_rules! root_op_tests {
    ($(#[$meta:meta])* fn $test_name:ident ($root_var:ident) $body:block) => {
        paste::paste! {
            $(#[$meta])*
            #[test]
            fn [<root_ $test_name>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let $root_var = Root::open(&root_dir)?;

                $body
            }

            $(#[$meta])*
            #[test]
            fn [<rootref_ $test_name>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let root = Root::open(&root_dir)?;
                let $root_var = root.as_ref();

                $body
            }

            $(#[$meta])*
            #[test]
            fn [<root_ $test_name _openat2>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let $root_var = Root::open(&root_dir)?
                    .with_resolver_backend(ResolverBackend::KernelOpenat2);
                if !$root_var.resolver_backend().supported() {
                    // Skip if not supported.
                    return Ok(());
                }

                $body
            }

            $(#[$meta])*
            #[test]
            fn [<rootref_ $test_name _openat2>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let root = Root::open(&root_dir)?;
                let $root_var = root
                    .as_ref()
                    .with_resolver_backend(ResolverBackend::KernelOpenat2);
                if !$root_var.resolver_backend().supported() {
                    // Skip if not supported.
                    return Ok(());
                }

                $body
            }

            $(#[$meta])*
            #[test]
            fn [<root_ $test_name _opath>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let $root_var = Root::open(&root_dir)?
                    .with_resolver_backend(ResolverBackend::EmulatedOpath);
                // EmulatedOpath is always supported.
                assert!(
                    $root_var.resolver_backend().supported(),
                    "emulated opath is always supported",
                );

                $body
            }

            $(#[$meta])*
            #[test]
            fn [<rootref_ $test_name _opath>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let root = Root::open(&root_dir)?;
                let $root_var = root
                    .as_ref()
                    .with_resolver_backend(ResolverBackend::EmulatedOpath);
                // EmulatedOpath is always supported.
                assert!(
                    $root_var.resolver_backend().supported(),
                    "emulated opath is always supported",
                );

                $body
            }

            $(#[$meta])*
            #[cfg(feature = "capi")]
            #[test]
            fn [<capi_root_ $test_name>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let $root_var = capi::CapiRoot::open(&root_dir)?;

                $body
            }
        }
    };

    ($(#[$meta:meta])* @mknod fn $test_name:ident ($path:expr) $make_inode_type:block => $expected_result:expr) => {
        root_op_tests!{
            $(#[$meta])*
            fn $test_name(root) {
                let inode_type = $make_inode_type;
                utils::check_root_create(&root, $path, inode_type, $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl mkfile $test_name:ident ($path:expr, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::File(Permissions::from_mode($mode))
            } => $expected_result
        }
    };
    ($(#[cfg($ignore_meta:meta)])* @impl mkdir $test_name:ident ($path:expr, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::Directory(Permissions::from_mode($mode))
            } => $expected_result
        }
    };
    ($(#[cfg($ignore_meta:meta)])* @impl symlink $test_name:ident ($path:expr, $target:expr) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::Symlink($target.into())
            } => $expected_result
        }
    };
    ($(#[cfg($ignore_meta:meta)])* @impl hardlink $test_name:ident ($path:expr, $target:expr) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::Hardlink($target.into())
            } => $expected_result
        }
    };
    ($(#[cfg($ignore_meta:meta)])* @impl mkfifo $test_name:ident ($path:expr, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::Fifo(Permissions::from_mode($mode))
            } => $expected_result
        }
    };
    ($(#[cfg($ignore_meta:meta)])* @impl mkblk $test_name:ident ($path:expr, $mode:literal, $major:literal, $minor:literal) => $expected_result:expr) => {
        root_op_tests!{
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::BlockDevice(Permissions::from_mode($mode), libc::makedev($major, $minor))
            } => $expected_result
        }
    };
    ($(#[cfg($ignore_meta:meta)])* @impl mkchar $test_name:ident ($path:expr, $mode:literal, $major:literal, $minor:literal) => $expected_result:expr) => {
        root_op_tests!{
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @mknod fn $test_name ($path) {
                InodeType::CharacterDevice(Permissions::from_mode($mode), libc::makedev($major, $minor))
            } => $expected_result
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl create_file $test_name:ident ($path:expr, $($oflag:ident)|+, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_create_file(&root, $path, $(OpenFlags::$oflag)|*, &Permissions::from_mode($mode), $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl open_subpath $test_name:ident ($path:expr, $($oflag:ident)|+) => $expected_result:expr) => {
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_open_subpath(&root, $path, $(OpenFlags::$oflag)|*, $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl remove_dir $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_remove_dir(&root, $path, $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl remove_file $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_remove_file(&root, $path, $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl remove_all $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_remove_all(&root, $path, $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl rename $test_name:ident ($src_path:expr, $dst_path:expr, $rflags:expr) => $expected_result:expr) => {
        root_op_tests!{
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_rename(&root, $src_path, $dst_path, $rflags, $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl mkdir_all $test_name:ident ($path:expr, $mode:expr) => $expected_result:expr) => {
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            fn $test_name(root) {
                utils::check_root_mkdir_all(&root, $path, Permissions::from_mode($mode), $expected_result)
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl-race mkdir_all_racing [#$num_threads:expr] $test_name:ident ($path:expr, $mode:expr) => $expected_result:expr) => {
        paste::paste! {
            root_op_tests! {
                $(#[cfg_attr(not($ignore_meta), ignore)])*
                fn [<$test_name _ $num_threads threads>](root) {
                    utils::check_root_mkdir_all_racing($num_threads, &root, $path, Permissions::from_mode($mode), $expected_result)
                }
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl-race remove_all_racing [#$num_threads:expr] $test_name:ident ($path:expr) => $expected_result:expr) => {
        paste::paste! {
            root_op_tests! {
                $(#[cfg_attr(not($ignore_meta), ignore)])*
                fn [<$test_name _ $num_threads threads>](root) {
                    utils::check_root_remove_all_racing($num_threads, &root, $path, $expected_result)
                }
            }
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl-race $op_name:ident $test_name:ident ( $($args:tt)* ) => $expected_result:expr) => {
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race $op_name [#2] $test_name( $($args)* ) => $expected_result
        }
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race $op_name [#4] $test_name( $($args)* ) => $expected_result
        }
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race $op_name [#8] $test_name( $($args)* ) => $expected_result
        }
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race $op_name [#16] $test_name( $($args)* ) => $expected_result
        }
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race $op_name [#32] $test_name( $($args)* ) => $expected_result
        }
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race $op_name [#64] $test_name( $($args)* ) => $expected_result
        }
        // This test fails fairly frequently in our GHA CI because the open file
        // limit is quite small. In principle the 64-parallel test should
        // already be more than enough.
        /*
            root_op_tests! {
                $(#[cfg_attr(not($ignore_meta), ignore)])*
                @impl-race $op_name [#128] $test_name( $($args)* ) => $expected_result
            }
        */
    };

    ($(#[cfg($ignore_meta:meta)])* @impl mkdir_all_racing $test_name:ident ( $($args:tt)* ) => $expected_result:expr) => {
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race mkdir_all_racing $test_name( $($args)* ) => $expected_result
        }
    };

    ($(#[cfg($ignore_meta:meta)])* @impl remove_all_racing $test_name:ident ( $($args:tt)* ) => $expected_result:expr) => {
        root_op_tests! {
            $(#[cfg_attr(not($ignore_meta), ignore)])*
            @impl-race remove_all_racing $test_name( $($args)* ) => $expected_result
        }
    };

    // root_tests!{
    //      ...
    // }
    ($($(#[cfg($ignore_meta:meta)])* $test_name:ident: $op_name:ident ( $($args:tt)* ) => $expected_result:expr );+ $(;)?) => {
        paste::paste! {
            $(
                root_op_tests!{
                    $(#[cfg($ignore_meta)])*
                    @impl $op_name [<$op_name _ $test_name>]( $($args)* ) => $expected_result
                }
            )*
        }
    };
}

root_op_tests! {
    plain: mkfile("abc", 0o444) => Ok(("abc", libc::S_IFREG | 0o444));
    exist_file: mkfile("b/c/file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkfile("a", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkfile("b-file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkfile("a-fake1", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: mkfile("b/c//foobar", 0o755) => Ok(("b/c/foobar", libc::S_IFREG | 0o755));
    parentdir_trailing_dot: mkfile("b/c/./foobar", 0o755) => Ok(("b/c/foobar", libc::S_IFREG | 0o755));
    parentdir_trailing_dotdot: mkfile("b/c/../foobar", 0o755) => Ok(("b/foobar", libc::S_IFREG | 0o755));
    trailing_slash: mkfile("foobar/", 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dot: mkfile("foobar/.", 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: mkfile("foobar/..", 0o755) => Err(ErrorKind::InvalidArgument);

    plain: mkdir("abc", 0o311) => Ok(("abc", libc::S_IFDIR | 0o311));
    exist_file: mkdir("b/c/file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkdir("a", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkdir("b-file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkdir("a-fake1", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: mkdir("b/c//foobar", 0o755) => Ok(("b/c/foobar", libc::S_IFDIR | 0o755));
    parentdir_trailing_dot: mkdir("b/c/./foobar", 0o755) => Ok(("b/c/foobar", libc::S_IFDIR | 0o755));
    parentdir_trailing_dotdot: mkdir("b/c/../foobar", 0o755) => Ok(("b/foobar", libc::S_IFDIR | 0o755));
    trailing_slash1: mkdir("b/c/abc/", 0o755) => Ok(("b/c/abc", libc::S_IFDIR | 0o755));
    trailing_slash2: mkdir("b/c/abc///", 0o755) => Ok(("b/c/abc", libc::S_IFDIR | 0o755));
    trailing_dot: mkdir("b/c/abc/.", 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: mkdir("b/c/abc/..", 0o755) => Err(ErrorKind::InvalidArgument);

    plain: symlink("abc", "/NEWLINK") => Ok(("abc", libc::S_IFLNK | 0o777));
    exist_file: symlink("b/c/file", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: symlink("a", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: symlink("b-file", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: symlink("a-fake1", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: symlink("b/c//foobar", "/SOMELINK") => Ok(("b/c/foobar", libc::S_IFLNK | 0o777));
    parentdir_trailing_dot: symlink("b/c/./foobar", "/SOMELINK") => Ok(("b/c/foobar", libc::S_IFLNK | 0o777));
    parentdir_trailing_dotdot: symlink("b/c/../foobar", "/SOMELINK") => Ok(("b/foobar", libc::S_IFLNK | 0o777));
    trailing_slash1: symlink("foobar/", "/SOMELINK") => Err(ErrorKind::InvalidArgument);
    trailing_slash2: symlink("foobar///", "/SOMELINK") => Err(ErrorKind::InvalidArgument);
    trailing_dot: symlink("foobar/.", "/SOMELINK") => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: symlink("foobar/..", "/foobar") => Err(ErrorKind::InvalidArgument);

    plain: hardlink("abc", "b/c/file") => Ok(("abc", libc::S_IFREG | 0o644));
    exist_file: hardlink("b/c/file", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: hardlink("a", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: hardlink("b-file", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: hardlink("a-fake1", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    to_symlink: hardlink("link", "b-file") => Ok(("link", libc::S_IFLNK | 0o777));
    to_dangling_symlink: hardlink("link", "a-fake1") => Ok(("link", libc::S_IFLNK | 0o777));
    to_dir: hardlink("abc", "/b/c") => Err(ErrorKind::OsError(Some(libc::EPERM)));
    parentdir_trailing_slash_dst: hardlink("b/c//foobar", "b/c/file") => Ok(("b/c/foobar", libc::S_IFREG | 0o644));
    parentdir_trailing_slash_src: hardlink("link", "b/c//file") => Ok(("link", libc::S_IFREG | 0o644));
    parentdir_trailing_dot_dst: hardlink("b/c/./foobar", "b/c/file") => Ok(("b/c/foobar", libc::S_IFREG | 0o644));
    parentdir_trailing_dot_src: hardlink("link", "b/c/./file") => Ok(("link", libc::S_IFREG | 0o644));
    parentdir_trailing_dotdot_dst: hardlink("b/c/../foobar", "b/c/file") => Ok(("b/foobar", libc::S_IFREG | 0o644));
    parentdir_trailing_dotdot_src: hardlink("link", "b/c/d/../file") => Ok(("link", libc::S_IFREG | 0o644));
    trailing_slash_dst1: hardlink("foobar/", "b/c/file") => Err(ErrorKind::InvalidArgument);
    trailing_slash_dst2: hardlink("foobar///", "b/c/file") => Err(ErrorKind::InvalidArgument);
    trailing_slash_src1: hardlink("link", "foobar/") => Err(ErrorKind::InvalidArgument);
    trailing_slash_src2: hardlink("link", "foobar///") => Err(ErrorKind::InvalidArgument);
    trailing_dot_dst: hardlink("foobar/.", "b/c/file") => Err(ErrorKind::InvalidArgument);
    trailing_dot_src: hardlink("link", "foobar/.") => Err(ErrorKind::InvalidArgument);
    trailing_dotdot_dst: hardlink("foobar/..", "b/c/file") => Err(ErrorKind::InvalidArgument);
    trailing_dotdot_src: hardlink("link", "foobar/..") => Err(ErrorKind::InvalidArgument);

    plain: mkfifo("abc", 0o222) => Ok(("abc", libc::S_IFIFO | 0o222));
    exist_file: mkfifo("b/c/file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkfifo("a", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkfifo("b-file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkfifo("a-fake1", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: mkfifo("b/c//foobar", 0o123) => Ok(("b/c/foobar", libc::S_IFIFO | 0o123));
    parentdir_trailing_dot: mkfifo("b/c/./foobar", 0o456) => Ok(("b/c/foobar", libc::S_IFIFO | 0o456));
    parentdir_trailing_dotdot: mkfifo("b/c/../foobar", 0o321) => Ok(("b/foobar", libc::S_IFIFO | 0o321));
    trailing_slash1: mkfifo("foobar/", 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_slash2: mkfifo("foobar///", 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dot: mkfifo("foobar/.", 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: mkfifo("foobar/..", 0o755) => Err(ErrorKind::InvalidArgument);

    plain: mkblk("abc", 0o001, 123, 456) => Ok(("abc", libc::S_IFBLK | 0o001));
    exist_file: mkblk("b/c/file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkblk("a", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkblk("b-file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkblk("a-fake1", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: mkblk("b/c//foobar", 0o123, 123, 456) => Ok(("b/c/foobar", libc::S_IFBLK | 0o123));
    parentdir_trailing_dot: mkblk("b/c/./foobar", 0o456, 123, 456) => Ok(("b/c/foobar", libc::S_IFBLK | 0o456));
    parentdir_trailing_dotdot: mkblk("b/c/../foobar", 0o321, 123, 456) => Ok(("b/foobar", libc::S_IFBLK | 0o321));
    trailing_slash1: mkblk("foobar/", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);
    trailing_slash2: mkblk("foobar///", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);
    trailing_dot: mkblk("foobar/.", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: mkblk("foobar/..", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);

    plain: mkchar("abc", 0o010, 111, 222) => Ok(("abc", libc::S_IFCHR | 0o010));
    exist_file: mkchar("b/c/file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkchar("a", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkchar("b-file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkchar("a-fake1", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: mkchar("b/c//foobar", 0o123, 123, 456) => Ok(("b/c/foobar", libc::S_IFCHR | 0o123));
    parentdir_trailing_dot: mkchar("b/c/./foobar", 0o456, 123, 456) => Ok(("b/c/foobar", libc::S_IFCHR | 0o456));
    parentdir_trailing_dotdot: mkchar("b/c/../foobar", 0o321, 123, 456) => Ok(("b/foobar", libc::S_IFCHR | 0o321));
    trailing_slash1: mkchar("foobar/", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);
    trailing_slash2: mkchar("foobar///", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);
    trailing_dot: mkchar("foobar/.", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: mkchar("foobar/..", 0o755, 123, 456) => Err(ErrorKind::InvalidArgument);

    plain: create_file("abc", O_RDONLY, 0o100) => Ok("abc");
    trailing_slash1: create_file("b/c/abc/", O_RDONLY, 0o222) => Err(ErrorKind::InvalidArgument);
    trailing_slash2: create_file("b/c/abc///", O_RDONLY, 0o222) => Err(ErrorKind::InvalidArgument);
    trailing_slash3: create_file("b/c/abc//./", O_RDONLY, 0o222) => Err(ErrorKind::InvalidArgument);
    oexcl_plain: create_file("abc", O_EXCL|O_RDONLY, 0o100) => Ok("abc");
    exist: create_file("b/c/file", O_RDONLY, 0o100) => Ok("b/c/file");
    oexcl_exist: create_file("a", O_EXCL|O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: create_file("b/c/d", O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    symlink: create_file("b-file", O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    oexcl_symlink: create_file("b-file", O_EXCL|O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    oexcl_dangling_symlink: create_file("a-fake1", O_EXCL|O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    parentdir_trailing_slash: create_file("b/c//foobar", O_RDONLY, 0o123) => Ok("b/c/foobar");
    parentdir_trailing_dot: create_file("b/c/./foobar", O_RDONLY, 0o456) => Ok("b/c/foobar");
    parentdir_trailing_dotdot: create_file("b/c/../foobar", O_RDONLY, 0o321) => Ok("b/foobar");
    trailing_slash: create_file("foobar/", O_RDONLY, 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dot: create_file("foobar/.", O_RDONLY, 0o755) => Err(ErrorKind::InvalidArgument);
    trailing_dotdot: create_file("foobar/..", O_RDONLY, 0o755) => Err(ErrorKind::InvalidArgument);

    ocreat: open_subpath("abc", O_CREAT|O_RDONLY) => Err(ErrorKind::InvalidArgument);
    oexcl: open_subpath("abc", O_EXCL|O_RDONLY) => Err(ErrorKind::InvalidArgument);
    ocreat_oexcl: open_subpath("abc", O_CREAT|O_EXCL|O_RDONLY) => Err(ErrorKind::InvalidArgument);
    noexist: open_subpath("abc", O_RDONLY) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    exist_file: open_subpath("b/c/file", O_RDONLY) => Ok("b/c/file");
    exist_file_trailing_slash1: open_subpath("b/c/file/", O_RDONLY) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    exist_file_trailing_slash2: open_subpath("b/c/file///", O_RDONLY) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    exist_file_trailing_slash3: open_subpath("b/c/file//./", O_RDONLY) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    exist_dir: open_subpath("b/c/d", O_RDONLY) => Ok("b/c/d");
    exist_dir_trailing_slash1: open_subpath("b/c/d/", O_RDONLY) => Ok("b/c/d");
    exist_dir_trailing_slash2: open_subpath("b/c/d///", O_RDONLY) => Ok("b/c/d");
    exist_dir_trailing_slash3: open_subpath("b/c/d//./", O_RDONLY) => Ok("b/c/d");
    symlink: open_subpath("b-file", O_RDONLY) => Ok("b/c/file");
    ocreat_symlink: open_subpath("b-file", O_CREAT|O_RDONLY) => Err(ErrorKind::InvalidArgument);
    nofollow_symlink: open_subpath("b-file", O_NOFOLLOW|O_RDONLY) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    opath_nofollow_symlink: open_subpath("b-file", O_PATH|O_NOFOLLOW) => Ok("b-file");
    nofollow_odir_symlink:  open_subpath("b-file", O_DIRECTORY|O_NOFOLLOW) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    opath_nofollow_odir_symlink:  open_subpath("b-file", O_DIRECTORY|O_PATH|O_NOFOLLOW) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_symlink: open_subpath("a-fake1",O_RDONLY) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    ocreat_dangling_symlink: open_subpath("a-fake1", O_CREAT|O_RDONLY) => Err(ErrorKind::InvalidArgument);

    empty_dir: remove_dir("a") => Ok(());
    empty_dir: remove_file("a") => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    empty_dir: remove_all("a") => Ok(());
    nonempty_dir: remove_dir("b") => Err(ErrorKind::OsError(Some(libc::ENOTEMPTY)));
    nonempty_dir: remove_file("b") => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    nonempty_dir: remove_all("b") => Ok(());
    deep_dir: remove_dir("deep-rmdir") => Err(ErrorKind::OsError(Some(libc::ENOTEMPTY)));
    deep_dir: remove_file("deep-rmdir") => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    deep_dir: remove_all("deep-rmdir") => Ok(());
    file: remove_dir("b/c/file") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file: remove_file("b/c/file") => Ok(());
    file: remove_all("b/c/file") => Ok(());
    fifo: remove_dir("b/fifo") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    fifo: remove_file("b/fifo") => Ok(());
    fifo: remove_all("b/fifo") => Ok(());
    sock: remove_dir("b/sock") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    sock: remove_file("b/sock") => Ok(());
    sock: remove_all("b/sock") => Ok(());
    noexist: remove_dir("abc") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    noexist: remove_file("abc") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    noexist: remove_all("abc") => Ok(());
    noexist_trailing_slash: remove_dir("abc/") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    noexist_trailing_slash: remove_file("abc/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    noexist_trailing_slash: remove_all("abc/") => Ok(());
    symlink: remove_dir("b-file") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    symlink: remove_file("b-file") => Ok(());
    symlink: remove_all("b-file") => Ok(());
    dangling_symlink: remove_dir("a-fake1") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_symlink: remove_file("a-fake1") => Ok(());
    dangling_symlink: remove_all("a-fake1") => Ok(());
    parentdir_trailing_slash1: remove_dir("b/c/d/e//f") => Ok(());
    parentdir_trailing_slash1: remove_file("b/c//file") => Ok(());
    parentdir_trailing_slash1: remove_all("b//c") => Ok(());
    parentdir_trailing_slash2: remove_dir("b/c/d/e////f") => Ok(());
    parentdir_trailing_slash2: remove_file("b/c////file") => Ok(());
    parentdir_trailing_slash2: remove_all("b////c") => Ok(());
    parentdir_trailing_dot: remove_dir("b/c/d/e/./f") => Ok(());
    parentdir_trailing_dot: remove_file("b/c/./file") => Ok(());
    parentdir_trailing_dot: remove_all("b/./c") => Ok(());
    parentdir_trailing_dotdot: remove_dir("b/c/d/e/f/../f") => Ok(());
    parentdir_trailing_dotdot: remove_file("b/c/d/../file") => Ok(());
    parentdir_trailing_dotdot: remove_all("b/c/../c") => Ok(());
    dir_trailing_slash1: remove_dir("a/") => Ok(());
    dir_trailing_slash1: remove_file("a/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dir_trailing_slash1: remove_all("a/") => Ok(());
    dir_trailing_slash2: remove_dir("a///") => Ok(());
    dir_trailing_slash2: remove_file("a///") =>  Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dir_trailing_slash2: remove_all("a///") => Ok(());
    dir_trailing_dot: remove_dir("a/.") => Err(ErrorKind::InvalidArgument);
    dir_trailing_dot: remove_file("a/.") => Err(ErrorKind::InvalidArgument);
    dir_trailing_dot: remove_all("a/.") => Err(ErrorKind::InvalidArgument);
    dir_trailing_dotdot: remove_dir("b/c/..") => Err(ErrorKind::InvalidArgument);
    dir_trailing_dotdot: remove_file("b/c/..") => Err(ErrorKind::InvalidArgument);
    dir_trailing_dotdot: remove_all("b/c/..") => Err(ErrorKind::InvalidArgument);
    file_trailing_slash: remove_dir("b/c/file/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file_trailing_slash: remove_file("b/c/file/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file_trailing_slash: remove_all("b/c/file/") => Ok(());
    file_trailing_dot: remove_dir("b/c/file/.") => Err(ErrorKind::InvalidArgument);
    file_trailing_dot: remove_file("b/c/file/.") => Err(ErrorKind::InvalidArgument);
    file_trailing_dot: remove_all("b/c/file/.") => Err(ErrorKind::InvalidArgument);
    file_trailing_dotdot: remove_dir("b/c/file/..") => Err(ErrorKind::InvalidArgument);
    file_trailing_dotdot: remove_file("b/c/file/..") => Err(ErrorKind::InvalidArgument);
    file_trailing_dotdot: remove_all("b/c/file/..") => Err(ErrorKind::InvalidArgument);

    empty_dir: rename("a", "aa", RenameFlags::empty()) => Ok(());
    nonempty_dir: rename("b", "bb", RenameFlags::empty()) => Ok(());
    file: rename("b/c/file", "bb-file", RenameFlags::empty()) => Ok(());
    parentdir_trailing_slash_src1: rename("b/c//d", "aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_slash_dst1: rename("a", "b//aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_slash_src2: rename("b/c////d", "aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_slash_dst2: rename("a", "b////aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_dot_src: rename("b/c/./file", "aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_dot_dst: rename("a", "b/./aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_dotdot_src: rename("b/c/d/../file", "aa", RenameFlags::empty()) => Ok(());
    parentdir_trailing_dotdot_dst: rename("a", "b/c/../aa", RenameFlags::empty()) => Ok(());
    dir_trailing_slash_src1: rename("a/", "aa", RenameFlags::empty()) => Ok(());
    dir_trailing_slash_dst1: rename("a", "aa/", RenameFlags::empty()) => Ok(());
    dir_trailing_slash_src2: rename("a///", "aa", RenameFlags::empty()) => Ok(());
    dir_trailing_slash_dst2: rename("a", "aa///", RenameFlags::empty()) => Ok(());
    dir_trailing_dot_src: rename("a/.", "aa", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    dir_trailing_dot_dst: rename("a", "aa/.", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    dir_trailing_dotdot_src: rename("b/c/..", "aa", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    dir_trailing_dotdot_dst: rename("a", "aa/..", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    file_trailing_slash_src1: rename("b/c/file/", "aa", RenameFlags::empty()) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file_trailing_slash_dst1: rename("b/c/file", "aa/", RenameFlags::empty()) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file_trailing_slash_src2: rename("b/c/file///", "aa", RenameFlags::empty()) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file_trailing_slash_dst2: rename("b/c/file", "aa///", RenameFlags::empty()) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file_trailing_dot_src: rename("b/c/file/.", "aa", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    file_trailing_dot_dst: rename("b/c/file", "aa/.", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    file_trailing_dotdot_src: rename("b/c/file/..", "aa", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    file_trailing_dotdot_dst: rename("b/c/file", "aa/..", RenameFlags::empty()) => Err(ErrorKind::InvalidArgument);
    noreplace_plain: rename("a", "aa", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_dir_trailing_slash_from: rename("a/", "aa", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_dir_trailing_slash_to: rename("a", "aa/", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_dir_trailing_slash_fromto: rename("a/", "aa/", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_dir_trailing_slash_many: rename("a///", "aa///", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_symlink: rename("a", "b-file", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    noreplace_dangling_symlink: rename("a", "a-fake1", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    noreplace_eexist: rename("a", "e", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    whiteout_dir: rename("a", "aa", RenameFlags::RENAME_WHITEOUT) => Ok(());
    whiteout_file: rename("b/c/file", "b/c/newfile", RenameFlags::RENAME_WHITEOUT) => Ok(());
    exchange_dir: rename("a", "b", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_dir_trailing_slash_from: rename("a/", "b", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_dir_trailing_slash_to: rename("a", "b/", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_dir_trailing_slash_fromto: rename("a/", "b/", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_dir_trailing_slash_many: rename("a///", "b///", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_difftype: rename("a", "e", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_difftype_trailing_slash_from: rename("a/", "e", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_difftype_trailing_slash_to: rename("a", "e/", RenameFlags::RENAME_EXCHANGE) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    exchange_difftype_trailing_slash_fromto: rename("a/", "e/", RenameFlags::RENAME_EXCHANGE) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    exchange_noexist: rename("a", "aa", RenameFlags::RENAME_EXCHANGE) => Err(ErrorKind::OsError(Some(libc::ENOENT)));

    invalid_mode_type: mkdir_all("foo", libc::S_IFDIR | 0o777) => Err(ErrorKind::InvalidArgument);
    invalid_mode_garbage: mkdir_all("foo", 0o12340777) => Err(ErrorKind::InvalidArgument);
    invalid_mode_setuid: mkdir_all("foo", libc::S_ISUID | 0o777) => Err(ErrorKind::InvalidArgument);
    invalid_mode_setgid: mkdir_all("foo", libc::S_ISGID | 0o777) => Err(ErrorKind::InvalidArgument);
    existing: mkdir_all("a", 0o711) => Ok(());
    basic: mkdir_all("a/b/c/d/e/f/g/h/i/j", 0o711) => Ok(());
    trailing_slash_basic: mkdir_all("a/b/c/d/e/f/g/", 0o711) => Ok(());
    trailing_slash_many: mkdir_all("a/b/c/d/e/f/g/////////", 0o711) => Ok(());
    trailing_slash_complex: mkdir_all("a/b/c/d/e/f/g////./////", 0o711) => Ok(());
    sticky: mkdir_all("foo", libc::S_ISVTX | 0o711) => Ok(());
    dotdot_in_nonexisting: mkdir_all("a/b/c/d/e/f/g/h/i/j/k/../lmnop", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dotdot_in_existing: mkdir_all("b/c/../c/./d/e/f/g/h", 0o711) => Ok(());
    dotdot_after_symlink: mkdir_all("e/../dd/ee/ff", 0o711) => Ok(());
    // Check that trying to create under a file fails.
    nondir_trailing: mkdir_all("b/c/file", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    nondir_dotdot: mkdir_all("b/c/file/../d", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    nondir_subdir: mkdir_all("b/c/file/subdir", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    nondir_symlink_trailing: mkdir_all("b-file", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    nondir_symlink_dotdot: mkdir_all("b-file/../d", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    nondir_symlink_subdir: mkdir_all("b-file/subdir", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    // Dangling symlinks are not followed.
    dangling1_trailing: mkdir_all("a-fake1", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling1_basic: mkdir_all("a-fake1/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling1_dotdot: mkdir_all("a-fake1/../bar/baz", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dangling2_trailing: mkdir_all("a-fake2", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling2_basic: mkdir_all("a-fake2/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling2_dotdot: mkdir_all("a-fake2/../bar/baz", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dangling3_trailing: mkdir_all("a-fake3", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling3_basic: mkdir_all("a-fake3/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling3_dotdot: mkdir_all("a-fake3/../bar/baz", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    // Non-lexical symlinks should work.
    nonlexical_basic: mkdir_all("target/foo", 0o711) => Ok(());
    nonlexical_level1_abs: mkdir_all("link1/target_abs/foo", 0o711) => Ok(());
    nonlexical_level1_rel: mkdir_all("link1/target_rel/foo", 0o711) => Ok(());
    nonlexical_level2_abs_abs: mkdir_all("link2/link1_abs/target_abs/foo", 0o711) => Ok(());
    nonlexical_level2_abs_rel: mkdir_all("link2/link1_abs/target_rel/foo", 0o711) => Ok(());
    nonlexical_level2_abs_open: mkdir_all("link2/link1_abs/../target/foo", 0o711) => Ok(());
    nonlexical_level2_rel_abs: mkdir_all("link2/link1_rel/target_abs/foo", 0o711) => Ok(());
    nonlexical_level2_rel_rel: mkdir_all("link2/link1_rel/target_rel/foo", 0o711) => Ok(());
    nonlexical_level2_rel_open: mkdir_all("link2/link1_rel/../target/foo", 0o711) => Ok(());
    nonlexical_level3_abs: mkdir_all("link3/target_abs/foo", 0o711) => Ok(());
    nonlexical_level3_rel: mkdir_all("link3/target_rel/foo", 0o711) => Ok(());
    // But really tricky dangling symlinks should fail.
    dangling_tricky1_trailing: mkdir_all("link3/deep_dangling1", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_tricky1_basic: mkdir_all("link3/deep_dangling1/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_tricky1_dotdot: mkdir_all("link3/deep_dangling1/../bar", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dangling_tricky2_trailing: mkdir_all("link3/deep_dangling2", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_tricky2_basic: mkdir_all("link3/deep_dangling2/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_tricky2_dotdot: mkdir_all("link3/deep_dangling2/../bar", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    // And trying to mkdir inside a loop should fail.
    loop_trailing: mkdir_all("loop/link", 0o711) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    loop_basic: mkdir_all("loop/link/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    loop_dotdot: mkdir_all("loop/link/../foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    // Make sure the S_ISGID handling is correct.
    setgid_selfdir: mkdir_all("setgid-self/a/b/c/d", 0o711) => Ok(());
    #[cfg(feature = "_test_as_root")]
    setgid_otherdir: mkdir_all("setgid-other/a/b/c/d", 0o711) => Ok(());
    parentdir_trailing_slash: mkdir_all("b/c//foobar", 0o711) => Ok(());
    parentdir_trailing_dot: mkdir_all("b/c/./foobar", 0o711) => Ok(());
    parentdir_trailing_dotdot: mkdir_all("b/c/../foobar", 0o711) => Ok(());
    trailing_slash: mkdir_all("foobar/", 0o755) => Ok(());
    trailing_dot: mkdir_all("foobar/.", 0o755) => Ok(());
    trailing_dotdot: mkdir_all("foobar/..", 0o755) => Err(ErrorKind::OsError(Some(libc::ENOENT)));

    // Check that multiple mkdir_alls racing against each other will not result
    // in a spurious error. <https://github.com/opencontainers/runc/issues/4543>
    plain: mkdir_all_racing("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z", 0o711) => Ok(());

    // Check that multiple rmdir_alls racing against each other will not result
    // in a spurious error.
    plain: remove_all_racing("deep-rmdir") => Ok(());
}

mod utils {
    use crate::{
        error::{ErrorExt, ErrorKind},
        flags::{OpenFlags, RenameFlags},
        resolvers::PartialLookup,
        syscalls,
        tests::{
            common as tests_common,
            traits::{ErrorImpl, RootImpl},
        },
        utils::{self, FdExt, PathIterExt},
        Handle, InodeType,
    };

    use std::{
        fs::Permissions,
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            io::{AsFd, OwnedFd},
        },
        path::{Path, PathBuf},
        sync::{Arc, Barrier},
        thread,
    };

    use anyhow::{Context, Error};
    use pretty_assertions::{assert_eq, assert_ne};
    use rustix::{
        fs::{Mode, RawMode},
        process as rustix_process,
    };

    fn root_roundtrip<R: RootImpl>(root: R) -> Result<R::Cloned, Error> {
        let root_clone = root.try_clone()?;
        assert_eq!(
            root.resolver(),
            root_clone.resolver(),
            "cloned root should have the same resolver settings"
        );
        let root_fd: OwnedFd = root_clone.into();

        Ok(R::from_fd(root_fd, root.resolver()))
    }

    pub(super) fn check_root_create<R: RootImpl>(
        root: R,
        path: impl AsRef<Path>,
        inode_type: InodeType,
        expected_result: Result<(&str, RawMode), ErrorKind>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        // Just clear the umask so all of the tests can use all of the
        // permission bits.
        let _ = rustix_process::umask(Mode::empty());

        // Update the expected path to have the rootdir as a prefix.
        let root_dir = root.as_fd().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|(path, mode)| (root_dir.join(path), mode));

        match root.create(path, &inode_type) {
            Err(err) => {
                tests_common::check_err(&Err::<(), _>(err), &expected_result)
                    .with_context(|| format!("root create {path:?}"))?;
            }
            Ok(_) => {
                let root = root_roundtrip(root)?;
                let created = root.resolve_nofollow(path)?;
                let meta = created.metadata()?;

                let actual_path = created.as_fd().as_unsafe_path_unchecked()?;
                let actual_mode = meta.mode();
                assert_eq!(
                    Ok((actual_path.clone(), actual_mode)),
                    expected_result,
                    "unexpected mode 0o{actual_mode:o} or path {actual_path:?}",
                );

                match inode_type {
                    // No need for extra checks for these types.
                    InodeType::File(_) | InodeType::Directory(_) | InodeType::Fifo(_) => (),
                    // Check
                    InodeType::CharacterDevice(_, dev) | InodeType::BlockDevice(_, dev) => {
                        assert_eq!(meta.rdev(), dev, "device type of mknod mismatch");
                    }
                    // Check hardlink is the same inode.
                    InodeType::Hardlink(target) => {
                        let target_meta = root.resolve_nofollow(target)?.as_fd().metadata()?;
                        assert_eq!(
                            meta.ino(),
                            target_meta.ino(),
                            "inode number of hard link doesn't match"
                        );
                    }
                    // Check symlink is correct.
                    InodeType::Symlink(target) => {
                        // Check using the a resolved handle.
                        let actual_target = syscalls::readlinkat(&created, "")?;
                        assert_eq!(
                            target, actual_target,
                            "readlinkat(handle) link target mismatch"
                        );
                        // Double-check with Root::readlink.
                        let actual_target = root.readlink(path)?;
                        assert_eq!(
                            target, actual_target,
                            "root.readlink(path) link target mismatch"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn check_root_create_file<R: RootImpl>(
        root: R,
        path: impl AsRef<Path>,
        oflags: OpenFlags,
        perm: &Permissions,
        expected_result: Result<&str, ErrorKind>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        // Just clear the umask so all of the tests can use all of the
        // permission bits.
        let _ = rustix_process::umask(Mode::empty());

        // Get a handle to the original path if it existed beforehand.
        let pre_create_handle = root.resolve_nofollow(path); // do not unwrap

        // Update the expected path to have the rootdir as a prefix.
        let root_dir = root.as_fd().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|path| root_dir.join(path));

        match root.create_file(path, oflags, perm) {
            Err(err) => {
                tests_common::check_err(&Err::<(), _>(err), &expected_result)
                    .with_context(|| format!("root create file {path:?}"))?;
            }
            Ok(file) => {
                let actual_path = file.as_fd().as_unsafe_path_unchecked()?;
                assert_eq!(
                    Ok(actual_path.clone()),
                    expected_result,
                    "create file had unexpected path {actual_path:?}",
                );

                let root = root_roundtrip(root)?;
                let new_lookup = root
                    .resolve_nofollow(path)
                    .wrap("re-open created file using original path")?;

                assert_eq!(
                    new_lookup.as_fd().as_unsafe_path_unchecked()?,
                    file.as_fd().as_unsafe_path_unchecked()?,
                    "expected real path of {path:?} handles to be the same",
                );

                let expect_mode = if let Ok(handle) = pre_create_handle {
                    handle.as_fd().metadata()?.mode()
                } else {
                    libc::S_IFREG | perm.mode()
                };

                let orig_meta = file.as_fd().metadata()?;
                assert_eq!(
                    orig_meta.mode(),
                    expect_mode,
                    "create file had unexpected mode 0o{:o}",
                    orig_meta.mode(),
                );

                let new_meta = new_lookup.as_fd().metadata()?;
                assert_eq!(
                    orig_meta.ino(),
                    new_meta.ino(),
                    "expected ino of {path:?} handles to be the same",
                );

                // Note that create_file is always implemented as a two-step
                // process (open the parent, create the file) with O_NOFOLLOW
                // always being applied to the created handle (to avoid races).
                tests_common::check_oflags(&file, oflags | OpenFlags::O_NOFOLLOW)?;
            }
        }
        Ok(())
    }

    pub(super) fn check_root_open_subpath<R: RootImpl>(
        root: R,
        path: impl AsRef<Path>,
        oflags: OpenFlags,
        expected_result: Result<&str, ErrorKind>,
    ) -> Result<(), Error> {
        let path = path.as_ref();

        // Update the expected path to have the rootdir as a prefix.
        let root_dir = root.as_fd().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|path| root_dir.join(path));

        match root.open_subpath(path, oflags) {
            Err(err) => {
                tests_common::check_err(&Err::<(), _>(err), &expected_result)
                    .with_context(|| format!("root open subpath {path:?}"))?;
            }
            Ok(file) => {
                let actual_path = file.as_fd().as_unsafe_path_unchecked()?;
                assert_eq!(
                    Ok(actual_path.clone()),
                    expected_result,
                    "create file had unexpected path {actual_path:?}",
                );

                let root = root_roundtrip(root)?;
                let new_lookup = if oflags.contains(OpenFlags::O_NOFOLLOW) {
                    root.resolve_nofollow(path)
                } else {
                    root.resolve(path)
                }
                .wrap("re-open created file using original path")?;

                assert_eq!(
                    new_lookup.as_fd().as_unsafe_path_unchecked()?,
                    file.as_fd().as_unsafe_path_unchecked()?,
                    "expected real path of {path:?} handles to be the same",
                );

                tests_common::check_oflags(&file, oflags)?;
            }
        }
        Ok(())
    }

    fn check_root_remove<R: RootImpl, F>(
        root: R,
        path: &Path,
        remove_fn: F,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error>
    where
        F: FnOnce(&R, &Path) -> Result<(), R::Error>,
    {
        // Get a handle before we remove the path, to make sure the actual inode
        // was unlinked.
        let handle = root.resolve_nofollow(path); // do not unwrap

        let res = remove_fn(&root, path);
        tests_common::check_err(&res, &expected_result)
            .with_context(|| format!("root remove {path:?}"))?;

        if res.is_ok() {
            // It's possible that the path didn't exist for remove_all, but if
            // it did check that it was unlinked.
            if let Ok(handle) = handle {
                let meta = handle.as_fd().metadata()?;
                assert_eq!(meta.nlink(), 0, "deleted file should have a 0 nlink");
            }

            let root = root_roundtrip(root)?;
            let new_lookup = root.resolve_nofollow(path);
            assert_eq!(
                new_lookup.as_ref().map_err(R::Error::kind).err(),
                Some(ErrorKind::OsError(Some(libc::ENOENT))),
                "path should not exist after deletion, got {new_lookup:?}"
            );
        }
        Ok(())
    }

    pub(super) fn check_root_remove_dir<R: RootImpl>(
        root: R,
        path: impl AsRef<Path>,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        check_root_remove(
            root,
            path.as_ref(),
            |root, path| root.remove_dir(path),
            expected_result,
        )
    }

    pub(super) fn check_root_remove_file<R: RootImpl>(
        root: R,
        path: impl AsRef<Path>,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        check_root_remove(
            root,
            path.as_ref(),
            |root, path| root.remove_file(path),
            expected_result,
        )
    }

    pub(super) fn check_root_remove_all<R: RootImpl>(
        root: R,
        path: impl AsRef<Path>,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        check_root_remove(
            root,
            path.as_ref(),
            |root, path| root.remove_all(path),
            expected_result,
        )
    }

    pub(super) fn check_root_rename<R: RootImpl>(
        root: R,
        src_path: impl AsRef<Path>,
        dst_path: impl AsRef<Path>,
        rflags: RenameFlags,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let src_path = src_path.as_ref();
        let dst_path = dst_path.as_ref();

        // Strip any slashes since we have tests where the paths being operated
        // on are not directories but have trailing slashes.
        let (stripped_src_path, _) = utils::path_strip_trailing_slash(src_path);
        let (stripped_dst_path, _) = utils::path_strip_trailing_slash(dst_path);

        // Get a handle before we move the paths, to make sure the right inodes
        // were moved. However, we *do not unwrap these here* since the paths
        // might not exist (it is valid for dst to not exist, but for some
        // failure tests we want src to not exist too).
        let src_handle = root.resolve_nofollow(stripped_src_path); // do not unwrap this here!
        let dst_handle = root.resolve_nofollow(stripped_dst_path); // do not unwrap this here!

        // Keep track of the original paths, pre-rename.
        let src_real_path = if let Ok(ref handle) = src_handle {
            Some(handle.as_fd().as_unsafe_path_unchecked()?)
        } else {
            None
        };
        let dst_real_path = if let Ok(ref handle) = dst_handle {
            Some(handle.as_fd().as_unsafe_path_unchecked()?)
        } else {
            None
        };

        let res = root.rename(src_path, dst_path, rflags);
        tests_common::check_err(&res, &expected_result)
            .with_context(|| format!("root rename {src_path:?} -> {dst_path:?} {rflags:?}"))?;

        if res.is_ok() {
            // If the operation succeeded we can expect the source to have
            // existed.
            let src_handle = src_handle.expect("rename source should have existed before rename");
            let src_real_path = src_real_path.unwrap();

            // Confirm that the handle was moved.
            let moved_src_real_path = src_handle.as_fd().as_unsafe_path_unchecked()?;
            assert_ne!(
                src_real_path, moved_src_real_path,
                "expected real path of handle to move after rename"
            );

            match rflags.intersection(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
                RenameFlags::RENAME_EXCHANGE => {
                    let dst_handle =
                        dst_handle.expect("destination should have existed for RENAME_EXCHANGE");
                    let dst_real_path = dst_real_path.unwrap();

                    // Confirm that the moved path matches the original
                    // destination.
                    assert_eq!(
                        dst_real_path, moved_src_real_path,
                        "expected real path of handle to match destination with RENAME_EXCHANGE"
                    );

                    // Confirm that the destination was also moved.
                    let moved_dst_real_path = dst_handle.as_fd().as_unsafe_path_unchecked()?;
                    assert_eq!(
                        src_real_path, moved_dst_real_path,
                        "expected real path of destination to move to source with RENAME_EXCHANGE"
                    );
                }
                RenameFlags::RENAME_WHITEOUT => {
                    // Verify that there is a whiteout entry where the source
                    // used to be.
                    let new_lookup = root
                        .resolve_nofollow(src_path)
                        .wrap("expected source to exist with RENAME_WHITEOUT")?;

                    let meta = new_lookup.as_fd().metadata()?;
                    assert_eq!(
                        syscalls::devmajorminor(meta.rdev()),
                        (0, 0),
                        "whiteout should have 0:0 rdev"
                    );
                    assert_eq!(
                        meta.mode() & libc::S_IFMT,
                        libc::S_IFCHR,
                        "whiteout should be char device, not 0o{:0}",
                        meta.mode()
                    )
                }
                _ => {}
            }
        } else if let Ok(src_handle) = src_handle {
            let src_real_path = src_real_path.unwrap();

            // Confirm the handle was not moved.
            let nonmoved_src_real_path = src_handle.as_fd().as_unsafe_path_unchecked()?;
            assert_eq!(
                src_real_path, nonmoved_src_real_path,
                "expected real path of handle to not change after failed rename"
            );
        }
        Ok(())
    }

    pub(super) fn check_root_mkdir_all<R: RootImpl>(
        root: R,
        unsafe_path: impl AsRef<Path>,
        perm: Permissions,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let root = &root;
        let unsafe_path = unsafe_path.as_ref();

        // Before trying to create the directory tree, figure out what
        // components don't exist yet so we can check them later.
        let before_partial_lookup = root.resolver().resolve_partial(root, unsafe_path, false)?;

        let expected_subdir_state: Option<((_, _), _)> = match expected_result {
            Err(_) => None,
            Ok(_) => {
                let expected_uid = syscalls::geteuid();
                let mut expected_gid = syscalls::getegid();
                // Assume the umask is 0o022. Writing code to verify the umask
                // is a little annoying just for the purposes of a test, so
                // let's just stick with the default for now.
                let mut expected_mode = libc::S_IFDIR | (perm.mode() & !0o022);

                let handle: &Handle = before_partial_lookup.as_ref();
                let dir_meta = handle.metadata()?;
                if dir_meta.mode() & libc::S_ISGID == libc::S_ISGID {
                    expected_gid = dir_meta.gid();
                    expected_mode |= libc::S_ISGID;
                }
                Some(((expected_uid, expected_gid), expected_mode))
            }
        };

        let res = root
            .mkdir_all(unsafe_path, &perm)
            .with_wrap(|| format!("mkdir_all {unsafe_path:?}"));
        tests_common::check_err(&res, &expected_result)?;

        if let PartialLookup::Partial {
            handle,
            remaining,
            last_error: _,
        } = before_partial_lookup
        {
            let mut subpaths = remaining
                .raw_components()
                .filter(|part| !part.is_empty())
                .fold(vec![PathBuf::from(".")], |mut subpaths, part| {
                    subpaths.push(
                        subpaths
                            .iter()
                            .last()
                            .expect("must have at least one entry")
                            .join(part),
                    );
                    subpaths
                })
                .into_iter();

            // Skip the first "." component.
            let _ = subpaths.next();

            // Verify that the remaining paths match the mode we expect (either
            // they don't exist or it matches the mode we requested).
            for subpath in subpaths {
                let got = syscalls::fstatat(&handle, &subpath)
                    .map(|st| ((st.st_uid, st.st_gid), st.st_mode))
                    .ok();
                match expected_subdir_state {
                    // We expect there to be a directory with the exact mode.
                    Some(want) => {
                        assert_eq!(
                            got, Some(want),
                            "unexpected owner + file mode for newly-created directory {subpath:?} for mkdir_all({unsafe_path:?})"
                        );
                    }
                    // Make sure there isn't directory (even errors are fine!).
                    None => {
                        assert_ne!(
                            got.map(|((_, _), mode)| mode & libc::S_IFMT),
                            Some(libc::S_IFDIR),
                            "unexpected directory {subpath:?} for mkdir_all({unsafe_path:?}) that failed"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub(super) fn check_root_mkdir_all_racing<R: RootImpl + Sync>(
        num_threads: usize,
        root: R,
        unsafe_path: impl AsRef<Path>,
        perm: Permissions,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let root = &root;
        let unsafe_path = unsafe_path.as_ref();

        // Do lots of runs to try to catch any possible races.
        let num_retries = 100 + 1_000 / (1 + (num_threads >> 5));
        for _ in 0..num_retries {
            thread::scope(|s| {
                let start_barrier = Arc::new(Barrier::new(num_threads));
                for _ in 0..num_threads {
                    let barrier = Arc::clone(&start_barrier);
                    let perm = perm.clone();
                    s.spawn(move || {
                        barrier.wait();
                        let res = root
                            .mkdir_all(unsafe_path, &perm)
                            .with_wrap(|| format!("mkdir_all {unsafe_path:?}"));
                        tests_common::check_err(&res, &expected_result).expect("unexpected result");
                    });
                }
            });
        }
        Ok(())
    }

    pub(super) fn check_root_remove_all_racing<R: RootImpl + Sync>(
        num_threads: usize,
        root: R,
        unsafe_path: impl AsRef<Path>,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let root = &root;
        let unsafe_path = unsafe_path.as_ref();

        // Do lots of runs to try to catch any possible races.
        let num_retries = 100 + 1_000 / (1 + (num_threads >> 5));
        for _ in 0..num_retries {
            thread::scope(|s| {
                let start_barrier = Arc::new(Barrier::new(num_threads));
                for _ in 0..num_threads {
                    let barrier = Arc::clone(&start_barrier);
                    s.spawn(move || {
                        barrier.wait();
                        let res = root
                            .remove_all(unsafe_path)
                            .with_wrap(|| format!("remove_all {unsafe_path:?}"));
                        tests_common::check_err(&res, &expected_result).expect("unexpected result");
                    });
                }
            });
        }
        Ok(())
    }
}

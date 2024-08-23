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
    error::ErrorKind,
    flags::{OpenFlags, RenameFlags},
    tests::common as tests_common,
    InodeType, ResolverBackend, Root,
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
            fn [<root_ $test_name _openat2>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let mut $root_var = Root::open(&root_dir)?;
                $root_var.resolver.backend = ResolverBackend::KernelOpenat2;

                $body
            }

            $(#[$meta])*
            #[test]
            fn [<root_ $test_name _opath>]() -> Result<(), Error> {
                let root_dir = tests_common::create_basic_tree()?;
                let mut $root_var = Root::open(&root_dir)?;
                $root_var.resolver.backend = ResolverBackend::EmulatedOpath;

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

    (@impl mkfile $test_name:ident ($path:expr, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            @mknod fn $test_name ($path) {
                InodeType::File(Permissions::from_mode($mode))
            } => $expected_result
        }
    };
    (@impl mkdir $test_name:ident ($path:expr, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            @mknod fn $test_name ($path) {
                InodeType::Directory(Permissions::from_mode($mode))
            } => $expected_result
        }
    };
    (@impl symlink $test_name:ident ($path:expr, $target:expr) => $expected_result:expr) => {
        root_op_tests!{
            @mknod fn $test_name ($path) {
                InodeType::Symlink($target.into())
            } => $expected_result
        }
    };
    (@impl hardlink $test_name:ident ($path:expr, $target:expr) => $expected_result:expr) => {
        root_op_tests!{
            @mknod fn $test_name ($path) {
                InodeType::Hardlink($target.into())
            } => $expected_result
        }
    };
    (@impl mkfifo $test_name:ident ($path:expr, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            @mknod fn $test_name ($path) {
                InodeType::Fifo(Permissions::from_mode($mode))
            } => $expected_result
        }
    };
    (@impl mkblk $test_name:ident ($path:expr, $mode:literal, $major:literal, $minor:literal) => $expected_result:expr) => {
        root_op_tests!{
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            @mknod fn $test_name ($path) {
                InodeType::BlockDevice(Permissions::from_mode($mode), libc::makedev($major, $minor))
            } => $expected_result
        }
    };
    (@impl mkchar $test_name:ident ($path:expr, $mode:literal, $major:literal, $minor:literal) => $expected_result:expr) => {
        root_op_tests!{
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            @mknod fn $test_name ($path) {
                InodeType::CharacterDevice(Permissions::from_mode($mode), libc::makedev($major, $minor))
            } => $expected_result
        }
    };

    (@impl create_file $test_name:ident ($path:expr, $($oflag:ident)|+, $mode:literal) => $expected_result:expr) => {
        root_op_tests!{
            fn $test_name(root) {
                utils::check_root_create_file(&root, $path, $(OpenFlags::$oflag)|*, &Permissions::from_mode($mode), $expected_result)
            }
        }
    };

    (@impl remove_dir $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            fn $test_name(root) {
                utils::check_root_remove_dir(&root, $path, $expected_result)
            }
        }
    };

    (@impl remove_file $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            fn $test_name(root) {
                utils::check_root_remove_file(&root, $path, $expected_result)
            }
        }
    };

    (@impl remove_all $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            fn $test_name(root) {
                utils::check_root_remove_all(&root, $path, $expected_result)
            }
        }
    };

    (@impl rename $test_name:ident ($src_path:expr, $dst_path:expr, $rflags:expr) => $expected_result:expr) => {
        root_op_tests!{
            fn $test_name(root) {
                utils::check_root_rename(&root, $src_path, $dst_path, $rflags, $expected_result)
            }
        }
    };

    (@impl mkdir_all $test_name:ident ($path:expr, $mode:expr) => $expected_result:expr) => {
        root_op_tests! {
            fn $test_name(root) {
                utils::check_root_mkdir_all(&root, $path, Permissions::from_mode($mode), $expected_result)
            }
        }
    };

    // root_tests!{
    //      ...
    // }
    ($($test_name:ident: $file_type:ident ( $($args:expr),* ) => $expected_result:expr );+ $(;)?) => {
        paste::paste! {
            $(
                root_op_tests!{ @impl $file_type [<$file_type _ $test_name>]( $($args),* ) => $expected_result }
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

    plain: mkdir("abc", 0o311) => Ok(("abc", libc::S_IFDIR | 0o311));
    exist_file: mkdir("b/c/file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkdir("a", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkdir("b-file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkdir("a-fake1", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));

    plain: symlink("abc", "/NEWLINK") => Ok(("abc", libc::S_IFLNK | 0o777));
    exist_file: symlink("b/c/file", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: symlink("a", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: symlink("b-file", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: symlink("a-fake1", "/NEWLINK") => Err(ErrorKind::OsError(Some(libc::EEXIST)));

    plain: hardlink("abc", "b/c/file") => Ok(("abc", libc::S_IFREG | 0o644));
    exist_file: hardlink("b/c/file", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: hardlink("a", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: hardlink("b-file", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: hardlink("a-fake1", "/b/c/file") => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    to_symlink: hardlink("link", "b-file") => Ok(("link", libc::S_IFLNK | 0o777));
    to_dangling_symlink: hardlink("link", "a-fake1") => Ok(("link", libc::S_IFLNK | 0o777));

    plain: mkfifo("abc", 0o222) => Ok(("abc", libc::S_IFIFO | 0o222));
    exist_file: mkfifo("b/c/file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkfifo("a", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkfifo("b-file", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkfifo("a-fake1", 0o444) => Err(ErrorKind::OsError(Some(libc::EEXIST)));

    plain: mkblk("abc", 0o001, 123, 456) => Ok(("abc", libc::S_IFBLK | 0o001));
    exist_file: mkblk("b/c/file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkblk("a", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkblk("b-file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkblk("a-fake1", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));

    plain: mkchar("abc", 0o010, 111, 222) => Ok(("abc", libc::S_IFCHR | 0o010));
    exist_file: mkchar("b/c/file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: mkchar("a", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_symlink: mkchar("b-file", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dangling_symlink: mkchar("a-fake1", 0o444, 123, 456) => Err(ErrorKind::OsError(Some(libc::EEXIST)));

    plain: create_file("abc", O_RDONLY, 0o100) => Ok("abc");
    oexcl_plain: create_file("abc", O_EXCL|O_RDONLY, 0o100) => Ok("abc");
    exist: create_file("b/c/file", O_RDONLY, 0o100) => Ok("b/c/file");
    oexcl_exist: create_file("a", O_EXCL|O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    exist_dir: create_file("b/c/d", O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    symlink: create_file("b-file", O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    oexcl_symlink: create_file("b-file", O_EXCL|O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    oexcl_dangling_symlink: create_file("a-fake1", O_EXCL|O_RDONLY, 0o100) => Err(ErrorKind::OsError(Some(libc::EEXIST)));

    empty_dir: remove_dir("a") => Ok(());
    empty_dir: remove_file("a") => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    empty_dir: remove_all("a") => Ok(());
    nonempty_dir: remove_dir("b") => Err(ErrorKind::OsError(Some(libc::ENOTEMPTY)));
    nonempty_dir: remove_file("b") => Err(ErrorKind::OsError(Some(libc::EISDIR)));
    nonempty_dir: remove_all("b") => Ok(());
    file: remove_dir("b/c/file") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    file: remove_file("b/c/file") => Ok(());
    file: remove_all("b/c/file") => Ok(());
    fifo: remove_dir("b/fifo") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    fifo: remove_file("b/fifo") => Ok(());
    fifo: remove_all("b/fifo") => Ok(());
    sock: remove_dir("b/sock") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    sock: remove_file("b/sock") => Ok(());
    sock: remove_all("b/sock") => Ok(());
    enoent: remove_dir("abc") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    enoent: remove_file("abc") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    enoent: remove_all("abc") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    symlink: remove_dir("b-file") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    symlink: remove_file("b-file") => Ok(());
    symlink: remove_all("b-file") => Ok(());
    dangling_symlink: remove_dir("a-fake1") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    dangling_symlink: remove_file("a-fake1") => Ok(());
    dangling_symlink: remove_all("a-fake1") => Ok(());
    dir_trailing_slash: remove_dir("a/") => Err(ErrorKind::InvalidArgument);
    dir_trailing_slash: remove_file("a/") => Err(ErrorKind::InvalidArgument);
    dir_trailing_slash: remove_all("a/") => Err(ErrorKind::InvalidArgument);
    file_trailing_slash: remove_dir("b/c/file/") => Err(ErrorKind::InvalidArgument);
    file_trailing_slash: remove_file("b/c/file/") => Err(ErrorKind::InvalidArgument);
    file_trailing_slash: remove_all("b/c/file/") => Err(ErrorKind::InvalidArgument);

    plain: rename("a", "aa", RenameFlags::empty()) => Ok(());
    noreplace_plain: rename("a", "aa", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_symlink: rename("a", "b-file", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    noreplace_dangling_symlink: rename("a", "a-fake1", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    noreplace_eexist: rename("a", "e", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    whiteout_plain: rename("a", "aa", RenameFlags::RENAME_WHITEOUT) => Ok(());
    exchange_plain: rename("a", "e", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_enoent: rename("a", "aa", RenameFlags::RENAME_EXCHANGE) => Err(ErrorKind::OsError(Some(libc::ENOENT)));

    invalid_mode: mkdir_all("foo", libc::S_IFDIR | 0o777) => Err(ErrorKind::InvalidArgument);
    existing: mkdir_all("a", 0o711) => Ok(());
    basic: mkdir_all("a/b/c/d/e/f/g/h/i/j", 0o711) => Ok(());
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
    dangling1_trailing: mkdir_all("a-fake1", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling1_basic: mkdir_all("a-fake1/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling1_dotdot: mkdir_all("a-fake1/../bar/baz", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dangling2_trailing: mkdir_all("a-fake2", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling2_basic: mkdir_all("a-fake2/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling2_dotdot: mkdir_all("a-fake2/../bar/baz", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dangling3_trailing: mkdir_all("a-fake3", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling3_basic: mkdir_all("a-fake3/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
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
    dangling_tricky1_trailing: mkdir_all("link3/deep_dangling1", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling_tricky1_basic: mkdir_all("link3/deep_dangling1/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling_tricky1_dotdot: mkdir_all("link3/deep_dangling1/../bar", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    dangling_tricky2_trailing: mkdir_all("link3/deep_dangling2", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling_tricky2_basic: mkdir_all("link3/deep_dangling2/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    dangling_tricky2_dotdot: mkdir_all("link3/deep_dangling2/../bar", 0o711) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    // And trying to mkdir inside a loop should fail.
    loop_trailing: mkdir_all("loop/link", 0o711) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    loop_basic: mkdir_all("loop/link/foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    loop_dotdot: mkdir_all("loop/link/../foo", 0o711) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
}

mod utils {
    use crate::{
        error::{Error as PathrsError, ErrorExt, ErrorKind},
        flags::{OpenFlags, RenameFlags},
        procfs::PROCFS_HANDLE,
        resolvers::PartialLookup,
        syscalls,
        utils::{self, FdExt, PathIterExt},
        InodeType, Root,
    };

    use std::{
        fs::Permissions,
        os::unix::{
            fs::PermissionsExt,
            io::{AsFd, OwnedFd},
        },
        path::{Path, PathBuf},
    };

    use anyhow::Error;
    use libc::mode_t;
    use pretty_assertions::{assert_eq, assert_ne};

    fn root_roundtrip(root: &Root) -> Result<Root, Error> {
        let root_clone = root.try_clone()?;
        assert_eq!(
            root.resolver, root_clone.resolver,
            "cloned root should have the same resolver settings"
        );
        let root_fd: OwnedFd = root_clone.into();

        let mut new_root = Root::from_fd_unchecked(root_fd);
        new_root.resolver = root.resolver;
        Ok(new_root)
    }

    pub(super) fn check_root_create<P: AsRef<Path>>(
        root: &Root,
        path: P,
        inode_type: InodeType,
        expected_result: Result<(&str, mode_t), ErrorKind>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        // Just clear the umask so all of the tests can use all of the
        // permission bits.
        let _ = unsafe { libc::umask(0) };

        // Update the expected path to have the rootdir as a prefix.
        let root_dir = root.as_fd().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|(path, mode)| (root_dir.join(path), mode));

        match root.create(path, &inode_type) {
            Err(err) => assert_eq!(Err(err.kind()), expected_result, "unexpected error {err:?}",),
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

    pub(super) fn check_root_create_file<P: AsRef<Path>>(
        root: &Root,
        path: P,
        oflags: OpenFlags,
        perm: &Permissions,
        expected_result: Result<&str, ErrorKind>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        // Just clear the umask so all of the tests can use all of the
        // permission bits.
        let _ = unsafe { libc::umask(0) };

        // Get a handle to the original path if it existed beforehand.
        let pre_create_handle = root.resolve_nofollow(path); // do not unwrap

        // Update the expected path to have the rootdir as a prefix.
        let root_dir = root.as_fd().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|path| root_dir.join(path));

        match root.create_file(path, oflags, perm) {
            Err(err) => assert_eq!(Err(err.kind()), expected_result, "unexpected err {err:?}"),
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

                // TODO: Check open flags.
            }
        }
        Ok(())
    }

    fn check_root_remove<F>(
        root: &Root,
        path: &Path,
        remove_fn: F,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error>
    where
        F: FnOnce(&Root, &Path) -> Result<(), PathrsError>,
    {
        // Get a handle before we remove the path, to make sure the actual inode
        // was unlinked.
        let handle = root.resolve_nofollow(path); // do not unwrap

        let res = remove_fn(root, path);
        assert_eq!(
            res.as_ref().err().map(PathrsError::kind),
            expected_result.err(),
            "unexpected result {res:?}"
        );

        if res.is_ok() {
            let handle = handle.wrap("open handle before remoev")?;

            let meta = handle.as_fd().metadata()?;
            assert_eq!(meta.nlink(), 0, "deleted file should have a 0 nlink");

            let root = root_roundtrip(root)?;
            let new_lookup = root.resolve_nofollow(path);
            assert_eq!(
                new_lookup.as_ref().map_err(PathrsError::kind).err(),
                Some(ErrorKind::OsError(Some(libc::ENOENT))),
                "path should not exist after deletion, got {new_lookup:?}"
            );
        }
        Ok(())
    }

    pub(super) fn check_root_remove_dir<P: AsRef<Path>>(
        root: &Root,
        path: P,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        check_root_remove(
            root,
            path.as_ref(),
            |root, path| root.remove_dir(path),
            expected_result,
        )
    }

    pub(super) fn check_root_remove_file<P: AsRef<Path>>(
        root: &Root,
        path: P,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        check_root_remove(
            root,
            path.as_ref(),
            |root, path| root.remove_file(path),
            expected_result,
        )
    }

    pub(super) fn check_root_remove_all<P: AsRef<Path>>(
        root: &Root,
        path: P,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        check_root_remove(
            root,
            path.as_ref(),
            |root, path| root.remove_all(path),
            expected_result,
        )
    }

    pub(super) fn check_root_rename<P1: AsRef<Path>, P2: AsRef<Path>>(
        root: &Root,
        src_path: P1,
        dst_path: P2,
        rflags: RenameFlags,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let src_path = src_path.as_ref();
        let dst_path = dst_path.as_ref();

        // Get a handle before we move the paths, to make sure the right inodes
        // were moved.
        let src_handle = root.resolve_nofollow(src_path)?;
        let dst_handle = root.resolve_nofollow(dst_path); // do not unwrap this here!

        // Keep track of the original paths, pre-rename.
        let src_real_path = src_handle.as_fd().as_unsafe_path_unchecked()?;
        let dst_real_path = if let Ok(ref handle) = dst_handle {
            Some(handle.as_fd().as_unsafe_path_unchecked()?)
        } else {
            None
        };

        let res = root.rename(src_path, dst_path, rflags);
        assert_eq!(
            res.as_ref().err().map(PathrsError::kind),
            expected_result.err(),
            "unexpected result {res:?}"
        );

        if res.is_ok() {
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
                    // Verify that there is a whiteout entry where the soure
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
        } else {
            // Confirm the handle was not moved.
            let nonmoved_src_real_path = src_handle.as_fd().as_unsafe_path_unchecked()?;
            assert_eq!(
                src_real_path, nonmoved_src_real_path,
                "expected real path of handle to not change after failed rename"
            );
        }
        Ok(())
    }

    pub(super) fn check_root_mkdir_all<P: AsRef<Path>>(
        root: &Root,
        unsafe_path: P,
        perm: Permissions,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let unsafe_path = unsafe_path.as_ref();

        // Before trying to create the directory tree, figure out what
        // components don't exist yet so we can check them later.
        let before_partial_lookup = root.resolver.resolve_partial(root, unsafe_path, false)?;

        let expected_mode = match expected_result {
            Ok(_) => Some(libc::S_IFDIR | (perm.mode() & !utils::get_umask(Some(&PROCFS_HANDLE))?)),
            Err(_) => None,
        };

        let res = root
            .mkdir_all(unsafe_path, &perm)
            .with_wrap(|| format!("mkdir_all {unsafe_path:?}"));
        assert_eq!(
            res.as_ref().err().map(PathrsError::kind),
            expected_result.err(),
            "unexpected result {:?}",
            res.map_err(|err| err.to_string())
        );

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
                let got_mode = syscalls::fstatat(&handle, &subpath)
                    .map(|st| st.st_mode)
                    .ok();
                match expected_mode {
                    // We expect there to be a directory with the exact mode.
                    Some(mode) => {
                        assert_eq!(
                            got_mode, Some(mode),
                            "unexpected file mode for newly-created directory {subpath:?} for mkdir_all({unsafe_path:?})"
                        );
                    }
                    // Make sure there isn't directory (even errors are fine!).
                    None => {
                        assert_ne!(
                            got_mode,
                            Some(libc::S_IFDIR),
                            "unexpected directory {subpath:?} for mkdir_all({unsafe_path:?}) that failed"
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

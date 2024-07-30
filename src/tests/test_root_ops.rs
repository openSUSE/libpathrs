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

    (@impl remove $test_name:ident ($path:expr) => $expected_result:expr) => {
        root_op_tests!{
            fn $test_name(root) {
                utils::check_root_remove(&root, $path, $expected_result)
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

    plain: remove("a") => Ok(());
    enoent: remove("abc") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
    symlink: remove("b-file") => Ok(());
    dangling_symlink: remove("a-fake1") => Ok(());

    plain: rename("a", "aa", RenameFlags::empty()) => Ok(());
    noreplace_plain: rename("a", "aa", RenameFlags::RENAME_NOREPLACE) => Ok(());
    noreplace_symlink: rename("a", "b-file", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    noreplace_dangling_symlink: rename("a", "a-fake1", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    noreplace_eexist: rename("a", "e", RenameFlags::RENAME_NOREPLACE) => Err(ErrorKind::OsError(Some(libc::EEXIST)));
    whiteout_plain: rename("a", "aa", RenameFlags::RENAME_WHITEOUT) => Ok(());
    exchange_plain: rename("a", "e", RenameFlags::RENAME_EXCHANGE) => Ok(());
    exchange_enoent: rename("a", "aa", RenameFlags::RENAME_EXCHANGE) => Err(ErrorKind::OsError(Some(libc::ENOENT)));
}

mod utils {
    use crate::{
        error::{Error as PathrsError, ErrorExt, ErrorKind},
        flags::{OpenFlags, RenameFlags},
        syscalls,
        utils::RawFdExt,
        InodeType, Root,
    };

    use std::{
        fs::Permissions,
        os::fd::AsRawFd,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
    };

    use anyhow::Error;
    use libc::mode_t;

    fn root_roundtrip(root: &Root) -> Result<Root, Error> {
        let root_clone = root.try_clone()?;
        assert_eq!(
            root.resolver, root_clone.resolver,
            "cloned root should have the same resolver settings"
        );

        let mut new_root = Root::from_file_unchecked(root_clone.into_file());
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
        let root_dir = root.as_file().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|(path, mode)| (root_dir.join(path), mode));

        match root.create(path, &inode_type) {
            Err(err) => assert_eq!(Err(err.kind()), expected_result, "unexpected error {err:?}",),
            Ok(_) => {
                let root = root_roundtrip(root)?;
                let created = root.resolve_nofollow(path)?;
                let meta = created.as_file().metadata()?;

                let actual_path = created.as_file().as_unsafe_path_unchecked()?;
                let actual_mode = meta.permissions().mode();
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
                        let target_meta = root.resolve_nofollow(target)?.as_file().metadata()?;
                        assert_eq!(
                            meta.ino(),
                            target_meta.ino(),
                            "inode number of hard link doesn't match"
                        );
                    }
                    // Check symlink is correct.
                    InodeType::Symlink(target) => {
                        let actual_target =
                            syscalls::readlinkat(created.as_file().as_raw_fd(), "")?;
                        assert_eq!(
                            target, actual_target,
                            "readlinkat(handle) link target mismatch"
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
        let root_dir = root.as_file().as_unsafe_path_unchecked()?;
        let expected_result = expected_result.map(|path| root_dir.join(path));

        match root.create_file(path, oflags, perm) {
            Err(err) => assert_eq!(Err(err.kind()), expected_result, "unexpected err {err:?}"),
            Ok(file) => {
                let actual_path = file.as_file().as_unsafe_path_unchecked()?;
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
                    new_lookup.as_file().as_unsafe_path_unchecked()?,
                    file.as_file().as_unsafe_path_unchecked()?,
                    "expected real path of {path:?} handles to be the same",
                );

                let expect_mode = if let Ok(handle) = pre_create_handle {
                    handle.as_file().metadata()?.mode()
                } else {
                    libc::S_IFREG | perm.mode()
                };

                let orig_meta = file.as_file().metadata()?;
                assert_eq!(
                    orig_meta.mode(),
                    expect_mode,
                    "create file had unexpected mode 0o{:o}",
                    orig_meta.mode(),
                );

                let new_meta = new_lookup.as_file().metadata()?;
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

    pub(super) fn check_root_remove<P: AsRef<Path>>(
        root: &Root,
        path: P,
        expected_result: Result<(), ErrorKind>,
    ) -> Result<(), Error> {
        let path = path.as_ref();

        // Get a handle before we remove the path, to make sure the actual inode
        // was unlinked.
        let handle = root.resolve_nofollow(path); // do not unwrap

        let res = root.remove(path);
        assert_eq!(
            res.as_ref().err().map(PathrsError::kind),
            expected_result.err(),
            "unexpected result {res:?}"
        );

        if res.is_ok() {
            let handle = handle.wrap("open handle before remoev")?;

            let meta = handle.as_file().metadata()?;
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
        let src_real_path = src_handle.as_file().as_unsafe_path_unchecked()?;
        let dst_real_path = if let Ok(ref handle) = dst_handle {
            Some(handle.as_file().as_unsafe_path_unchecked()?)
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
            let moved_src_real_path = src_handle.as_file().as_unsafe_path_unchecked()?;
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
                    let moved_dst_real_path = dst_handle.as_file().as_unsafe_path_unchecked()?;
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

                    let meta = new_lookup.as_file().metadata()?;
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
            let nonmoved_src_real_path = src_handle.as_file().as_unsafe_path_unchecked()?;
            assert_eq!(
                src_real_path, nonmoved_src_real_path,
                "expected real path of handle to not change after failed rename"
            );
        }
        Ok(())
    }
}

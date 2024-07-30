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
    procfs::{ProcfsBase, ProcfsHandle},
    resolvers::procfs::ProcfsResolver,
    syscalls::{self, OpenTreeFlags},
    OpenFlags,
};
use utils::ExpectedResult;

use anyhow::Error;

macro_rules! procfs_tests {
    // Create the actual test functions.
    (@fn [<$func_prefix:ident $test_name:ident>] $procfs_var:ident = { $procfs_inst:expr } <- $do_test:expr => (over_mounts: $over_mounts:expr, error: $expect_error:expr) ;) => {
        paste::paste! {
            #[test]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<$func_prefix $test_name>]() -> Result<(), Error> {
                utils::in_mnt_ns_with_overmounts($over_mounts, ExpectedResult::$expect_error, || {
                    let $procfs_var = { $procfs_inst } ?;
                    $do_test
                })
            }

            #[test]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<$func_prefix openat2_ $test_name>]() -> Result<(), Error> {
                if !*syscalls::OPENAT2_IS_SUPPORTED {
                    // skip this test
                    return Ok(());
                }
                utils::in_mnt_ns_with_overmounts($over_mounts, ExpectedResult::$expect_error, || {
                    let mut $procfs_var = { $procfs_inst } ?;
                    // Force openat2 resolver.
                    $procfs_var.resolver = ProcfsResolver::Openat2;
                    $do_test
                })
            }

            #[test]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<$func_prefix opath_ $test_name>]() -> Result<(), Error> {
                utils::in_mnt_ns_with_overmounts($over_mounts, ExpectedResult::$expect_error, || {
                    let mut $procfs_var = { $procfs_inst } ?;
                    // Force opath resolver.
                    $procfs_var.resolver = ProcfsResolver::RestrictedOpath;
                    $do_test
                })
            }
        }
    };

    // Create a test for each ProcfsHandle::new_* method.
    (@impl $test_name:ident $procfs_var:ident <- $do_test:expr => ($($tt:tt)*) ;) => {
        procfs_tests! {
            @fn [<procfs_overmounts_new_ $test_name>]
                $procfs_var = { ProcfsHandle::new() } <- $do_test => (over_mounts: false, $($tt)*);
        }

        procfs_tests! {
            @fn [<procfs_overmounts_new_fsopen_ $test_name>]
                $procfs_var = { ProcfsHandle::new_fsopen() } <- $do_test => (over_mounts: false, $($tt)*);
        }

        procfs_tests! {
            @fn [<procfs_overmounts_new_open_tree_ $test_name>]
                $procfs_var = {
                    ProcfsHandle::new_open_tree(OpenTreeFlags::OPEN_TREE_CLONE)
                } <- $do_test => (over_mounts: false, $($tt)*);
        }

        procfs_tests! {
            @fn [<procfs_overmounts_new_open_tree_recursive_ $test_name>]
                $procfs_var = {
                    ProcfsHandle::new_open_tree(OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::AT_RECURSIVE)
                } <- $do_test => (over_mounts: true, $($tt)*);
        }

        procfs_tests! {
            @fn [<procfs_overmounts_new_unsafe_open $test_name>]
                $procfs_var = { ProcfsHandle::new_unsafe_open() } <- $do_test => (over_mounts: true, $($tt)*);
        }
    };

    // procfs_tests! { abc: readlink("foo") => (error: ExpectedResult::Some(ErrorKind::OsError(Some(libc::ENOENT)))) }
    ($test_name:ident : readlink ( $path:expr ) => ($($tt:tt)*)) => {
        paste::paste! {
            procfs_tests! {
                @impl [<self_readlink_ $test_name>]
                    procfs <- procfs.readlink(ProcfsBase::ProcSelf, $path) => ($($tt)*);
            }
            procfs_tests! {
                @impl [<threadself_readlink_ $test_name>]
                    procfs <- procfs.readlink(ProcfsBase::ProcThreadSelf, $path) => ($($tt)*);
            }
        }
    };

    // procfs_tests! { xyz: open("self/fd", O_DIRECTORY) => (error: None) }
    ($test_name:ident : open ( $path:expr, $($flag:ident)|* ) => ($($tt:tt)*)) => {
        paste::paste! {
            procfs_tests! {
                @impl [<self_open_ $test_name>]
                    procfs <- procfs.open(ProcfsBase::ProcSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
            procfs_tests! {
                @impl [<threadself_open_ $test_name>]
                    procfs <- procfs.open(ProcfsBase::ProcThreadSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
        }
    };

    // procfs_tests! { def: open_follow("self/exe", O_DIRECTORY | O_PATH) => (error: ErrorKind::OsError(Some(libc::ENOTDIR) }
    ($test_name:ident : open_follow ( $path:expr, $($flag:ident)|* ) => ($($tt:tt)*)) => {
        paste::paste! {
            procfs_tests! {
                @impl [<self_open_follow_ $test_name>]
                    procfs <- procfs.open_follow(ProcfsBase::ProcSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
            procfs_tests! {
                @impl [<threadself_open_follow_ $test_name>]
                    procfs <- procfs.open_follow(ProcfsBase::ProcThreadSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
        }
    };

    ($($test_name:ident : $func:ident ($($args:tt)*) => ($($res:tt)*) );* $(;)?) => {
        paste::paste! {
            $(
                procfs_tests!{$test_name : $func ( $($args)* ) => ($($res)*) }
            )*
        }
    }
}

procfs_tests! {
    // Non-procfs overmount.
    tmpfs_dir: open("fdinfo", O_DIRECTORY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    tmpfs_dir: open_follow("fdinfo", O_DIRECTORY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    // No overmounts.
    nomount: open("attr/current", O_RDONLY) => (error: Ok);
    nomount: open_follow("attr/current", O_RDONLY) => (error: Ok);
    // Procfs regular file overmount.
    proc_file_wr: open("attr/exec", O_WRONLY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    proc_file_wr: open_follow("attr/exec", O_WRONLY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    proc_file_rd: open("mountinfo", O_RDONLY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    proc_file_rd: open_follow("mountinfo", O_RDONLY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    // Magic-links with no overmount.
    magiclink_nomount: open("cwd", O_PATH) => (error: Ok);
    magiclink_nomount: open_follow("cwd", O_RDONLY) => (error: Ok);
    magiclink_nomount: readlink("cwd") => (error: Ok);
    magiclink_nomount_fd1: readlink("fd/1") => (error: Ok);
    magiclink_nomount_fd2: readlink("fd/2") => (error: Ok);
    // Magic-links with overmount.
    magiclink_exe: open("exe", O_PATH) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    magiclink_exe: open_follow("exe", O_RDONLY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    magiclink_exe: readlink("exe") => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    magiclink_fd0: open("fd/0", O_PATH) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    magiclink_fd0: open_follow("fd/0", O_RDONLY) => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    magiclink_fd0: readlink("fd/0") => (error: ErrOvermount(ErrorKind::OsError(Some(libc::EXDEV))));
    // Behaviour-related testing.
    proc_cwd_trailing_slash: open_follow("cwd/", O_RDONLY) => (error: Ok);
    proc_fdlink_trailing_slash: open_follow("fd//1/", O_RDONLY) => (error: Err(ErrorKind::OsError(Some(libc::ENOTDIR))));
    // TODO: root can always open procfs files with O_RDWR even if writes fail.
    // proc_nowrite: open("status", O_RDWR) => (error: Err(ErrorKind::OsError(Some(libc::EACCES))));
    proc_dotdot_escape: open_follow("../..", O_PATH) => (error: Err(ErrorKind::OsError(Some(libc::EXDEV))));
    // TODO: openat2(RESOLVE_BENEATH) seems to handle "fd/../.." incorrectly (-EAGAIN), and "fd/.." is allowed.
    // proc_dotdot_escape: open_follow("fd/../..", O_PATH) => (error: Err(ErrorKind::OsError(Some(libc::EXDEV))));
    // proc_dotdot: open_follow("fd/..", O_PATH) => (error: Err(ErrorKind::OsError(Some(libc::EXDEV))));
    proc_magic_component: open("root/etc/passwd", O_RDONLY) => (error: Err(ErrorKind::OsError(Some(libc::ELOOP))));
    proc_magic_component: open_follow("root/etc/passwd", O_RDONLY) => (error: Err(ErrorKind::OsError(Some(libc::ELOOP))));
    proc_magic_component: readlink("root/etc/passwd") => (error: Err(ErrorKind::OsError(Some(libc::ELOOP))));
    proc_sym_onofollow: open("fd/1", O_RDONLY) => (error: Err(ErrorKind::OsError(Some(libc::ELOOP))));
    proc_sym_opath_onofollow: open("fd/1", O_PATH) => (error: Ok);
    proc_sym_odir_opath_onofollow: open("fd/1", O_DIRECTORY|O_PATH) => (error: Err(ErrorKind::OsError(Some(libc::ENOTDIR))));
    proc_dir_odir_opath_onofollow: open("fd", O_DIRECTORY|O_PATH) => (error: Ok);
}

mod utils {
    use std::{fmt::Debug, path::PathBuf};

    use crate::{
        error::{Error as PathrsError, ErrorKind},
        tests::common::{self as tests_common, MountType},
    };

    use anyhow::Error;

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub(super) enum ExpectedResult {
        Ok,
        Err(ErrorKind),
        ErrOvermount(ErrorKind),
    }

    fn check_proc_error<T: Debug>(
        res: Result<T, PathrsError>,
        over_mounts: bool,
        expected: ExpectedResult,
    ) {
        let want_error = match expected {
            ExpectedResult::Ok => None,
            ExpectedResult::Err(kind) => Some(kind),
            ExpectedResult::ErrOvermount(kind) => {
                if over_mounts {
                    Some(kind)
                } else {
                    None
                }
            }
        };
        assert_eq!(
            res.as_ref().err().map(PathrsError::kind),
            want_error,
            "unexpected result for overmounts={} got {:?} (expected error {:?})",
            over_mounts,
            res,
            expected
        );
    }

    pub(super) fn in_mnt_ns_with_overmounts<T, F>(
        are_over_mounts_visible: bool,
        expected: ExpectedResult,
        func: F,
    ) -> Result<(), Error>
    where
        T: Debug,
        F: FnOnce() -> Result<T, PathrsError>,
    {
        tests_common::in_mnt_ns(|| {
            // Add some overmounts to /proc/self and /proc/thread-self.
            for prefix in ["/proc/self", "/proc/thread-self"] {
                let prefix = PathBuf::from(prefix);

                // A tmpfs on top of /proc/.../fdinfo.
                tests_common::mount(prefix.join("fdinfo"), MountType::Tmpfs)?;
                // A bind-mount of a real procfs file that ignores all writes.
                tests_common::mount(
                    prefix.join("attr/exec"),
                    MountType::Bind {
                        src: "/proc/1/sched".into(),
                    },
                )?;
                // A bind-mount of a real procfs file that can have custom data.
                tests_common::mount(
                    prefix.join("mountinfo"),
                    MountType::Bind {
                        src: "/proc/1/environ".into(),
                    },
                )?;
                // Magic-link overmounts.
                tests_common::mount(
                    prefix.join("exe"),
                    MountType::Bind {
                        src: "/proc/1/fd/0".into(),
                    },
                )?;
                tests_common::mount(
                    prefix.join("fd/0"),
                    MountType::Bind {
                        src: "/proc/1/exe".into(),
                    },
                )?;
                // TODO: Add some tests for mounts on top of /proc/self.
            }

            let res = func();
            check_proc_error(res, are_over_mounts_visible, expected);
            Ok(())
        })
    }
}

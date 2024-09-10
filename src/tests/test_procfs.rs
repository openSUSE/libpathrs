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
use crate::tests::capi::CapiProcfsHandle;
use crate::{
    error::ErrorKind,
    flags::OpenFlags,
    procfs::{ProcfsBase, ProcfsHandle},
    resolvers::procfs::ProcfsResolver,
    syscalls::{self, OpenTreeFlags},
};
use utils::ExpectedResult;

use anyhow::Error;

macro_rules! procfs_tests {
    // Create the actual test functions.
    (@rust-fn [<$func_prefix:ident $test_name:ident>] $procfs_inst:block . $procfs_op:ident ($($args:expr),*) => (over_mounts: $over_mounts:expr, error: $expect_error:expr) ;) => {
        paste::paste! {
            #[test]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<procfs_overmounts_ $func_prefix $test_name>]() -> Result<(), Error> {
                utils::[<check_proc_ $procfs_op>](
                    || $procfs_inst,
                    $($args,)*
                    $over_mounts,
                    ExpectedResult::$expect_error,
                )
            }

            #[test]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<procfs_overmounts_ $func_prefix openat2_ $test_name>]() -> Result<(), Error> {
                if !*syscalls::OPENAT2_IS_SUPPORTED {
                    // skip this test
                    return Ok(());
                }
                utils::[<check_proc_ $procfs_op>](
                    || {
                        let mut proc = $procfs_inst ?;
                        // Force openat2 resolver.
                        proc.resolver = ProcfsResolver::Openat2;
                        Ok(proc)
                    },
                    $($args,)*
                    $over_mounts,
                    ExpectedResult::$expect_error,
                )
            }

            #[test]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<procfs_overmounts_ $func_prefix opath_ $test_name>]() -> Result<(), Error> {
                utils::[<check_proc_ $procfs_op>](
                    || {
                        let mut proc = $procfs_inst ?;
                        // Force opath resolver.
                        proc.resolver = ProcfsResolver::RestrictedOpath;
                        Ok(proc)
                    },
                    $($args,)*
                    $over_mounts,
                    ExpectedResult::$expect_error,
                )
            }
        }
    };

    // Create the actual test function for the C API.
    (@capi-fn [<$func_prefix:ident $test_name:ident>] $procfs_inst:block . $procfs_op:ident ($($args:expr),*) => (over_mounts: $over_mounts:expr, error: $expect_error:expr) ;) => {
        paste::paste! {
            #[test]
            #[cfg(feature = "capi")]
            #[cfg_attr(not(feature = "_test_as_root"), ignore)]
            fn [<procfs_overmounts_ $func_prefix $test_name>]() -> Result<(), Error> {
                utils::[<check_proc_ $procfs_op>](
                    || $procfs_inst,
                    $($args,)*
                    $over_mounts,
                    ExpectedResult::$expect_error,
                )
            }
        }
    };

    // Create a test for each ProcfsHandle::new_* method.
    (@impl $test_name:ident $procfs_var:ident . $procfs_op:ident ($($args:tt)*) => ($($tt:tt)*) ;) => {
        procfs_tests! {
            @rust-fn [<new_ $test_name>]
                { ProcfsHandle::new() }.$procfs_op($($args)*) => (over_mounts: false, $($tt)*);
        }

        procfs_tests! {
            @rust-fn [<new_fsopen_ $test_name>]
                { ProcfsHandle::new_fsopen() }.$procfs_op($($args)*) => (over_mounts: false, $($tt)*);
        }

        procfs_tests! {
            @rust-fn [<new_open_tree_ $test_name>]
                {
                    ProcfsHandle::new_open_tree(OpenTreeFlags::OPEN_TREE_CLONE)
                }.$procfs_op($($args)*) => (over_mounts: false, $($tt)*);
        }

        procfs_tests! {
            @rust-fn [<new_open_tree_recursive_ $test_name>]
                {
                    ProcfsHandle::new_open_tree(OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::AT_RECURSIVE)
                }.$procfs_op($($args)*) => (over_mounts: true, $($tt)*);
        }

        procfs_tests! {
            @rust-fn [<new_unsafe_open_ $test_name>]
                { ProcfsHandle::new_unsafe_open() }.$procfs_op($($args)*) => (over_mounts: true, $($tt)*);
        }

        // Assume that PROCFS_HANDLE is fsopen(2)-based.
        //
        // TODO: Figure out the fd type of PROCFS_HANDLE. In principle we would
        // expect to be able to do fsopen(2) (otherwise the fsopen(2) tests will
        // fail) but it would be nice to avoid possible spurrious errors.
        procfs_tests! {
            @capi-fn [<capi_ $test_name>]
                { Ok(CapiProcfsHandle) }.$procfs_op($($args)*) => (over_mounts: false, $($tt)*);
        }
    };

    // procfs_tests! { abc: readlink("foo") => (error: ExpectedResult::Some(ErrorKind::OsError(Some(libc::ENOENT)))) }
    ($test_name:ident : readlink ( $path:expr ) => ($($tt:tt)*)) => {
        paste::paste! {
            procfs_tests! {
                @impl [<self_readlink_ $test_name>]
                    procfs.readlink(ProcfsBase::ProcSelf, $path) => ($($tt)*);
            }
            procfs_tests! {
                @impl [<threadself_readlink_ $test_name>]
                    procfs.readlink(ProcfsBase::ProcThreadSelf, $path) => ($($tt)*);
            }
        }
    };

    // procfs_tests! { xyz: open("self/fd", O_DIRECTORY) => (error: None) }
    ($test_name:ident : open ( $path:expr, $($flag:ident)|* ) => ($($tt:tt)*)) => {
        paste::paste! {
            procfs_tests! {
                @impl [<self_open_ $test_name>]
                    procfs.open(ProcfsBase::ProcSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
            procfs_tests! {
                @impl [<threadself_open_ $test_name>]
                    procfs.open(ProcfsBase::ProcThreadSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
        }
    };

    // procfs_tests! { def: open_follow("self/exe", O_DIRECTORY | O_PATH) => (error: ErrorKind::OsError(Some(libc::ENOTDIR) }
    ($test_name:ident : open_follow ( $path:expr, $($flag:ident)|* ) => ($($tt:tt)*)) => {
        paste::paste! {
            procfs_tests! {
                @impl [<self_open_follow_ $test_name>]
                    procfs.open_follow(ProcfsBase::ProcSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
            }
            procfs_tests! {
                @impl [<threadself_open_follow_ $test_name>]
                    procfs.open_follow(ProcfsBase::ProcThreadSelf, $path, $(OpenFlags::$flag)|*) => ($($tt)*);
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
    // TODO: openat2(RESOLVE_BENEATH) does not block all ".." components unlike
    //       our custom resolver, so "fd/.." has different results based on the
    //       resolver.
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
    use std::{
        fmt::Debug,
        path::{Path, PathBuf},
    };

    use crate::{
        error::ErrorKind,
        flags::OpenFlags,
        procfs::ProcfsBase,
        tests::{
            common::{self as tests_common, MountType},
            traits::{ErrorImpl, ProcfsHandleImpl},
        },
    };

    use anyhow::Error;

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub(super) enum ExpectedResult {
        Ok,
        Err(ErrorKind),
        ErrOvermount(ErrorKind),
    }

    fn check_proc_error<T: Debug, E: ErrorImpl>(
        res: Result<T, E>,
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
            res.as_ref().err().map(E::kind),
            want_error,
            "unexpected result for overmounts={} got {:?} (expected error {:?})",
            over_mounts,
            res,
            expected
        );
    }

    fn in_mnt_ns_with_overmounts<T, E, F>(
        are_over_mounts_visible: bool,
        expected: ExpectedResult,
        func: F,
    ) -> Result<(), Error>
    where
        T: Debug,
        E: ErrorImpl,
        F: FnOnce() -> Result<T, E>,
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

    pub(super) fn check_proc_open<Proc, ProcFn, P: AsRef<Path>, F: Into<OpenFlags>>(
        proc_fn: ProcFn,
        base: ProcfsBase,
        path: P,
        oflags: F,
        are_over_mounts_visible: bool,
        expected: ExpectedResult,
    ) -> Result<(), Error>
    where
        Proc: ProcfsHandleImpl,
        ProcFn: FnOnce() -> Result<Proc, Proc::Error>,
    {
        in_mnt_ns_with_overmounts(are_over_mounts_visible, expected, || {
            proc_fn()?.open(base, path, oflags)
        })
    }

    pub(super) fn check_proc_open_follow<Proc, ProcFn, P: AsRef<Path>, F: Into<OpenFlags>>(
        proc_fn: ProcFn,
        base: ProcfsBase,
        path: P,
        oflags: F,
        are_over_mounts_visible: bool,
        expected: ExpectedResult,
    ) -> Result<(), Error>
    where
        Proc: ProcfsHandleImpl,
        ProcFn: FnOnce() -> Result<Proc, Proc::Error>,
    {
        in_mnt_ns_with_overmounts(are_over_mounts_visible, expected, || {
            proc_fn()?.open_follow(base, path, oflags)
        })
    }

    pub(super) fn check_proc_readlink<Proc, ProcFn, P: AsRef<Path>>(
        proc_fn: ProcFn,
        base: ProcfsBase,
        path: P,
        are_over_mounts_visible: bool,
        expected: ExpectedResult,
    ) -> Result<(), Error>
    where
        Proc: ProcfsHandleImpl,
        ProcFn: FnOnce() -> Result<Proc, Proc::Error>,
    {
        in_mnt_ns_with_overmounts(are_over_mounts_visible, expected, || {
            proc_fn()?.readlink(base, path)
        })
    }
}

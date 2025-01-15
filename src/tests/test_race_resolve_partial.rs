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
    flags::ResolverFlags,
    resolvers::{PartialLookup, ResolverBackend},
    tests::common as tests_common,
    Root,
};

use std::{os::unix::io::AsFd, sync::mpsc, thread};

use anyhow::Error;

macro_rules! resolve_race_tests {
    // resolve_race_tests! {
    //     test_ok: resolve_partial(...) => Ok(("path", Some("remaining", ErrorKind::...)), libc::S_IF...));
    //     test_err: resolve_partial(...) => Err(ErrorKind::...);
    // }
    ([$root_dir:expr] fn $test_name:ident (mut $root_var:ident : Root) $body:block) => {
        paste::paste! {
            #[test]
            fn [<root_ $test_name _default>]() -> Result<(), Error> {
                let (tmpdir, root_dir) = $root_dir;
                let mut $root_var = Root::open(&root_dir)?;
                assert_eq!(
                    $root_var.resolver_backend(),
                    ResolverBackend::default(),
                    "ResolverBackend not the default despite not being configured"
                );

                { $body }

                // Make sure tmpdir is not dropped earlier.
                let _tmpdir = tmpdir;
                // Make sure the mut $root_var doesn't give us a warning.
                $root_var.set_resolver_flags($root_var.resolver_flags());
                Ok(())
            }

            #[test]
            fn [<root_ $test_name _openat2>]() -> Result<(), Error> {
                let (tmpdir, root_dir) = $root_dir;
                let mut $root_var = Root::open(&root_dir)?;
                $root_var.set_resolver_backend(ResolverBackend::KernelOpenat2);
                assert_eq!(
                    $root_var.resolver_backend(),
                    ResolverBackend::KernelOpenat2,
                    "incorrect ResolverBackend despite using set_resolver_backend"
                );

                if !$root_var.resolver_backend().supported() {
                    // Skip if not supported.
                    return Ok(());
                }

                { $body }

                // Make sure tmpdir is not dropped earlier.
                let _tmpdir = tmpdir;
                Ok(())
            }

            #[test]
            fn [<root_ $test_name _opath>]() -> Result<(), Error> {
                let (tmpdir, root_dir) = $root_dir;
                let mut $root_var = Root::open(&root_dir)?;
                $root_var.set_resolver_backend(ResolverBackend::EmulatedOpath);
                assert_eq!(
                    $root_var.resolver_backend(),
                    ResolverBackend::EmulatedOpath,
                    "incorrect ResolverBackend despite using set_resolver_backend"
                );

                // EmulatedOpath is always supported.
                assert!(
                    $root_var.resolver_backend().supported(),
                    "emulated opath is always supported",
                );

                { $body }

                // Make sure tmpdir is not dropped earlier.
                let _tmpdir = tmpdir;
                Ok(())
            }
        }
    };

    (@impl [$rename_a:literal <=> $rename_b:literal] $test_name:ident $op_name:ident ($path:expr, $rflags:expr, $no_follow_trailing:expr) => { $($expected:tt)* }) => {
        paste::paste! {
            resolve_race_tests! {
                [tests_common::create_race_tree()?]
                fn [<$op_name _ $test_name>](mut root: Root) {
                    root.set_resolver_flags($rflags);

                    thread::scope(|s| -> Result<_, Error> {
                        use utils::RenameStateMsg;

                        let root_fd = root.as_fd();
                        let (ctl_tx, ctl_rx) = mpsc::sync_channel(0);

                        s.spawn(move || {
                            utils::rename_exchange(
                                ctl_rx,
                                root_fd,
                                $rename_a,
                                $rename_b,
                            )
                        });

                        let expected = vec![ $($expected)* ];
                        for _ in 0..50000 {
                            // Make sure the rename thread isn't paused.
                            ctl_tx
                                .send(RenameStateMsg::Run)
                                .expect("should be able to send run signal to rename thread");

                            utils::[<check_root_race_ $op_name>](
                                &root,
                                &ctl_tx,
                                $path,
                                $no_follow_trailing,
                                &expected,
                            )?;
                        }

                        // Make sure a kill signal gets sent. When the tx handle
                        // is dropped, the rename loop should die anyway but
                        // this just makes sure. We have to ignore any errors
                        // because if the rename loop is already dead (and so rx
                        // has been dropped) then send will return an error.
                        let _ = ctl_tx.send(RenameStateMsg::Quit);
                        Ok(())
                    })?;
                }
            }
        }
    };

    (@impl [$($race_task:tt)*] $test_name:ident $op_name:ident ($path:expr, rflags = $($rflag:ident)|+) => { $($expected:tt)* } ) => {
        resolve_race_tests! {
            @impl [$($race_task)*]
            $test_name $op_name($path, $(ResolverFlags::$rflag)|*, false) => { $($expected)* }
        }
    };

    (@impl [$($race_task:tt)*] $test_name:ident $op_name:ident ($path:expr, no_follow_trailing = $no_follow_trailing:expr) => { $($expected:tt)* } ) => {
        resolve_race_tests! {
            @impl [$($race_task)*]
            $test_name $op_name($path, ResolverFlags::empty(), $no_follow_trailing) => { $($expected)* }
        }
    };

    (@impl [$($race_task:tt)*] $test_name:ident $op_name:ident ($path:expr) => { $($expected:tt)* } ) => {
        resolve_race_tests! {
            @impl [$($race_task)*]
            $test_name $op_name($path, ResolverFlags::empty(), false) => { $($expected)* }
        }
    };

    // NOTE: Because of the way that the repetition is nested, we need to make
    // the $race_task metavariable a basic tt ($($race_task:tt)* fails when we
    // try to substitute it). Luckily we can just use :tt for blocks of the form
    // [] and then re-parse it in the individual rule.
    ($($test_prefix:ident $race_task:tt { $($test_name:ident : $op_name:ident ($($args:tt)*) => { $($expected:tt)* } );* $(;)? });* $(;)?) => {
        $( $(
            paste::paste! {
                resolve_race_tests! {
                    @impl $race_task
                    [<$test_prefix _ $test_name>] $op_name ($($args)*) => { $($expected)* }
                }
            }
        )* )*
    };
}

resolve_race_tests! {
    // Swap a directory component with a symlink during lookup.
    swap_dir_link1 ["a/b" <=> "b-link"] {
        basic: resolve_partial("/a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        dotdot1: resolve_partial("/a/b/../b/../b/../b/../b/../b/../b/c/d/../d/../d/../d/../d/../d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "../d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "../b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        dotdot2: resolve_partial("/a/b/c/../c/../c/../c/../c/../c/../c/d/../d/../d/../d/../d/../d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "../d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "../c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
    };
    swap_dir_link2 ["a/b/c" <=> "c-link"] {
        basic: resolve_partial("/a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        dotdot: resolve_partial("/a/b/c/../c/../c/../c/../c/../c/../c/d/../d/../d/../d/../d/../d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "../d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "../c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
    };

    // Swap a directory with a non-directory.
    swap_dir_file ["a/b" <=> "file"] {
        basic: resolve_partial("/a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            // Hit the file during lookup.
            Ok(PartialLookup::Partial {
                handle: ("/file", libc::S_IFREG),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
        };
        dotdot: resolve_partial("a/b/c/../c/../c/../c/../c/../c/../c/d/../d/../d/../d/../d/../d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "../d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "../c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            // Hit the file during lookup.
            Ok(PartialLookup::Partial {
                handle: ("/file", libc::S_IFREG),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
        };
    };

    // Swap a directory with a dangling symlink.
    swap_dir_badlink_enoent ["a/b" <=> "bad-link1"] {
        basic: resolve_partial("/a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // Hit the dangling symlink (this makes us stop above it at "/a").
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        dotdot: resolve_partial("a/b/c/../c/../c/../c/../c/../c/../c/d/../d/../d/../d/../d/../d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "../d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "../c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // Hit the dangling symlink (this makes us stop above it at "/a").
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
    };
    swap_dir_badlink_enotdir ["a/b" <=> "bad-link2"] {
        basic: resolve_partial("/a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            // Hit the dangling symlink (this makes us stop above it at "/a").
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
        };
        dotdot: resolve_partial("a/b/c/../c/../c/../c/../c/../c/../c/d/../d/../d/../d/../d/../d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "../d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "../c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
            // Hit the dangling symlink (this makes us stop above it at "/a").
            Ok(PartialLookup::Partial {
                handle: ("/a", libc::S_IFDIR),
                remaining: "b/c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
            }),
        };
    };

    // Swap a directory with a symlink that would cause a naive resolver to
    // escape the root. This is effectively CVE-2018-15664.
    swap_dir_attack_link ["etc-target" <=> "etc-attack-rel-link"] {
        basic: resolve_partial("/etc-target/passwd") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Complete(("/etc-target/passwd", libc::S_IFREG))),
            // We successfully resolved the swapped symlink inside the root.
            Ok(PartialLookup::Complete(("/etc/passwd", libc::S_IFREG))),
        };
        dotdot: resolve_partial("/etc-target/../etc-target/../etc-target/../etc-target/../etc-target/../etc-target/passwd") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Complete(("/etc-target/passwd", libc::S_IFREG))),
            // We successfully resolved the swapped symlink inside the root.
            Ok(PartialLookup::Complete(("/etc/passwd", libc::S_IFREG))),
        };
    };
    swap_dir_attack_abs_link ["etc-target" <=> "etc-attack-abs-link"] {
        basic: resolve_partial("/etc-target/passwd") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Complete(("/etc-target/passwd", libc::S_IFREG))),
            // We successfully resolved the swapped symlink inside the root.
            Ok(PartialLookup::Complete(("/etc/passwd", libc::S_IFREG))),
        };
        dotdot: resolve_partial("/etc-target/../etc-target/../etc-target/../etc-target/../etc-target/../etc-target/passwd") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Complete(("/etc-target/passwd", libc::S_IFREG))),
            // We successfully resolved the swapped symlink inside the root.
            Ok(PartialLookup::Complete(("/etc/passwd", libc::S_IFREG))),
        };
    };

    // Move the root to a different location. This should not affect lookups
    move_root ["." <=> "../outsideroot"] {
        basic: resolve_partial("a/b/c/d/e") => {
            // Breakout detected.
            //Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        dotdot: resolve_partial("a/b/../../a/b/../../a/b/../../a/b/../../a/b/../../a/b/../../a/b/../../a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        // TODO: dotdot_extra with 10 copies of "b/c/d/../../../".
    };

    // Try to move a directory we are walking inside to be outside the root.
    // A naive "is .. the root" implementation would be tripped up by this.
    swap_dir_outside_root ["a/b" <=> "../outsideroot"] {
        basic: resolve_partial("a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // We could also land in the "outsideroot" path. This is okay
            // because there was a moment when the directory was inside the
            // root, and the attacker just moved it outside the root. We know
            // that neither resolver will allow us to walk into ".." in this
            // scenario, so we should be okay.
            Ok(PartialLookup::Partial {
                handle: ("../outsideroot/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("../outsideroot/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("../outsideroot", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
        dotdot: resolve_partial("a/b/../../a/b/../../a/b/../../a/b/../../a/b/../../a/b/../../a/b/../../a/b/c/d/e") => {
            // Breakout detected.
            Err(ErrorKind::SafetyViolation),
            // We successfully resolved the path as if there wasn't a race.
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // We could also land in the "outsideroot" path. This is okay
            // because there was a moment when the directory was inside the
            // root, and the attacker just moved it outside the root. We know
            // that neither resolver will allow us to walk into ".." in this
            // scenario, so we should be okay.
            Ok(PartialLookup::Partial {
                handle: ("../outsideroot/c/d", libc::S_IFDIR),
                remaining: "e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            // There was a race during the walk-back logic, which resulted in an
            // error but then the path was replaced back when walking back to
            // find the "last good" path.
            Ok(PartialLookup::Partial {
                handle: ("../outsideroot/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b/c", libc::S_IFDIR),
                remaining: "d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("../outsideroot", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
            Ok(PartialLookup::Partial {
                handle: ("/a/b", libc::S_IFDIR),
                remaining: "c/d/e".into(),
                last_error: ErrorKind::OsError(Some(libc::ENOENT)),
            }),
        };
    };
}

mod utils {
    use crate::{
        error::ErrorKind,
        flags::RenameFlags,
        resolvers::PartialLookup,
        syscalls,
        tests::{
            common::{self as tests_common, LookupResult},
            traits::RootImpl,
        },
        utils::FdExt,
        Root,
    };

    use std::{
        os::unix::{fs::MetadataExt, io::AsFd},
        path::{Path, PathBuf},
        sync::mpsc::{Receiver, RecvError, SyncSender, TryRecvError},
    };

    use anyhow::Error;
    use path_clean::PathClean;

    pub(super) enum RenameStateMsg {
        Run,
        Pause,
        Quit,
    }

    pub(super) fn rename_exchange<Fd: AsFd, P1: AsRef<Path>, P2: AsRef<Path>>(
        ctl_rx: Receiver<RenameStateMsg>,
        root: Fd,
        path1: P1,
        path2: P2,
    ) {
        let root = root.as_fd();
        let (path1, path2) = (path1.as_ref(), path2.as_ref());

        // One of the paths might be ".", which will give us -EBUSY from
        // renameat. We can just use full paths here (we are the only thing
        // doing renames here, and the root path is known to be safe to us).
        let root_path = root
            .as_unsafe_path_unchecked()
            .expect("should be able to get real path");
        let (root, path1, path2) = (
            syscalls::AT_FDCWD,
            [&root_path, path1].iter().collect::<PathBuf>().clean(),
            [&root_path, path2].iter().collect::<PathBuf>().clean(),
        );

        'rename: loop {
            match ctl_rx.try_recv() {
                Ok(RenameStateMsg::Quit) | Err(TryRecvError::Disconnected) => break 'rename,
                Ok(RenameStateMsg::Run) | Err(TryRecvError::Empty) => (),
                Ok(RenameStateMsg::Pause) => {
                    // Wait for a "Run" message.
                    loop {
                        match ctl_rx.recv() {
                            Ok(RenameStateMsg::Quit) | Err(RecvError) => break 'rename,
                            Ok(RenameStateMsg::Pause) => continue,
                            Ok(RenameStateMsg::Run) => break,
                        }
                    }
                }
            }

            syscalls::renameat2(root, &path1, root, &path2, RenameFlags::RENAME_EXCHANGE)
                .expect("swap A <-> B should work");
            syscalls::renameat2(root, &path1, root, &path2, RenameFlags::RENAME_EXCHANGE)
                .expect("swap B <-> A back should work");
        }
    }

    pub(super) fn check_root_race_resolve_partial<P: AsRef<Path>>(
        root: &Root,
        ctl_tx: &SyncSender<RenameStateMsg>,
        unsafe_path: P,
        no_follow_trailing: bool,
        allowed_results: &[Result<PartialLookup<LookupResult, ErrorKind>, ErrorKind>],
    ) -> Result<(), Error> {
        let unsafe_path = unsafe_path.as_ref();

        // Resolve the path.
        let result = root
            .resolver()
            .resolve_partial(root, unsafe_path, no_follow_trailing);

        // Pause the rename attack so that we can get the "unswapped" path with
        // as_unsafe_path_unchecked().
        ctl_tx
            .send(RenameStateMsg::Pause)
            .expect("should be able to pause rename attack");

        let root_dir = root.as_unsafe_path_unchecked()?;

        // Convert the handle to something useful for our tests.
        let result = result.map(|lookup_result| {
            let (path, file_type) = {
                let file = lookup_result.as_inner_handle();
                (
                    file.as_unsafe_path_unchecked()
                        .expect("should be able to get real path of handle"),
                    file.metadata()
                        .expect("should be able to fstat handle")
                        .mode()
                        & libc::S_IFMT,
                )
            };

            match lookup_result {
                PartialLookup::Complete(_) => PartialLookup::Complete((path, file_type)),
                PartialLookup::Partial {
                    handle: _,
                    remaining,
                    last_error,
                } => PartialLookup::Partial {
                    handle: (path, file_type),
                    remaining: remaining.clean(),
                    last_error: last_error.kind(),
                },
            }
        });

        // TODO: Check that we hit every error condition at least once, maybe
        // even output some statistics like filepath-securejoin does?

        assert!(
            allowed_results.iter().any(|expected| {
                let expected = expected
                    .as_ref()
                    .map(|lookup_result| {
                        let (path, file_type) = {
                            let (path, file_type) = lookup_result.as_inner_handle();
                            (
                                root_dir.join(path.trim_start_matches('/')).clean(),
                                *file_type,
                            )
                        };
                        match lookup_result {
                            PartialLookup::Complete(_) => {
                                PartialLookup::Complete((path, file_type))
                            }
                            PartialLookup::Partial {
                                handle: _,
                                remaining,
                                last_error,
                            } => PartialLookup::Partial {
                                handle: (path, file_type),
                                remaining: remaining.clone(),
                                last_error: *last_error,
                            },
                        }
                    })
                    .map_err(|err| *err);

                eprintln!("trying to match got {result:?} against allowed {expected:?}");
                match (&result, &expected) {
                    (Ok(lookup_result), Ok(expected_lookup_result)) => {
                        lookup_result == expected_lookup_result
                    }
                    (result, expected) => tests_common::check_err(result, expected).is_ok(),
                }
            }),
            "resolve({unsafe_path:?}) result {result:?} not in allowed result set"
        );

        Ok(())
    }
}

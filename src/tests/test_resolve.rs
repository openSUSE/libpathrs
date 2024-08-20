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

use std::path::Path;

use crate::{
    error::ErrorKind, flags::ResolverFlags, resolvers::PartialLookup,
    tests::common as tests_common, ResolverBackend, Root,
};

use anyhow::Error;

macro_rules! resolve_tests {
    // resolve_tests! {
    //      [create_root_path] {
    //          test_ok: resolve(...) => Ok(("path", libc::S_IF...))
    //          test_err: resolve(...) => Err(ErrorKind::...)
    //          test_ok: resolve_partial(...) => Ok(("path", Some("remaining", ErrorKind::...)), libc::S_IF...))
    //          test_err: resolve_partial(...) => Err(ErrorKind::...)
    //      }
    // }
    ([$root_dir:expr] fn $test_name:ident (mut $root_var:ident : Root) $body:block => $expected:expr) => {
        paste::paste! {
            #[test]
            fn [<$test_name _default>]() -> Result<(), Error> {
                let root_dir = $root_dir;
                let mut $root_var = Root::open(&root_dir)?;

                { $body }

                // Make sure root_dir is not dropped earlier.
                let _root_dir = root_dir;
                Ok(())
            }

            #[test]
            fn [<$test_name _openat2>]() -> Result<(), Error> {
                let root_dir = $root_dir;
                let mut $root_var = Root::open(&root_dir)?;
                $root_var.resolver.backend = ResolverBackend::KernelOpenat2;

                { $body }

                // Make sure root_dir is not dropped earlier.
                let _root_dir = root_dir;
                Ok(())
            }

            #[test]
            fn [<$test_name _opath>]() -> Result<(), Error> {
                let root_dir = $root_dir;
                let mut $root_var = Root::open(&root_dir)?;
                $root_var.resolver.backend = ResolverBackend::EmulatedOpath;

                { $body }

                // Make sure root_dir is not dropped earlier.
                let _root_dir = root_dir;
                Ok(())
            }
        }
    };

    ([$root_dir:expr] @impl $test_name:ident $op_name:ident ($path:expr, $rflags:expr, $no_follow_trailing:expr) => $expected:expr) => {
        paste::paste! {
            resolve_tests! {
                [$root_dir]
                fn [<root_ $op_name _ $test_name>](mut root: Root) {
                    root.resolver.flags = $rflags;
                    if !root.resolver.backend.supported() {
                        // Skip if not supported.
                        return Ok(());
                    }

                    let expected = $expected;
                    utils::[<check_root_ $op_name>](
                        &root,
                        $path,
                        $no_follow_trailing,
                        expected,
                    )?;
                } => $expected
            }
        }
    };

    ([$root_dir:expr] @impl $test_name:ident $op_name:ident ($path:expr, rflags = $($rflag:ident)|+) => $expected:expr ) => {
        resolve_tests! {
            [$root_dir]
            @impl $test_name $op_name($path, $(ResolverFlags::$rflag)|*, false) => $expected
        }
    };

    ([$root_dir:expr] @impl $test_name:ident $op_name:ident ($path:expr, no_follow_trailing = $no_follow_trailing:expr) => $expected:expr ) => {
        resolve_tests! {
            [$root_dir]
            @impl $test_name $op_name($path, ResolverFlags::empty(), $no_follow_trailing) => $expected
        }
    };

    ([$root_dir:expr] @impl $test_name:ident $op_name:ident ($path:expr) => $expected:expr ) => {
        resolve_tests! {
            [$root_dir]
            @impl $test_name $op_name($path, ResolverFlags::empty(), false) => $expected
        }
    };

    ($([$root_dir:expr] { $($test_name:ident : $op_name:ident ($($args:tt)*) => $expected:expr);* $(;)? });* $(;)?) => {
        $( $(
            resolve_tests! {
                [$root_dir]
                @impl $test_name $op_name ($($args)*) => $expected
            }
        )* )*
    }
}

resolve_tests! {
    [Path::new("/proc")] {
        proc_pseudo_magiclink: resolve("self/sched") => Ok(("{{/proc/self}}/sched", libc::S_IFREG));
        proc_pseudo_magiclink_nosym1: resolve("self", rflags = NO_SYMLINKS) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        proc_pseudo_magiclink_nosym2: resolve("self/sched", rflags = NO_SYMLINKS) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        proc_pseudo_magiclink_nofollow1: resolve("self", no_follow_trailing = true) => Ok(("self", libc::S_IFLNK));
        proc_pseudo_magiclink_nofollow2: resolve("self/sched", no_follow_trailing = true) => Ok(("{{/proc/self}}/sched", libc::S_IFREG));

        // Verify forced RESOLVE_NO_MAGICLINKS behaviour.
        proc_magiclink: resolve("self/exe") => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        proc_magiclink_nofollow: resolve("self/exe", no_follow_trailing = true) => Ok(("{{/proc/self}}/exe", libc::S_IFLNK));
        proc_magiclink_component_nofollow: resolve("self/root/etc/passwd", no_follow_trailing = true) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
    };

    // Complete lookups.
    [tests_common::create_basic_tree()?] {
        complete_root1: resolve("/") => Ok(("/", libc::S_IFDIR));
        complete_root1: resolve_partial("/") => Ok(PartialLookup::Complete(("/", libc::S_IFDIR)));
        complete_root2: resolve("/../../../../../..") => Ok(("/", libc::S_IFDIR));
        complete_root2: resolve_partial("/../../../../../..") => Ok(PartialLookup::Complete(("/", libc::S_IFDIR)));
        complete_root_link1: resolve("root-link1") => Ok(("/", libc::S_IFDIR));
        complete_root_link1: resolve_partial("root-link1") => Ok(PartialLookup::Complete(("/", libc::S_IFDIR)));
        complete_root_link2: resolve("root-link2") => Ok(("/", libc::S_IFDIR));
        complete_root_link2: resolve_partial("root-link2") => Ok(PartialLookup::Complete(("/", libc::S_IFDIR)));
        complete_root_link3: resolve("root-link3") => Ok(("/", libc::S_IFDIR));
        complete_root_link3: resolve_partial("root-link3") => Ok(PartialLookup::Complete(("/", libc::S_IFDIR)));
        complete_dir1: resolve("a") => Ok(("/a", libc::S_IFDIR));
        complete_dir1: resolve_partial("a") => Ok(PartialLookup::Complete(("/a", libc::S_IFDIR)));
        complete_dir2: resolve("b/c/d/e/f") => Ok(("/b/c/d/e/f", libc::S_IFDIR));
        complete_dir2: resolve_partial("b/c/d/e/f") => Ok(PartialLookup::Complete(("/b/c/d/e/f", libc::S_IFDIR)));
        complete_dir3: resolve("b///././c////.//d/./././///e////.//./f//././././") => Ok(("/b/c/d/e/f", libc::S_IFDIR));
        complete_dir3: resolve_partial("b///././c////.//d/./././///e////.//./f//././././") => Ok(PartialLookup::Complete(("/b/c/d/e/f", libc::S_IFDIR)));
        complete_file: resolve("b/c/file") => Ok(("/b/c/file", libc::S_IFREG));
        complete_file: resolve_partial("b/c/file") => Ok(PartialLookup::Complete(("/b/c/file", libc::S_IFREG)));
        complete_file_link: resolve("b-file") => Ok(("/b/c/file", libc::S_IFREG));
        complete_file_link: resolve_partial("b-file") => Ok(PartialLookup::Complete(("/b/c/file", libc::S_IFREG)));
        complete_fifo: resolve("b/fifo") => Ok(("/b/fifo", libc::S_IFIFO));
        complete_fifo: resolve_partial("b/fifo") => Ok(PartialLookup::Complete(("/b/fifo", libc::S_IFIFO)));
        complete_sock: resolve("b/sock") => Ok(("/b/sock", libc::S_IFSOCK));
        complete_sock: resolve_partial("b/sock") => Ok(PartialLookup::Complete(("/b/sock", libc::S_IFSOCK)));
        // Partial lookups.
        partial_dir_basic: resolve("a/b/c/d/e/f/g/h") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        partial_dir_basic: resolve_partial("a/b/c/d/e/f/g/h") => Ok(PartialLookup::Partial {
            handle: ("a", libc::S_IFDIR),
            remaining: "b/c/d/e/f/g/h".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        partial_dir_dotdot: resolve("a/foo/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        partial_dir_dotdot: resolve_partial("a/foo/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("a", libc::S_IFDIR),
            remaining: "foo/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        // Non-lexical symlinks.
        nonlexical_basic_complete: resolve("target") => Ok(("/target", libc::S_IFDIR));
        nonlexical_basic_complete: resolve_partial("target") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_basic_complete1: resolve("target/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_basic_complete1: resolve_partial("target/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_basic_complete2: resolve("target//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_basic_complete2: resolve_partial("target//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_basic_partial: resolve("target/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_basic_partial: resolve_partial("target/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_basic_partial_dotdot: resolve("target/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_basic_partial_dotdot: resolve_partial("target/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level1_abs_complete1: resolve("link1/target_abs") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level1_abs_complete1: resolve_partial("link1/target_abs") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level1_abs_complete2: resolve("link1/target_abs/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level1_abs_complete2: resolve_partial("link1/target_abs/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level1_abs_complete3: resolve("link1/target_abs//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level1_abs_complete3: resolve_partial("link1/target_abs//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level1_abs_partial: resolve("link1/target_abs/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level1_abs_partial: resolve_partial("link1/target_abs/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level1_abs_partial_dotdot: resolve("link1/target_abs/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level1_abs_partial_dotdot: resolve_partial("link1/target_abs/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level1_rel_complete1: resolve("link1/target_rel") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level1_rel_complete1: resolve_partial("link1/target_rel") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level1_rel_complete2: resolve("link1/target_rel/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level1_rel_complete2: resolve_partial("link1/target_rel/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level1_rel_complete3: resolve("link1/target_rel//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level1_rel_complete3: resolve_partial("link1/target_rel//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level1_rel_partial: resolve("link1/target_rel/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level1_rel_partial: resolve_partial("link1/target_rel/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level1_rel_partial_dotdot: resolve("link1/target_rel/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level1_rel_partial_dotdot: resolve_partial("link1/target_rel/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_abs_abs_complete1: resolve("link2/link1_abs/target_abs") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_abs_complete1: resolve_partial("link2/link1_abs/target_abs") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_abs_complete2: resolve("link2/link1_abs/target_abs/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_abs_complete2: resolve_partial("link2/link1_abs/target_abs/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_abs_complete3: resolve("link2/link1_abs/target_abs//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_abs_complete3: resolve_partial("link2/link1_abs/target_abs//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_abs_partial: resolve("link2/link1_abs/target_abs/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_abs_abs_partial: resolve_partial("link2/link1_abs/target_abs/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_abs_abs_partial_dotdot: resolve("link2/link1_abs/target_abs/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_abs_abs_partial_dotdot: resolve_partial("link2/link1_abs/target_abs/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_abs_rel_complete1: resolve("link2/link1_abs/target_rel") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_rel_complete1: resolve_partial("link2/link1_abs/target_rel") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_rel_complete2: resolve("link2/link1_abs/target_rel/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_rel_complete2: resolve_partial("link2/link1_abs/target_rel/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_rel_complete3: resolve("link2/link1_abs/target_rel//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_rel_complete3: resolve_partial("link2/link1_abs/target_rel//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_rel_partial: resolve("link2/link1_abs/target_rel/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_abs_rel_partial: resolve_partial("link2/link1_abs/target_rel/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_abs_rel_partial_dotdot: resolve("link2/link1_abs/target_rel/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_abs_rel_partial_dotdot: resolve_partial("link2/link1_abs/target_rel/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_abs_open_complete1: resolve("link2/link1_abs/../target") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_open_complete1: resolve_partial("link2/link1_abs/../target") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_open_complete2: resolve("link2/link1_abs/../target/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_open_complete2: resolve_partial("link2/link1_abs/../target/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_open_complete3: resolve("link2/link1_abs/../target//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_abs_open_complete3: resolve_partial("link2/link1_abs/../target//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_abs_open_partial: resolve("link2/link1_abs/../target/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_abs_open_partial: resolve_partial("link2/link1_abs/../target/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_abs_open_partial_dotdot: resolve("link2/link1_abs/../target/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_abs_open_partial_dotdot: resolve_partial("link2/link1_abs/../target/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_rel_abs_complete1: resolve("link2/link1_rel/target_abs") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_abs_complete1: resolve_partial("link2/link1_rel/target_abs") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_abs_complete2: resolve("link2/link1_rel/target_abs/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_abs_complete2: resolve_partial("link2/link1_rel/target_abs/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_abs_complete3: resolve("link2/link1_rel/target_abs//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_abs_complete3: resolve_partial("link2/link1_rel/target_abs//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_abs_partial: resolve("link2/link1_rel/target_abs/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_rel_abs_partial: resolve_partial("link2/link1_rel/target_abs/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_rel_abs_partial_dotdot: resolve("link2/link1_rel/target_abs/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_rel_abs_partial_dotdot: resolve_partial("link2/link1_rel/target_abs/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_rel_rel_complete1: resolve("link2/link1_rel/target_rel") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_rel_complete1: resolve_partial("link2/link1_rel/target_rel") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_rel_complete2: resolve("link2/link1_rel/target_rel/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_rel_complete2: resolve_partial("link2/link1_rel/target_rel/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_rel_complete3: resolve("link2/link1_rel/target_rel//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_rel_complete3: resolve_partial("link2/link1_rel/target_rel//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_rel_partial: resolve("link2/link1_rel/target_rel/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_rel_rel_partial: resolve_partial("link2/link1_rel/target_rel/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_rel_rel_partial_dotdot: resolve("link2/link1_rel/target_rel/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_rel_rel_partial_dotdot: resolve_partial("link2/link1_rel/target_rel/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_rel_open_complete1: resolve("link2/link1_rel/../target") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_open_complete1: resolve_partial("link2/link1_rel/../target") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_open_complete2: resolve("link2/link1_rel/../target/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_open_complete2: resolve_partial("link2/link1_rel/../target/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_open_complete3: resolve("link2/link1_rel/../target//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level2_rel_open_complete3: resolve_partial("link2/link1_rel/../target//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level2_rel_open_partial: resolve("link2/link1_rel/../target/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_rel_open_partial: resolve_partial("link2/link1_rel/../target/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level2_rel_open_partial_dotdot: resolve("link2/link1_rel/../target/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level2_rel_open_partial_dotdot: resolve_partial("link2/link1_rel/../target/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level3_abs_complete1: resolve("link3/target_abs") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level3_abs_complete1: resolve_partial("link3/target_abs") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level3_abs_complete2: resolve("link3/target_abs/") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level3_abs_complete2: resolve_partial("link3/target_abs/") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level3_abs_complete3: resolve("link3/target_abs//") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level3_abs_complete3: resolve_partial("link3/target_abs//") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level3_abs_partial: resolve("link3/target_abs/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level3_abs_partial: resolve_partial("link3/target_abs/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level3_abs_partial_dotdot: resolve("link3/target_abs/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level3_abs_partial_dotdot: resolve_partial("link3/target_abs/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level3_rel_complete: resolve("link3/target_rel") => Ok(("/target", libc::S_IFDIR));
        nonlexical_level3_rel_complete: resolve_partial("link3/target_rel") => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        nonlexical_level3_rel_partial: resolve("link3/target_rel/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level3_rel_partial: resolve_partial("link3/target_rel/foo") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        nonlexical_level3_rel_partial_dotdot: resolve("link3/target_rel/../target/foo/bar/../baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        nonlexical_level3_rel_partial_dotdot: resolve_partial("link3/target_rel/../target/foo/bar/../baz") => Ok(PartialLookup::Partial {
            handle: ("target", libc::S_IFDIR),
            remaining: "foo/bar/../baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        // Partial lookups due to hitting a non_directory.
        partial_nondir_slash1: resolve("b/c/file/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_slash1: resolve_partial("b/c/file/") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_slash2: resolve("b/c/file//") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_slash2: resolve_partial("b/c/file//") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "/".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_dot: resolve("b/c/file/.") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_dot: resolve_partial("b/c/file/.") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: ".".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_dotdot1: resolve("b/c/file/..") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_dotdot1: resolve_partial("b/c/file/..") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "..".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_dotdot2: resolve("b/c/file/../foo/bar") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_dotdot2: resolve_partial("b/c/file/../foo/bar") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "../foo/bar".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_symlink_slash1: resolve("b-file/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_symlink_slash1: resolve_partial("b-file/") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_symlink_slash2: resolve("b-file//") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_symlink_slash2: resolve_partial("b-file//") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "/".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_symlink_dot: resolve("b-file/.") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_symlink_dot: resolve_partial("b-file/.") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: ".".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_symlink_dotdot1: resolve("b-file/..") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_symlink_dotdot1: resolve_partial("b-file/..") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "..".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_nondir_symlink_dotdot2: resolve("b-file/../foo/bar") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_nondir_symlink_dotdot2: resolve_partial("b-file/../foo/bar") => Ok(PartialLookup::Partial {
            handle: ("b/c/file", libc::S_IFREG),
            remaining: "../foo/bar".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_fifo_slash1: resolve("b/fifo/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_fifo_slash1: resolve_partial("b/fifo/") => Ok(PartialLookup::Partial {
            handle: ("b/fifo", libc::S_IFIFO),
            remaining: "".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_fifo_slash2: resolve("b/fifo//") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_fifo_slash2: resolve_partial("b/fifo//") => Ok(PartialLookup::Partial {
            handle: ("b/fifo", libc::S_IFIFO),
            remaining: "/".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_fifo_dot: resolve("b/fifo/.") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_fifo_dot: resolve_partial("b/fifo/.") => Ok(PartialLookup::Partial {
            handle: ("b/fifo", libc::S_IFIFO),
            remaining: ".".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_fifo_dotdot1: resolve("b/fifo/..") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_fifo_dotdot1: resolve_partial("b/fifo/..") => Ok(PartialLookup::Partial {
            handle: ("b/fifo", libc::S_IFIFO),
            remaining: "..".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_fifo_dotdot2: resolve("b/fifo/../foo/bar") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_fifo_dotdot2: resolve_partial("b/fifo/../foo/bar") => Ok(PartialLookup::Partial {
            handle: ("b/fifo", libc::S_IFIFO),
            remaining: "../foo/bar".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_sock_slash1: resolve("b/sock/") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_sock_slash1: resolve_partial("b/sock/") => Ok(PartialLookup::Partial {
            handle: ("b/sock", libc::S_IFSOCK),
            remaining: "".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_sock_slash2: resolve("b/sock//") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_sock_slash2: resolve_partial("b/sock//") => Ok(PartialLookup::Partial {
            handle: ("b/sock", libc::S_IFSOCK),
            remaining: "/".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_sock_dot: resolve("b/sock/.") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_sock_dot: resolve_partial("b/sock/.") => Ok(PartialLookup::Partial {
            handle: ("b/sock", libc::S_IFSOCK),
            remaining: ".".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_sock_dotdot1: resolve("b/sock/..") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_sock_dotdot1: resolve_partial("b/sock/..") => Ok(PartialLookup::Partial {
            handle: ("b/sock", libc::S_IFSOCK),
            remaining: "..".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        partial_sock_dotdot2: resolve("b/sock/../foo/bar") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        partial_sock_dotdot2: resolve_partial("b/sock/../foo/bar") => Ok(PartialLookup::Partial {
            handle: ("b/sock", libc::S_IFSOCK),
            remaining: "../foo/bar".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        // O_NOFOLLOW doesn't matter for trailing-slash paths.
        partial_symlink_nofollow_slash1: resolve("link3/target_abs/", no_follow_trailing = true) => Ok(("/target", libc::S_IFDIR));
        partial_symlink_nofollow_slash1: resolve_partial("link3/target_abs/", no_follow_trailing = true) => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        partial_symlink_nofollow_slash2: resolve("link3/target_abs//", no_follow_trailing = true) => Ok(("/target", libc::S_IFDIR));
        partial_symlink_nofollow_slash2: resolve_partial("link3/target_abs//", no_follow_trailing = true) => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        partial_symlink_nofollow_dot: resolve("link3/target_abs/.", no_follow_trailing = true) => Ok(("/target", libc::S_IFDIR));
        partial_symlink_nofollow_dot: resolve_partial("link3/target_abs/.", no_follow_trailing = true) => Ok(PartialLookup::Complete(("/target", libc::S_IFDIR)));
        // Dangling symlinks are treated as though they are non_existent.
        dangling1_inroot_trailing: resolve("a-fake1") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling1_inroot_trailing: resolve_partial("a-fake1") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake1".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling1_inroot_partial: resolve("a-fake1/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling1_inroot_partial: resolve_partial("a-fake1/foo") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake1/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling1_inroot_partial_dotdot: resolve("a-fake1/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling1_inroot_partial_dotdot: resolve_partial("a-fake1/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake1/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling1_sub_trailing: resolve("c/a-fake1") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling1_sub_trailing: resolve_partial("c/a-fake1") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake1".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling1_sub_partial: resolve("c/a-fake1/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling1_sub_partial: resolve_partial("c/a-fake1/foo") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake1/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling1_sub_partial_dotdot: resolve("c/a-fake1/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling1_sub_partial_dotdot: resolve_partial("c/a-fake1/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake1/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling2_inroot_trailing: resolve("a-fake2") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling2_inroot_trailing: resolve_partial("a-fake2") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake2".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling2_inroot_partial: resolve("a-fake2/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling2_inroot_partial: resolve_partial("a-fake2/foo") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake2/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling2_inroot_partial_dotdot: resolve("a-fake2/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling2_inroot_partial_dotdot: resolve_partial("a-fake2/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake2/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling2_sub_trailing: resolve("c/a-fake2") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling2_sub_trailing: resolve_partial("c/a-fake2") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake2".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling2_sub_partial: resolve("c/a-fake2/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling2_sub_partial: resolve_partial("c/a-fake2/foo") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake2/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling2_sub_partial_dotdot: resolve("c/a-fake2/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling2_sub_partial_dotdot: resolve_partial("c/a-fake2/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake2/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling3_inroot_trailing: resolve("a-fake3") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling3_inroot_trailing: resolve_partial("a-fake3") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake3".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling3_inroot_partial: resolve("a-fake3/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling3_inroot_partial: resolve_partial("a-fake3/foo") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake3/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling3_inroot_partial_dotdot: resolve("a-fake3/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling3_inroot_partial_dotdot: resolve_partial("a-fake3/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "a-fake3/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling3_sub_trailing: resolve("c/a-fake3") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling3_sub_trailing: resolve_partial("c/a-fake3") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake3".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling3_sub_partial: resolve("c/a-fake3/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling3_sub_partial: resolve_partial("c/a-fake3/foo") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake3/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling3_sub_partial_dotdot: resolve("c/a-fake3/../bar/baz") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling3_sub_partial_dotdot: resolve_partial("c/a-fake3/../bar/baz") => Ok(PartialLookup::Partial {
            handle: ("c", libc::S_IFDIR),
            remaining: "a-fake3/../bar/baz".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        // Tricky dangling symlinks.
        dangling_tricky1_trailing: resolve("link3/deep_dangling1") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling_tricky1_trailing: resolve_partial("link3/deep_dangling1") => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "deep_dangling1".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling_tricky1_partial: resolve("link3/deep_dangling1/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling_tricky1_partial: resolve_partial("link3/deep_dangling1/foo") => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "deep_dangling1/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling_tricky1_partial_dotdot: resolve("link3/deep_dangling1/..") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling_tricky1_partial_dotdot: resolve_partial("link3/deep_dangling1/..") => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "deep_dangling1/..".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling_tricky2_trailing: resolve("link3/deep_dangling2") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling_tricky2_trailing: resolve_partial("link3/deep_dangling2") => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "deep_dangling2".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling_tricky2_partial: resolve("link3/deep_dangling2/foo") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling_tricky2_partial: resolve_partial("link3/deep_dangling2/foo") => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "deep_dangling2/foo".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        dangling_tricky2_partial_dotdot: resolve("link3/deep_dangling2/..") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        dangling_tricky2_partial_dotdot: resolve_partial("link3/deep_dangling2/..") => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "deep_dangling2/..".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        // Really deep dangling links.
        deep_dangling1: resolve("dangling/a") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        deep_dangling1: resolve_partial("dangling/a") => Ok(PartialLookup::Partial {
            handle: ("dangling", libc::S_IFDIR),
            remaining: "a".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        deep_dangling2: resolve("dangling/b/c") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        deep_dangling2: resolve_partial("dangling/b/c") => Ok(PartialLookup::Partial {
            handle: ("dangling/b", libc::S_IFDIR),
            remaining: "c".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        deep_dangling3: resolve("dangling/c") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        deep_dangling3: resolve_partial("dangling/c") => Ok(PartialLookup::Partial {
            handle: ("dangling", libc::S_IFDIR),
            remaining: "c".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        deep_dangling4: resolve("dangling/d/e") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        deep_dangling4: resolve_partial("dangling/d/e") => Ok(PartialLookup::Partial {
            handle: ("dangling/d", libc::S_IFDIR),
            remaining: "e".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        deep_dangling5: resolve("dangling/e") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        deep_dangling5: resolve_partial("dangling/e") => Ok(PartialLookup::Partial {
            handle: ("dangling", libc::S_IFDIR),
            remaining: "e".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        deep_dangling6: resolve("dangling/g") => Err(ErrorKind::OsError(Some(libc::ENOENT)));
        deep_dangling6: resolve_partial("dangling/g") => Ok(PartialLookup::Partial {
            handle: ("dangling", libc::S_IFDIR),
            remaining: "g".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOENT)),
        });
        deep_dangling_fileasdir1: resolve("dangling-file/a") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        deep_dangling_fileasdir1: resolve_partial("dangling-file/a") => Ok(PartialLookup::Partial {
            handle: ("dangling-file", libc::S_IFDIR),
            remaining: "a".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        deep_dangling_fileasdir2: resolve("dangling-file/b/c") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        deep_dangling_fileasdir2: resolve_partial("dangling-file/b/c") => Ok(PartialLookup::Partial {
            handle: ("dangling-file/b", libc::S_IFDIR),
            remaining: "c".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        deep_dangling_fileasdir3: resolve("dangling-file/c") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        deep_dangling_fileasdir3: resolve_partial("dangling-file/c") => Ok(PartialLookup::Partial {
            handle: ("dangling-file", libc::S_IFDIR),
            remaining: "c".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        deep_dangling_fileasdir4: resolve("dangling-file/d/e") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        deep_dangling_fileasdir4: resolve_partial("dangling-file/d/e") => Ok(PartialLookup::Partial {
            handle: ("dangling-file/d", libc::S_IFDIR),
            remaining: "e".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        deep_dangling_fileasdir5: resolve("dangling-file/e") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        deep_dangling_fileasdir5: resolve_partial("dangling-file/e") => Ok(PartialLookup::Partial {
            handle: ("dangling-file", libc::S_IFDIR),
            remaining: "e".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        deep_dangling_fileasdir6: resolve("dangling-file/g") => Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        deep_dangling_fileasdir6: resolve_partial("dangling-file/g") => Ok(PartialLookup::Partial {
            handle: ("dangling-file", libc::S_IFDIR),
            remaining: "g".into(),
            last_error: ErrorKind::OsError(Some(libc::ENOTDIR)),
        });
        // Symlink loops.
        loop1: resolve("loop/link") => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        loop1: resolve_partial("loop/link") => Ok(PartialLookup::Partial {
            handle: ("loop", libc::S_IFDIR),
            remaining: "link".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        loop_basic1: resolve("loop/basic-loop1") => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        loop_basic1: resolve_partial("loop/basic-loop1") => Ok(PartialLookup::Partial {
            handle: ("loop", libc::S_IFDIR),
            remaining: "basic-loop1".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        loop_basic2: resolve("loop/basic-loop2") => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        loop_basic2: resolve_partial("loop/basic-loop2") => Ok(PartialLookup::Partial {
            handle: ("loop", libc::S_IFDIR),
            remaining: "basic-loop2".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        loop_basic3: resolve("loop/basic-loop3") => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        loop_basic3: resolve_partial("loop/basic-loop3") => Ok(PartialLookup::Partial {
            handle: ("loop", libc::S_IFDIR),
            remaining: "basic-loop3".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        // NO_FOLLOW.
        symlink_nofollow: resolve("link3/target_abs", no_follow_trailing = true) => Ok(("link3/target_abs", libc::S_IFLNK));
        symlink_nofollow: resolve_partial("link3/target_abs", no_follow_trailing = true) => Ok(PartialLookup::Complete(("link3/target_abs", libc::S_IFLNK)));
        symlink_component_nofollow1: resolve("e/f", no_follow_trailing = true) => Ok(("b/c/d/e/f", libc::S_IFDIR));
        symlink_component_nofollow1: resolve_partial("e/f", no_follow_trailing = true) => Ok(PartialLookup::Complete(("b/c/d/e/f", libc::S_IFDIR)));
        symlink_component_nofollow2: resolve("link2/link1_abs/target_rel", no_follow_trailing = true) => Ok(("link1/target_rel", libc::S_IFLNK));
        symlink_component_nofollow2: resolve_partial("link2/link1_abs/target_rel", no_follow_trailing = true) => Ok(PartialLookup::Complete(("link1/target_rel", libc::S_IFLNK)));
        loop_nofollow: resolve("loop/link", no_follow_trailing = true) => Ok(("loop/link", libc::S_IFLNK));
        loop_nofollow: resolve_partial("loop/link", no_follow_trailing = true) => Ok(PartialLookup::Complete(("loop/link", libc::S_IFLNK)));
        // RESOLVE_NO_SYMLINKS.
        dir_nosym: resolve("b/c/d/e", rflags = NO_SYMLINKS) => Ok(("b/c/d/e", libc::S_IFDIR));
        dir_nosym: resolve_partial("b/c/d/e", rflags = NO_SYMLINKS) => Ok(PartialLookup::Complete(("b/c/d/e", libc::S_IFDIR)));
        symlink_nosym: resolve("link3/target_abs", rflags = NO_SYMLINKS) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        symlink_nosym: resolve_partial("link3/target_abs", rflags = NO_SYMLINKS) => Ok(PartialLookup::Partial {
            handle: ("link3", libc::S_IFDIR),
            remaining: "target_abs".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        symlink_component_nosym1: resolve("e/f", rflags = NO_SYMLINKS) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        symlink_component_nosym1: resolve_partial("e/f", rflags = NO_SYMLINKS) => Ok(PartialLookup::Partial {
            handle: ("", libc::S_IFDIR),
            remaining: "e/f".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        symlink_component_nosym2: resolve("link2/link1_abs/target_rel", rflags = NO_SYMLINKS) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        symlink_component_nosym2: resolve_partial("link2/link1_abs/target_rel", rflags = NO_SYMLINKS) => Ok(PartialLookup::Partial {
            handle: ("link2", libc::S_IFDIR),
            remaining: "link1_abs/target_rel".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
        loop_nosym: resolve("loop/link", rflags = NO_SYMLINKS) => Err(ErrorKind::OsError(Some(libc::ELOOP)));
        loop_nosym: resolve_partial("loop/link", rflags = NO_SYMLINKS) => Ok(PartialLookup::Partial {
            handle: ("loop", libc::S_IFDIR),
            remaining: "link".into(),
            last_error: ErrorKind::OsError(Some(libc::ELOOP)),
        });
    }
}

mod utils {
    use std::{os::linux::fs::MetadataExt, path::Path};

    use crate::{
        error::ErrorKind, flags::OpenFlags, resolvers::PartialLookup, syscalls, utils::RawFdExt,
        Handle, Root,
    };

    use anyhow::Error;
    use errno::Errno;
    use pretty_assertions::assert_eq;

    pub(super) type LookupResult<'a> = (&'a str, libc::mode_t);

    impl<H, E> PartialEq for PartialLookup<H, E>
    where
        H: PartialEq,
        E: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Complete(left), Self::Complete(right)) => left == right,
                (
                    Self::Partial {
                        handle: left_handle,
                        remaining: left_remaining,
                        last_error: left_last_error,
                    },
                    Self::Partial {
                        handle: right_handle,
                        remaining: right_remaining,
                        last_error: right_last_error,
                    },
                ) => {
                    left_handle == right_handle
                        && left_remaining == right_remaining
                        && left_last_error == right_last_error
                }
                _ => false,
            }
        }
    }

    impl<H, E> PartialLookup<H, E> {
        fn as_inner_handle(&self) -> &H {
            match self {
                PartialLookup::Complete(handle) => handle,
                PartialLookup::Partial { handle, .. } => handle,
            }
        }
    }

    fn errno_description(err: ErrorKind) -> String {
        match err {
            ErrorKind::OsError(Some(errno)) => format!("{err:?} ({})", Errno(errno)),
            _ => format!("{err:?}"),
        }
    }

    fn check_reopen(
        handle: &Handle,
        flags: OpenFlags,
        expected_error: Option<i32>,
    ) -> Result<(), Error> {
        let expected_error = expected_error.map(|errno| ErrorKind::OsError(Some(errno)));
        let file = match (handle.reopen(flags), expected_error) {
            (Ok(f), None) => f,
            (Err(e), None) => anyhow::bail!("unexpected error '{}'", e),
            (Ok(f), Some(want_err)) => anyhow::bail!(
                "expected to get io::Error {} but instead got file {}",
                errno_description(want_err),
                f.as_unsafe_path_unchecked()?.display(),
            ),
            (Err(err), Some(want_err)) => {
                assert_eq!(
                    err.kind(),
                    want_err,
                    "expected io::Error {}, got '{}'",
                    errno_description(want_err),
                    err,
                );
                return Ok(());
            }
        };

        let real_handle_path = handle.as_file().as_unsafe_path_unchecked()?;
        let real_reopen_path = file.as_unsafe_path_unchecked()?;

        assert_eq!(
            real_handle_path, real_reopen_path,
            "reopened handle should be equivalent to old handle",
        );

        let clone_handle = handle.try_clone()?;
        let clone_handle_path = clone_handle.as_file().as_unsafe_path_unchecked()?;

        assert_eq!(
            real_handle_path, clone_handle_path,
            "cloned handle should be equivalent to old handle",
        );

        // TODO: Check fd flags.

        Ok(())
    }

    pub(super) fn check_root_resolve_partial<P: AsRef<Path>>(
        root: &Root,
        unsafe_path: P,
        no_follow_trailing: bool,
        expected: Result<PartialLookup<LookupResult, ErrorKind>, ErrorKind>,
    ) -> Result<(), Error> {
        let root_dir = root.as_file().as_unsafe_path_unchecked()?;
        let unsafe_path = unsafe_path.as_ref();

        let result = root
            .resolver
            .resolve_partial(root.as_file(), unsafe_path, no_follow_trailing)
            .map(|lookup_result| {
                let (path, file_type) = {
                    let file = lookup_result.as_inner_handle().as_file();
                    (
                        file.as_unsafe_path_unchecked()
                            .expect("should be able to get real path of handle"),
                        file.metadata()
                            .expect("should be able to fstat handle")
                            .st_mode()
                            & libc::S_IFMT,
                    )
                };

                match lookup_result {
                    PartialLookup::Complete(handle) => {
                        (handle, PartialLookup::Complete((path, file_type)))
                    }
                    PartialLookup::Partial {
                        handle,
                        remaining,
                        last_error,
                    } => (
                        handle,
                        PartialLookup::Partial {
                            handle: (path, file_type),
                            remaining,
                            last_error: last_error.kind(),
                        },
                    ),
                }
            });

        let ((handle, lookup_result), expected_lookup_result) = match (result, expected) {
            (Ok((handle, lookup_result)), Ok(expected_lookup_result)) => {
                let (path, file_type) = {
                    let (path, file_type) = expected_lookup_result.as_inner_handle();
                    (root_dir.join(path.trim_start_matches('/')), *file_type)
                };
                let expected_lookup_result = match expected_lookup_result {
                    PartialLookup::Complete(_) => PartialLookup::Complete((path, file_type)),
                    PartialLookup::Partial {
                        handle: _,
                        remaining,
                        last_error,
                    } => PartialLookup::Partial {
                        handle: (path, file_type),
                        remaining,
                        last_error,
                    },
                };

                ((handle, lookup_result), expected_lookup_result)
            }

            (Err(err), Ok(expected)) => {
                anyhow::bail!(
                    "unexpected error '{}', expected successful {:?}",
                    err,
                    expected,
                )
            }

            (Ok((_, lookup_result)), Err(want_err)) => anyhow::bail!(
                "expected to get io::Error {} but instead got result {:?}",
                errno_description(want_err),
                lookup_result,
            ),

            (Err(err), Err(want_err)) => {
                assert_eq!(
                    err.kind(),
                    want_err,
                    "expected io::Error {}, got '{}'",
                    errno_description(want_err),
                    err,
                );
                return Ok(());
            }
        };

        assert_eq!(
            lookup_result, expected_lookup_result,
            "partial_lookup({unsafe_path:?}, {no_follow_trailing}) result mismatch",
        );

        let (_, real_file_type) = lookup_result.as_inner_handle();
        match *real_file_type {
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

        Ok(())
    }

    pub(super) fn check_root_resolve<P: AsRef<Path>>(
        root: &Root,
        unsafe_path: P,
        no_follow_trailing: bool,
        expected: Result<LookupResult, ErrorKind>,
    ) -> Result<(), Error> {
        let root_dir = root.as_file().as_unsafe_path_unchecked()?;
        let unsafe_path = unsafe_path.as_ref();

        let result = if no_follow_trailing {
            root.resolve_nofollow(unsafe_path)
        } else {
            root.resolve(unsafe_path)
        };

        let (handle, expected_path, expected_file_type) = match (result, expected) {
            (Ok(handle), Ok((expected_path, file_type))) => (
                handle,
                expected_path.replace("{{/proc/self}}", &format!("{}", syscalls::getpid())),
                file_type,
            ),

            (Err(err), Ok((expected_path, _))) => {
                anyhow::bail!(
                    "unexpected error '{}', expected file {}",
                    err,
                    expected_path
                )
            }

            (Ok(handle), Err(want_err)) => anyhow::bail!(
                "expected to get io::Error {} but instead got file {}",
                errno_description(want_err),
                handle.as_file().as_unsafe_path_unchecked()?.display(),
            ),

            (Err(err), Err(want_err)) => {
                assert_eq!(
                    err.kind(),
                    want_err,
                    "expected io::Error {}, got '{}'",
                    errno_description(want_err),
                    err,
                );
                return Ok(());
            }
        };

        let expected_path = expected_path.trim_start_matches('/');
        let real_handle_path = handle.as_file().as_unsafe_path_unchecked()?;
        assert_eq!(
            real_handle_path,
            root_dir.join(expected_path),
            "resolve({unsafe_path:?}, {no_follow_trailing}) path mismatch",
        );

        let meta = handle.as_file().metadata()?;
        let real_file_type = meta.st_mode() & libc::S_IFMT;
        assert_eq!(real_file_type, expected_file_type, "file type mismatch",);

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

        Ok(())
    }
}

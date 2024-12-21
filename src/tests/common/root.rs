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

use std::{fs, os::unix::fs as unixfs, path::Path};

use crate::syscalls;

use anyhow::{Context, Error};
use rustix::fs::{self as rustix_fs, AtFlags, OFlags, CWD};
use tempfile::TempDir;

// TODO: Make these macros usable from outside this crate...

macro_rules! create_inode {
    // "/foo/bar" @ chmod 0o755
    (@do $path:expr, chmod $mode:expr) => {
        // rustix returns -EOPNOTSUPP if you use AT_SYMLINK_NOFOLLOW.
        rustix_fs::chmodat(CWD, $path, $mode.into(), AtFlags::empty())
            .with_context(|| format!("chmod 0o{:o} {}", $mode, $path.display()))?;
    };

    // "/foo/bar" @ chown 0:0
    (@do $path:expr, chown $uid:literal : $gid:literal) => {
        rustix_fs::chownat(
            CWD,
            $path,
            // SAFETY: We pick valid uids and gids for this.
            Some(unsafe { ::rustix::process::Uid::from_raw($uid) }),
            Some(unsafe { ::rustix::process::Gid::from_raw($gid) }),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .with_context(|| format!("chown {}:{} {}", $uid, $gid, $path.display()))?;
    };

    // "/foo/bar" @ chown 0:
    (@do $path:expr, chown $uid:literal :) => {
        rustix_fs::chownat(
            CWD,
            $path,
            // SAFETY: We pick valid uids and gids for this.
            Some(unsafe { ::rustix::process::Uid::from_raw($uid) }),
            None,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .with_context(|| format!("chown {}:<none> {}", $uid, $path.display()))?;
    };

    // "/foo/bar" @ chown :0
    (@do $path:expr, chown : $gid:literal) => {
        rustix_fs::chownat(
            CWD,
            $path,
            // SAFETY: We pick valid uids and gids for this.
            None,
            Some(unsafe { ::rustix::process::Gid::from_raw($gid) }),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .with_context(|| format!("chown <none>:{} {}", $gid, $path.display()))?;
    };

    // "/foo/bar" => dir
    ($path:expr => dir $(,{$($extra:tt)*})*) => {
        rustix_fs::mkdir($path, 0o755.into())
            .with_context(|| format!("mkdir {}", $path.display()))?;
        $(
            create_inode!(@do $path, $($extra)*);
        )*
    };
    // "/foo/bar" => file
    ($path:expr => file $(,{$($extra:tt)*})*) => {
        rustix_fs::open($path, OFlags::CREATE, 0o644.into())
            .with_context(|| format!("mkfile {}", $path.display()))?;
        $(
            create_inode!(@do $path, $($extra)*);
        )*
    };
    // "/foo/bar" => fifo
    ($path:expr => fifo $(, {$($extra:tt)*})*) => {
        syscalls::mknodat(rustix_fs::CWD, $path, libc::S_IFIFO | 0o644, 0)
            .with_context(|| format!("mkfifo {}", $path.display()))?;
        $(
            create_inode!(@do $path, $($extra)*);
        )*
    };
    // "/foo/bar" => sock
    ($path:expr => sock $(,{$($extra:tt)*})*) => {
        syscalls::mknodat(rustix_fs::CWD, $path, libc::S_IFSOCK | 0o644, 0)
            .with_context(|| format!("mksock {}", $path.display()))?;
        $(
            create_inode!(@do $path, $($extra)*);
        )*
    };
    // "/foo/bar" => symlink -> "target"
    ($path:expr => symlink -> $target:expr $(,{$($extra:tt)*})*) => {
        unixfs::symlink($target, $path)
            .with_context(|| format!("symlink {} -> {}", $path.display(), $target))?;
        $(
            create_inode!(@do $path, $($extra)*);
        )*
    };
    // "/foo/bar" => hardlink -> "target"
    ($path:expr => hardlink -> $target:expr) => {
        fs::hard_link($target, $path)
            .with_context(|| format!("hardlink {} -> {}", $path.display(), $target))?;
    };
}

macro_rules! create_tree {
    // create_tree! {
    //     "a" => (dir);
    //     "a/b/c" => (file);
    //     "b-link" => (symlink -> "a/b");
    // }
    ($($subpath:expr => $(#[$meta:meta])* ($($inner:tt)*));+ $(;)*) => {
        {
            let root = TempDir::new()?;
            $(
                $(#[$meta])*
                {
                    let root_dir: &Path = root.as_ref();
                    let subpath = $subpath;
                    let path = root_dir.join(subpath.trim_start_matches('/'));
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).with_context(|| format!("mkdirall {}", path.display()))?;
                    }
                    create_inode!(&path => $($inner)*);
                }
            )*
            root
        }
    }
}

pub(crate) fn create_basic_tree() -> Result<TempDir, Error> {
    Ok(create_tree! {
        // Basic inodes.
        "a" => (dir);
        "b/c/d/e/f" => (dir);
        "b/c/file" => (file);
        "e" => (symlink -> "/b/c/d/e");
        "b-file" => (symlink -> "b/c/file");
        "root-link1" => (symlink -> "/");
        "root-link2" => (symlink -> "/..");
        "root-link3" => (symlink -> "/../../../../..");
        "escape-link1" => (symlink -> "../../../../../../../../../../target");
        "escape-link2" => (symlink -> "/../../../../../../../../../../target");
        // Some "bad" inodes that non-privileged users can create.
        "b/fifo" => (fifo);
        "b/sock" => (sock);
        // Dangling symlinks.
        "a-fake1" => (symlink -> "a/fake");
        "a-fake2" => (symlink -> "a/fake/foo/bar/..");
        "a-fake3" => (symlink -> "a/fake/../../b");
        "c/a-fake1" => (symlink -> "/a/fake");
        "c/a-fake2" => (symlink -> "/a/fake/foo/bar/..");
        "c/a-fake3" => (symlink -> "/a/fake/../../b");
        // Non-lexical symlinks.
        "target" => (dir);
        "link1/target_abs" => (symlink -> "/target");
        "link1/target_rel" => (symlink -> "../target");
        "link2/link1_abs" => (symlink -> "/link1");
        "link2/link1_rel" => (symlink -> "../link1");
        "link3/target_abs" => (symlink -> "/link2/link1_rel/target_rel");
        "link3/target_rel" => (symlink -> "../link2/link1_rel/target_rel");
        "link3/deep_dangling1" => (symlink -> "../link2/link1_rel/target_rel/nonexist");
        "link3/deep_dangling2" => (symlink -> "../link2/link1_abs/target_abs/nonexist");
        // Deep dangling symlinks (with single components).
        "dangling/a" => (symlink -> "b/c");
        "dangling/b/c" => (symlink -> "../c");
        "dangling/c" => (symlink -> "d/e");
        "dangling/d/e" => (symlink -> "../e");
        "dangling/e" => (symlink -> "f/../g");
        "dangling/f" => (dir);
        "dangling/g" => (symlink -> "h/i/j/nonexistent");
        "dangling/h/i/j" => (dir);
        // Deep dangling symlinks using a non-dir component.
        "dangling-file/a" => (symlink -> "b/c");
        "dangling-file/b/c" => (symlink -> "../c");
        "dangling-file/c" => (symlink -> "d/e");
        "dangling-file/d/e" => (symlink -> "../e");
        "dangling-file/e" => (symlink -> "f/../g");
        "dangling-file/f" => (dir);
        "dangling-file/g" => (symlink -> "h/i/j/file/foo");
        "dangling-file/h/i/j/file" => (file);
        // Symlink loops.
        "loop/basic-loop1" => (symlink -> "basic-loop1");
        "loop/basic-loop2" => (symlink -> "/loop/basic-loop2");
        "loop/basic-loop3" => (symlink -> "../loop/basic-loop3");
        "loop/a/link" => (symlink -> "../b/link");
        "loop/b/link" => (symlink -> "/loop/c/link");
        "loop/c/link" => (symlink -> "/loop/d/link");
        "loop/d" => (symlink -> "e");
        "loop/e/link" => (symlink -> "../a/link");
        "loop/link" => (symlink -> "a/link");
        // Symlinks in a world-writable directory (fs.protected_symlinks).
        // ... owned by us.
        "tmpfs-self" => (dir, {chmod 0o1777});
        "tmpfs-self/file" => (file);
        "tmpfs-self/link-self" => (symlink -> "file");
        "tmpfs-self/link-otheruid" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown 12345:});
        "tmpfs-self/link-othergid" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown :12345});
        "tmpfs-self/link-other" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown 12345:12345});
        // ... owned by another user.
        "tmpfs-other" => #[cfg(feature = "_test_as_root")] (dir, {chown 12345:12345}, {chmod 0o1777});
        "tmpfs-other/file" => #[cfg(feature = "_test_as_root")] (file);
        "tmpfs-other/link-self" => #[cfg(feature = "_test_as_root")] (symlink -> "file");
        "tmpfs-other/link-selfuid" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown :11111});
        "tmpfs-other/link-owner" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown 12345:12345});
        "tmpfs-other/link-otheruid" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown 11111:12345});
        "tmpfs-other/link-othergid" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown 12345:11111});
        "tmpfs-other/link-other" => #[cfg(feature = "_test_as_root")] (symlink -> "file", {chown 11111:11111});
        // setgid has unique behaviour when interacting with mkdir_all.
        "setgid-self" => (dir, {chmod 0o7777});
        "setgid-other" => #[cfg(feature = "_test_as_root")] (dir, {chown 12345:12345}, {chmod 0o7777});
    })
}

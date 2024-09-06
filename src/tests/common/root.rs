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

use std::{
    ffi::CString,
    fs, io,
    os::unix::{ffi::OsStrExt, fs as unixfs},
    path::Path,
};

use anyhow::{Context, Error};
use rustix::fs::{self as rustix_fs, OFlags};
use tempfile::TempDir;

fn mknod<P: AsRef<Path>>(path: P, mode: libc::mode_t, dev: libc::dev_t) -> Result<(), io::Error> {
    let path = CString::new(path.as_ref().as_os_str().as_bytes()).expect("CString::new failed");
    // SAFETY: Obviously safe-to-use Linux syscall.
    let ret = unsafe { libc::mknod(path.as_ptr(), mode, dev) };
    let err = io::Error::last_os_error();

    if ret >= 0 {
        Ok(())
    } else {
        Err(err)
    }
}

macro_rules! create_inode {
    // "/foo/bar" => dir
    ($path:expr => dir) => {
        rustix_fs::mkdir($path, 0o755.into()).with_context(|| format!("mkdir {}", $path.display()))
    };
    // "/foo/bar" => file
    ($path:expr => file) => {
        rustix_fs::open($path, OFlags::CREATE, 0o644.into())
            .with_context(|| format!("mkfile {}", $path.display()))
    };
    // "/foo/bar" => fifo
    ($path:expr => fifo) => {
        mknod($path, libc::S_IFIFO | 0o644, 0)
            .with_context(|| format!("mkfifo {}", $path.display()))
    };
    // "/foo/bar" => sock
    ($path:expr => sock) => {
        mknod($path, libc::S_IFSOCK | 0o644, 0)
            .with_context(|| format!("mksock {}", $path.display()))
    };
    // "/foo/bar" => symlink -> "target"
    ($path:expr => symlink -> $target:expr) => {
        unixfs::symlink($target, $path)
            .with_context(|| format!("symlink {} -> {}", $path.display(), $target))
    };
    // "/foo/bar" => hardlink -> "target"
    ($path:expr => hardlink -> $target:expr) => {
        fs::hard_link($target, $path)
            .with_context(|| format!("hardlink {} -> {}", $path.display(), $target))
    };
}

macro_rules! create_tree {
    // create_tree! {
    //     "a" => (dir);
    //     "a/b/c" => (file);
    //     "b-link" => (symlink -> "a/b");
    // }
    ($($subpath:expr => ($($inner:tt)*));+ $(;)*) => {
        {
            let root = TempDir::new()?;
            $(
                {
                    let root_dir: &Path = root.as_ref();
                    let subpath = $subpath;
                    let path = root_dir.join(subpath.trim_start_matches('/'));
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).with_context(|| format!("mkdirall {}", path.display()))?;
                    }
                    create_inode!(&path => $($inner)*)?;
                }
            )*
            Ok(root)
        }
    }
}

pub fn create_basic_tree() -> Result<TempDir, Error> {
    create_tree! {
        // Basic inodes.
        "a" => (dir);
        "b/c/d/e/f" => (dir);
        "b/c/file" => (file);
        "e" => (symlink -> "/b/c/d/e");
        "b-file" => (symlink -> "b/c/file");
        "root-link1" => (symlink -> "/");
        "root-link2" => (symlink -> "/..");
        "root-link3" => (symlink -> "/../../../../..");
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
    }
}

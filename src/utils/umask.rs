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
    error::{Error, ErrorImpl},
    flags::OpenFlags,
    procfs::{ProcfsBase, ProcfsHandle},
    syscalls,
};

use std::{
    env,
    io::{BufRead, BufReader},
};

use libc::mode_t;
use regex::Regex;

/// Get the current process's umask from `/proc/thread-self/status`.
// There has been a Umask: field in /proc/self/status since Linux 4.7.
// See commit 3e42979e65da ("procfs: expose umask in /proc/<PID>/status").
//
//NOTE: While the umask is shared between threads, it unshared with `CLONE_FS`
//      so a single thread could have a different umask to other threads.
fn get_umask_procfs(procfs: &ProcfsHandle) -> Result<Option<mode_t>, Error> {
    // MSRV(1.70): Use OnceLock.
    // MSRV(1.80): Use LazyLock.
    // TODO: Figure out if we even need to use a regex for this. Surely there's
    //       something like sscanf which works properly in Rust...
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^Umask:\s*(0[0-7]+)$").unwrap();
    }

    let status_file = procfs.open(ProcfsBase::ProcThreadSelf, "status", OpenFlags::O_RDONLY)?;
    let reader = BufReader::new(status_file);
    for line in reader.lines() {
        let line = line.map_err(|err| ErrorImpl::OsError {
            operation: "read lines from /proc/self/status".into(),
            source: err,
        })?;
        // MSRV(1.65): Use let-else here.
        if let Some((_, [umask])) = RE.captures(&line).map(|caps| caps.extract()) {
            return Ok(Some(
                mode_t::from_str_radix(umask, 8).expect("parsing 0[0-7]+ octal should work"),
            ));
        }
    }
    Ok(None)
}

/// Get the current process's umask by creating a file and checking which bits
/// were cleared due to the umask.
fn get_umask_tmpfile() -> Result<mode_t, Error> {
    // O_TMPFILE was added in Linux v3.11. See commit 60545d0d4610 ("[O_TMPFILE]
    // it's still short a few helpers, but infrastructure should be OK now...").
    let fd = syscalls::openat(
        syscalls::AT_FDCWD,
        env::temp_dir(),
        libc::O_TMPFILE | libc::O_RDWR,
        0o777,
    )
    .map_err(|err| ErrorImpl::RawOsError {
        operation: "create O_TMPFILE".into(),
        source: err,
    })?;
    // TODO: Use tempfile to create a named temporary file as a backup. This
    // would let us support pre-3.11 kernels. Ideally setting permissions with
    // O_TMPFILE would be supported by the tempfile crate, see this issue:
    // <https://github.com/Stebalien/tempfile/issues/292>

    let actual_mode = syscalls::fstatat(fd, "")
        .map_err(|err| ErrorImpl::RawOsError {
            operation: "fstat temporary file".into(),
            source: err,
        })?
        .st_mode;

    Ok(0o777 ^ actual_mode & 0o777)
}

/// Get the current thread's umask (umask is not strictly thread-specific, but
/// it is unshared with `CLONE_FS` so it could be different between threads).
pub(crate) fn get_umask(procfs: Option<&ProcfsHandle>) -> Result<mode_t, Error> {
    match procfs
        .map(get_umask_procfs)
        .transpose()
        .map(Option::flatten)
    {
        Ok(Some(umask)) => Ok(umask),
        _ => get_umask_tmpfile(),
    }
    // NOTE: There is an infallible mechanism for doing this (umask(2)), however
    // it is not safe to call from within a multi-threaded program because
    // umask(2) modifies the existing umask which could result in other threads
    // producing bad or forking threads to spawn processes with unexpected
    // umasks. This is also true for CLONE_FS processes, so even single-threaded
    // programs can run into this issue.
}

#[cfg(test)]
mod tests {
    use super::{get_umask, get_umask_procfs, get_umask_tmpfile};
    use crate::procfs::GLOBAL_PROCFS_HANDLE;

    #[test]
    fn umask_default() {
        assert_eq!(
            get_umask_tmpfile().unwrap(),
            get_umask_procfs(&GLOBAL_PROCFS_HANDLE).unwrap().unwrap(),
            "tmpfile and procfs should give same results"
        );
        assert_eq!(
            get_umask(None).unwrap(),
            get_umask_procfs(&GLOBAL_PROCFS_HANDLE).unwrap().unwrap(),
            "default and procfs should give same results"
        );
        assert_eq!(
            get_umask(Some(&GLOBAL_PROCFS_HANDLE)).unwrap(),
            get_umask_tmpfile().unwrap(),
            "default and tmpfile should give same results"
        );
    }

    // TODO: Figure out a way to test this properly. Ideally we would set the
    // umask to a random value and check that we get the right value. However,
    // "cargo test" runs tests in separate threads. We can't temporarily
    // `unshare(CLONE_FS)` and there's no way to nicely kill that thread so that
    // it doesn't break other threads with `CLONE_FS`.
    //
    // nextest does run each test in a separate process, but AFAICS there is no
    // cfg(...) we could use to mark tests as ignored unless you use nextest.
}

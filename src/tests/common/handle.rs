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
    flags::OpenFlags,
    tests::{
        common as tests_common,
        traits::{ErrorImpl, HandleImpl},
    },
    utils::FdExt,
};

use anyhow::{Context, Error};
use errno::Errno;
use pretty_assertions::assert_eq;
use rustix::{
    fs::{self as rustix_fs, OFlags},
    io::{self as rustix_io, FdFlags},
};

pub type LookupResult<'a> = (&'a str, libc::mode_t);

pub(in crate::tests) fn errno_description(err: ErrorKind) -> String {
    match err {
        ErrorKind::OsError(Some(errno)) => format!("{err:?} ({})", Errno(errno)),
        _ => format!("{err:?}"),
    }
}

pub(in crate::tests) fn check_reopen<H: HandleImpl>(
    handle: H,
    flags: OpenFlags,
    expected_error: Option<i32>,
) -> Result<(), Error> {
    let expected_error = expected_error.map(|errno| ErrorKind::OsError(Some(errno)));
    let file = match (handle.reopen(flags), expected_error) {
        (Ok(f), None) => f,
        (Err(e), None) => anyhow::bail!("unexpected error '{}'", e),
        (Ok(f), Some(want_err)) => anyhow::bail!(
            "expected to get io::Error {} but instead got file {}",
            tests_common::errno_description(want_err),
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

    let real_handle_path = handle.as_unsafe_path_unchecked()?;
    let real_reopen_path = file.as_unsafe_path_unchecked()?;

    assert_eq!(
        real_handle_path, real_reopen_path,
        "reopened handle should be equivalent to old handle",
    );

    let clone_handle = handle.try_clone()?;
    let clone_handle_path = clone_handle.as_unsafe_path_unchecked()?;

    assert_eq!(
        real_handle_path, clone_handle_path,
        "cloned handle should be equivalent to old handle",
    );

    // Convert to OFlags so we can compare them.
    let mut wanted_flags = OFlags::from_bits_retain(flags.bits() as u32);
    // Add O_CLOEXEC to the set of wanted flags if the HandleImpl forces it.
    if H::FORCED_CLOEXEC {
        wanted_flags.insert(OFlags::CLOEXEC);
    }

    // Check regular file flags.
    let got_file_flags = rustix_fs::fcntl_getfl(&file).context("failed to F_GETFL")?;
    assert_eq!(
        // Ignore O_LARGEFILE since it's basically a kernel internal.
        got_file_flags & !OFlags::LARGEFILE,
        // O_CLOEXEC is represented in the fd flags, not file flags.
        wanted_flags & !OFlags::CLOEXEC,
        "expected the reopened file's flags to match the requested flags"
    );

    // Check fd flags (namely O_CLOEXEC).
    let got_fd_flags = rustix_io::fcntl_getfd(&file).context("failed to F_GETFD")?;
    assert_eq!(
        got_fd_flags.contains(FdFlags::CLOEXEC),
        wanted_flags.contains(OFlags::CLOEXEC),
        "expected the reopened file's O_CLOEXEC to be correct (oflags: {:?}, is O_CLOEXEC forced? {})",
        flags, H::FORCED_CLOEXEC,
    );

    Ok(())
}

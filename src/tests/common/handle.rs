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
    resolvers::PartialLookup,
    tests::{common as tests_common, traits::HandleImpl},
    utils::FdExt,
};

use std::os::unix::io::AsFd;

use anyhow::{Context, Error};
use pretty_assertions::assert_eq;
use rustix::{
    fs::{self as rustix_fs, OFlags},
    io::{self as rustix_io, FdFlags},
};

pub type LookupResult<'a> = (&'a str, libc::mode_t);

impl<H, E> PartialLookup<H, E> {
    pub(in crate::tests) fn as_inner_handle(&self) -> &H {
        match self {
            PartialLookup::Complete(handle) => handle,
            PartialLookup::Partial { handle, .. } => handle,
        }
    }
}

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

pub(in crate::tests) fn check_oflags<Fd: AsFd>(fd: Fd, flags: OpenFlags) -> Result<(), Error> {
    let fd = fd.as_fd();

    // Convert to OFlags so we can compare them.
    let mut wanted_flags = OFlags::from_bits_retain(flags.bits() as u32);
    // O_CLOEXEC is always automatically enabled by libpathrs.
    wanted_flags.insert(OFlags::CLOEXEC);

    // The kernel clears several flags from f_flags in do_dentry_open(), so we
    // need to drop them from the expected flag set.
    wanted_flags.remove(OFlags::CREATE | OFlags::EXCL | OFlags::NOCTTY | OFlags::TRUNC);

    // Check regular file flags.
    let got_file_flags = rustix_fs::fcntl_getfl(fd).context("failed to F_GETFL")?;
    assert_eq!(
        // Ignore O_LARGEFILE since it's basically a kernel internal.
        got_file_flags & !OFlags::LARGEFILE,
        // O_CLOEXEC is represented in the fd flags, not file flags.
        wanted_flags & !OFlags::CLOEXEC,
        "expected the reopened file's flags to match the requested flags"
    );

    // Check fd flags (namely O_CLOEXEC).
    let got_fd_flags = rustix_io::fcntl_getfd(fd).context("failed to F_GETFD")?;
    assert_eq!(
        got_fd_flags.contains(FdFlags::CLOEXEC),
        wanted_flags.contains(OFlags::CLOEXEC),
        "expected the reopened file's O_CLOEXEC to be correct (oflags: {flags:?})",
    );
    assert!(
        got_fd_flags.difference(FdFlags::CLOEXEC).is_empty(),
        "expected fd flags to not contain anything other than FD_CLOEXEC (got flags: 0x{:x})",
        got_fd_flags.bits()
    );

    Ok(())
}

pub(in crate::tests) fn check_reopen<H: HandleImpl>(
    handle: H,
    flags: OpenFlags,
    expected_error: Option<i32>,
) -> Result<(), Error> {
    let expected_error = match expected_error {
        None => Ok(()),
        Some(errno) => Err(ErrorKind::OsError(Some(errno))),
    };

    let file = match (handle.reopen(flags), expected_error) {
        (Ok(f), Ok(_)) => f,
        (result, expected) => {
            let result = match result {
                Ok(file) => Ok(file.as_unsafe_path_unchecked()?),
                Err(err) => Err(err),
            };

            tests_common::check_err(&result, &expected)
                .with_context(|| format!("reopen handle {flags:?}"))?;

            assert!(
                result.is_err(),
                "we should never see an Ok(file) after check_err if we expected {expected:?}"
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

    check_oflags(
        &file,
        // NOTE: Handle::reopen() drops O_NOFOLLOW, so we shouldn't see it.
        flags.difference(OpenFlags::O_NOFOLLOW),
    )?;

    Ok(())
}

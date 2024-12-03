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

use crate::{error::ErrorKind, tests::traits::ErrorImpl};

use std::fmt::Debug;

use anyhow::Error;

pub(in crate::tests) fn check_err<T1, Err1, T2>(
    result: &Result<T1, Err1>,
    expected: &Result<T2, ErrorKind>,
) -> Result<(), Error>
where
    T1: Debug,
    Err1: ErrorImpl,
    T2: Debug,
{
    let result = result.as_ref();
    let expected = expected.as_ref();

    match (result, expected) {
        (Err(error), Err(expected_kind)) => {
            let kind = error.kind();
            if kind != *expected_kind {
                anyhow::bail!(
                    "expected error {expected_kind:?} but got {error:?} (kind: {kind:?})"
                );
            }
        }
        (Ok(_), Ok(_)) => (),
        (result, expected) => anyhow::bail!("expected {expected:?} but got {result:?}"),
    }
    Ok(())
}

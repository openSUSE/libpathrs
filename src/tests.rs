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

pub(crate) mod common {
    mod root;
    pub(crate) use root::*;

    mod mntns;
    pub(in crate::tests) use mntns::*;

    mod handle;
    pub(in crate::tests) use handle::*;

    mod error;
    pub(in crate::tests) use error::*;
}

#[cfg(feature = "capi")]
#[allow(unsafe_code)]
pub(in crate::tests) mod capi {
    mod utils;

    mod root;
    pub(in crate::tests) use root::*;

    mod handle;
    pub(in crate::tests) use handle::*;

    mod procfs;
    pub(in crate::tests) use procfs::*;
}

pub(in crate::tests) mod traits {
    // TODO: Unless we can figure out a way to get Deref working, we might want
    // to have these traits be included in the actual library...

    mod root;
    pub(in crate::tests) use root::*;

    mod handle;
    pub(in crate::tests) use handle::*;

    mod procfs;
    pub(in crate::tests) use procfs::*;

    mod error;
    pub(in crate::tests) use error::*;
}

mod test_procfs;
mod test_resolve;
mod test_resolve_partial;
mod test_root_ops;

mod test_race_resolve_partial;

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

use crate::{flags::OpenFlags, syscalls, utils::FdExt};

use std::{
    fs::File,
    os::unix::io::{AsFd, AsRawFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Error};
use rustix::{
    mount::{self as rustix_mount, MountFlags, MountPropagationFlags},
    thread::{self as rustix_thread, LinkNameSpaceType, UnshareFlags},
};

#[derive(Debug, Clone)]
pub(crate) enum MountType {
    Tmpfs,
    Bind { src: PathBuf },
}

pub(in crate::tests) fn mount<P: AsRef<Path>>(dst: P, ty: MountType) -> Result<(), Error> {
    let dst = dst.as_ref();
    let dst_file = syscalls::openat(
        syscalls::AT_FDCWD,
        dst,
        OpenFlags::O_NOFOLLOW | OpenFlags::O_PATH,
        0,
    )?;
    let dst_path = format!("/proc/self/fd/{}", dst_file.as_raw_fd());

    match ty {
        MountType::Tmpfs => rustix_mount::mount2(
            None::<&Path>,
            &dst_path,
            Some("tmpfs"),
            MountFlags::empty(),
            None,
        )
        .with_context(|| {
            format!(
                "mount tmpfs on {:?}",
                dst_file
                    .as_unsafe_path_unchecked()
                    .unwrap_or(dst_path.into())
            )
        }),
        MountType::Bind { src } => {
            let src_file = syscalls::openat(
                syscalls::AT_FDCWD,
                src,
                OpenFlags::O_NOFOLLOW | OpenFlags::O_PATH,
                0,
            )?;
            let src_path = format!("/proc/self/fd/{}", src_file.as_raw_fd());
            rustix_mount::mount_bind(&src_path, &dst_path).with_context(|| {
                format!(
                    "bind-mount {:?} -> {:?}",
                    src_file
                        .as_unsafe_path_unchecked()
                        .unwrap_or(src_path.into()),
                    dst_file
                        .as_unsafe_path_unchecked()
                        .unwrap_or(dst_path.into())
                )
            })
        }
    }
}

pub(in crate::tests) fn in_mnt_ns<F, T>(func: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
{
    let old_ns = File::open("/proc/self/ns/mnt")?;

    // TODO: Run this in a subprocess.

    rustix_thread::unshare(UnshareFlags::FS | UnshareFlags::NEWNS)
        .expect("unable to create a mount namespace");

    // Mark / as MS_SLAVE to avoid DoSing the host.
    rustix_mount::mount_change(
        "/",
        MountPropagationFlags::SLAVE | MountPropagationFlags::REC,
    )?;

    let ret = func();

    rustix_thread::move_into_link_name_space(old_ns.as_fd(), Some(LinkNameSpaceType::Mount))
        .expect("unable to rejoin old namespace");

    ret
}

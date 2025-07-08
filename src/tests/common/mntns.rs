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

use anyhow::{bail, Context, Error};
use rustix::{
    mount::{self as rustix_mount, MountFlags, MountPropagationFlags},
    thread::{self as rustix_thread, LinkNameSpaceType, UnshareFlags},
};

#[derive(Debug, Clone)]
pub(crate) enum MountType {
    Tmpfs,
    Bind { src: PathBuf },
    RebindWithFlags { flags: MountFlags },
}

// TODO: NOSYMFOLLOW is not exported for the libc backend of rustix. Until this
// is fixed by <https://github.com/bytecodealliance/rustix/pull/1471> we need to
// hardcode the value here. Thanfully, it has the same value for all
// architectures.
pub(in crate::tests) const NOSYMFOLLOW: MountFlags = MountFlags::from_bits_retain(0x100); // From <linux/mount.h>.

fn are_vfs_flags(flags: MountFlags) -> bool {
    flags
        .difference(
            // MS_RDONLY can be both a vfsmount and sb flag, but if we're operating
            // using MS_BIND then it acts like a vfs flag.
            MountFlags::RDONLY |
        // These NO* flags are all per-vfsmount flags.
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC | NOSYMFOLLOW |
        // Except LAZYATIME, these are all per-vfsmount flags.
        MountFlags::NOATIME | MountFlags::NODIRATIME | MountFlags::RELATIME,
        )
        .is_empty()
}

pub(in crate::tests) fn mount(dst: impl AsRef<Path>, ty: MountType) -> Result<(), Error> {
    let dst = dst.as_ref();
    let dst_file = syscalls::openat(
        syscalls::AT_FDCWD,
        dst,
        OpenFlags::O_NOFOLLOW | OpenFlags::O_PATH,
        0,
    )?;
    let dst_path = format!("/proc/self/fd/{}", dst_file.as_raw_fd());

    match ty {
        MountType::Tmpfs => rustix_mount::mount("", &dst_path, "tmpfs", MountFlags::empty(), None)
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
        MountType::RebindWithFlags { flags } => {
            if !are_vfs_flags(flags) {
                bail!("rebind-with-flags mount options {flags:?} contains non-vfsmount flags");
            }

            // Create a bind-mount first for us to apply our mount flags to.
            rustix_mount::mount_bind_recursive(&dst_path, &dst_path).with_context(|| {
                format!(
                    "bind-mount {:?} to self",
                    dst_file
                        .as_unsafe_path_unchecked()
                        .unwrap_or(dst_path.clone().into())
                )
            })?;

            // We need to re-open the path because the handle references the
            // dentry below the mount, and so MS_REMOUNT will return -EINVAL if
            // we don't get a new handle.
            // TODO: Would be nice to be able to do reopen(O_PATH|O_NOFOLLOW).
            let dst_file = syscalls::openat(
                syscalls::AT_FDCWD,
                dst,
                OpenFlags::O_NOFOLLOW | OpenFlags::O_PATH,
                0,
            )?;
            let dst_path = format!("/proc/self/fd/{}", dst_file.as_raw_fd());

            // Then apply our mount flags.
            rustix_mount::mount_remount(&dst_path, MountFlags::BIND | flags, "").with_context(
                || {
                    format!(
                        "vfs-remount {:?} with {flags:?}",
                        dst_file
                            .as_unsafe_path_unchecked()
                            .unwrap_or(dst_path.into())
                    )
                },
            )
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

    // Mark / as MS_SLAVE ("DOWNSTREAM" in rustix) to avoid DoSing the host.
    rustix_mount::mount_change(
        "/",
        MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC,
    )?;

    let ret = func();

    rustix_thread::move_into_link_name_space(old_ns.as_fd(), Some(LinkNameSpaceType::Mount))
        .expect("unable to rejoin old namespace");

    ret
}

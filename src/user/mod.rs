/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019 SUSE LLC
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! libpathrs::user implements an emulated version of the openat(2) patchset's
//! features. The primary method by which this is done is through shameless
//! abuse of procfs and O_PATH magic-links. The basic idea is that we need to
//! perform all of the path resolution steps (walking down the set of
//! components, handling the effect of symlinks on the resolution, etc).
//!
//! In order to do this safely we need to verify after the walk is done whether
//! the path of the final file descriptor is what we expected (most importantly,
//! is it inside the root which we started the walk with?). This check is done
//! through readlink(/proc/self/fd/$n), which is a magic kernel interface which
//! gives you the kernel's view of the path -- and in cases where the kernel is
//! unsure or otherwise unhappy you get "/".
//!
//! If the check fails, we assume we are being attacked and return an error (and
//! the caller can decide to re-try if they want). The kernel implementation
//! will fail in fewer cases because it has access to in-kernel locks and other
//! measures, but the final check throgh procfs should block all attack
//! attempts.

use crate::{
    syscalls,
    utils::{FileExt, PATH_SEPARATOR},
};
use crate::{Error, Handle, Root};

use core::convert::TryFrom;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Error as IOError;
use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
use std::path::{Component, Path, PathBuf};

use failure::{Error as FailureError, ResultExt};

/// Maximum number of symlink traversals we will accept.
const MAX_SYMLINK_TRAVERSALS: usize = 128;

/// Ensure that the expected path within the root matches the current fd.
fn check_current<P: AsRef<Path>>(
    current: &File,
    root: &Root,
    expected: P,
) -> Result<(), FailureError> {
    // Combine the root path and our expected_path to get the full path to
    // compare current against.
    let full_path: PathBuf = root.as_ref().join(
        expected
            .as_ref()
            .components()
            // At this point, expected_path should only have Normal components.
            // If there are any other components we can just ignore them because
            // this expected_path check will probably fail.
            .filter(|c| match c {
                Component::Normal(_) => true,
                _ => false,
            })
            .collect::<PathBuf>(),
    );

    // Does /proc/self/fd agree with us? There are several circumstances where
    // this check might give a false positive (namely, if the kernel decides
    // that the path is not ordinarily resolveable). But if this check passes,
    // then we can be fairly sure (barring kernel bugs) that the path was safe
    // at least one point in time.
    let current_path = current
        .as_path()
        .context("check fd against expected path")?;
    if current_path != full_path {
        return Err(Error::SafetyViolation("fd doesn't match expected path"))?;
    }
    Ok(())
}

/// Resolve `path` within `root` through user-space emulation.
pub fn resolve<P: AsRef<Path>>(root: &Root, path: P) -> Result<Handle, FailureError> {
    let path = path.as_ref();

    // What is the final path we expect to get after we do the final open? This
    // allows us to track any attacker moving path components around and we can
    // sanity-check at the very end. This does not include rootpath.
    let mut expected_path = PathBuf::from(Component::RootDir.as_os_str());

    // We only need to keep track of our current dirfd, since we are applying
    // the components one-by-one, and can always switch back to the root
    // if we hit an absolute symlink.
    let mut current = root
        .try_clone_hotfix()
        .context("dup root as starting point")?;

    // Get initial set of components from the passed path. We remove  all components
    let mut components: VecDeque<_> = path
        .components()
        .map(|p| PathBuf::from(p.as_os_str()))
        .collect();

    let mut symlink_traversals = 0;
    while let Some(part) = components.pop_front() {
        // XXX: Thanks to borrowck, we can't seem to just store Component in our
        //      VecDeque. So we need to do a dirty conversion back to Component.
        //      But we are definitely sure there is at only one component.
        let part = part
            .components()
            .next()
            .expect("components should have one entry");

        // Ensure that we only got the components we wanted, and generate a
        // tentative expected_path.
        match part {
            Component::Normal(part) => {
                // This part might be a symlink, but we clean that up later.
                expected_path.push(part);

                // Ensure that part doesn't contain any "/"s. It's critical we
                // are only touching the final component in the path. If there
                // are any other path components we must bail. This shouldn't
                // ever happen, but it's better to be safe.
                if part.as_bytes().contains(&PATH_SEPARATOR) {
                    return Err(Error::SafetyViolation(
                        "component of path resolution contains '/'",
                    ))?;
                }
            }
            Component::ParentDir => {
                // All of expected_path is non-symlinks, so we can treat ".."
                // lexically. If pop() fails, then we are at the root and we
                // must ignore this ".." component.
                if !expected_path.pop() {
                    continue;
                }
            }
            // Just skip any other components.
            _ => continue,
        };

        // Get our next element.
        let next = syscalls::openat(current.as_raw_fd(), part, libc::O_PATH, 0)
            .context("open next component of resolution")?;

        // Make sure that the path is what we expect. If not, there was a racing
        // rename and we should bail out here -- otherwise we might be tricked
        // into revealing information outside the rootfs through errors or
        // timing-related attacks.
        //
        // The safety argument for only needing to check ".." is identical to
        // the kernel implementation (namely, walking down is safe
        // by-definition). However, unlike the in-kernel version we don't have
        // the luxury of only doing this check when there was a racing rename --
        // we have to do it every time.
        if part == Component::ParentDir {
            check_current(&next, root, &expected_path)
                .context("check next '..' component didn't escape")?;
        }

        // Is the next dirfd a symlink or an ordinary path?
        // NOTE: File::metadata definitely does an fstat(2) here.
        let next_type = next.metadata().context("fstat of next")?.file_type();

        // If we're an ordinary dirent, we just update current and move on
        // to the next component. Nothing special here.
        if !next_type.is_symlink() {
            current = next;
            continue;
        }

        // Check if it's safe for us to touch. In principle this should never be
        // an actual security issue (since we readlink(2) the symlink) but it's
        // much better to be safe than sorry here.
        if next
            .is_dangerous()
            .context("check if next is on a dangerous filesystem")?
        {
            return Err(Error::SafetyViolation(
                "next is a symlink on a dangerous filesystem",
            ))?;
        }

        // We need a limit on the number of symlinks we traverse to avoid
        // hitting filesystem loops and DoSing.
        symlink_traversals += 1;
        if symlink_traversals >= MAX_SYMLINK_TRAVERSALS {
            return Err(IOError::from_raw_os_error(libc::ELOOP))
                .context("too many symlinks encountered during resolution")?;
        }

        // XXX: There is currently no way for us to use next to get the
        //      contents of the symlink. /proc/self/fd will just give us the
        //      path to the symlink. However, since readlink(2) doesn't follow
        //      symlink components we can just do it manually safely.
        let contents = syscalls::readlinkat(current.as_raw_fd(), part)?;

        // Add contents of the symlink to the set of components we are looping
        // over. The
        contents
            .components()
            .map(|p| PathBuf::from(p.as_os_str()))
            // VecDeque doesn't have an amortized way of prepending a Vec, so we
            // need to do this manually. We need to rev() the iterator since
            // we're pushing to the front each time.
            .rev()
            .for_each(|p| components.push_front(p));

        // Remove our tentative expected_path contents. They will be filled on
        // later iterations. If the path is absolute we need to reset our
        // current back to the root.
        expected_path.pop();
        if contents.is_absolute() {
            current = root
                .try_clone_hotfix()
                .context("dup root as next current")?;
        }
    }

    // Make sure that the path is what we expect...
    check_current(&current, root, &expected_path).context("check final handle didn't escape")?;

    // Make sure the root path is still correct.
    root.check()?;

    // Everything is Kosher here -- convert to a handle.
    Handle::try_from(current)
}

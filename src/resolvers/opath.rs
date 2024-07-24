/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

//! libpathrs::opath implements an emulated version of openat2(RESOLVE_IN_ROOT).
//! The primary method by which this is done is through shameless abuse of
//! procfs and O_PATH magic-links. The basic idea is that we need to perform all
//! of the path resolution steps (walking down the set of components, handling
//! the effect of symlinks on the resolution, etc).
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
    error::{self, Error, ErrorExt},
    resolvers::ResolverFlags,
    syscalls,
    utils::{FileExt, RawComponentsIter, RawFdExt},
    Handle,
};

use std::{
    collections::VecDeque,
    fs::File,
    io::Error as IOError,
    os::unix::{ffi::OsStrExt, io::AsRawFd},
    path::{Path, PathBuf},
    rc::Rc,
};

use snafu::ResultExt;

/// Maximum number of symlink traversals we will accept.
const MAX_SYMLINK_TRAVERSALS: usize = 128;

/// Ensure that the expected path within the root matches the current fd.
fn check_current<P: AsRef<Path>>(current: &File, root: &File, expected: P) -> Result<(), Error> {
    // SAFETY: as_unsafe_path is safe here since we're using it to build a path
    //         for a string-based check as part of a larger safety setup. This
    //         path will be re-checked after the unsafe "current_path" is
    //         generated.
    let root_path = root
        .as_unsafe_path()
        .wrap("get root path to construct expected path")?;

    // Combine the root path and our expected_path to get the full path to
    // compare current against.
    let full_path: PathBuf = root_path.join(
        expected
            .as_ref()
            .raw_components()
            // At this point, expected_path should only have Normal components.
            // If there are any other components we can just ignore them because
            // this expected_path check will probably fail.
            // NOTE: PathBuf::push() does not normalise components.
            .collect::<PathBuf>(),
    );

    // Does /proc/self/fd agree with us? There are several circumstances where
    // this check might give a false positive (namely, if the kernel decides
    // that the path is not ordinarily resolveable). But if this check passes,
    // then we can be fairly sure (barring kernel bugs) that the path was safe
    // at least one point in time.
    // SAFETY: as_unsafe_path is safe here since we're explicitly doing a
    //         string-based check to see whether the path we want is correct.
    let current_path = current
        .as_unsafe_path()
        .wrap("check fd against expected path")?;

    // The paths should be identical.
    ensure!(
        current_path == full_path,
        error::SafetyViolationSnafu {
            description: "fd doesn't match expected path"
        }
    );

    // And the root should not have moved. Note that this check could (in
    // theory) be bypassed by an attacker -- so it important that users be aware
    // that allowing roots to be moved by an attacker is a very bad idea.
    // SAFETY: as_unsafe_path path is safe here because it's just used in a
    //         string check -- and it's known that this check isn't perfect.
    let new_root_path = root
        .as_unsafe_path()
        .wrap("get root path to double-check it hasn't moved")?;
    ensure!(
        root_path == new_root_path,
        error::SafetyViolationSnafu {
            description: "root moved during lookup"
        }
    );

    Ok(())
}

/// Resolve `path` within `root` through user-space emulation.
pub(crate) fn resolve<P: AsRef<Path>>(
    root: &File,
    path: P,
    flags: ResolverFlags,
) -> Result<Handle, Error> {
    let path = path.as_ref();

    // What is the final path we expect to get after we do the final open? This
    // allows us to track any attacker moving path components around and we can
    // sanity-check at the very end. This does not include rootpath.
    let mut expected_path = PathBuf::from("/");

    // We only need to keep track of our current dirfd, since we are applying
    // the components one-by-one, and can always switch back to the root
    // if we hit an absolute symlink.
    let root = Rc::new(root.try_clone_hotfix().wrap("dup root as starting point")?);
    let mut current = Rc::clone(&root);

    // Get initial set of components from the passed path. We remove components
    // as we do the path walk, and update them with the contents of any symlinks
    // we encounter. Path walking terminates when there are no components left.
    let mut remaining_components = path
        .raw_components()
        .map(|p| p.to_os_string())
        .collect::<VecDeque<_>>();

    let mut symlink_traversals = 0;
    while let Some(part) = remaining_components
        .pop_front()
        // If we hit an empty component, we need to treat it as though it is
        // "." so that trailing "/" and "//" components on a non-directory
        // correctly return the right error code.
        .map(|part| if part.is_empty() { ".".into() } else { part })
    {
        // Ensure that we only got the components we wanted, and generate a
        // tentative expected_path.
        match part.as_bytes() {
            b"" => unreachable!(),
            // For "." component we don't touch expected_path, but we do try to
            // do the open (to return the correct openat2-compliant error if the
            // current path is a not directory).
            b"." => {}
            b".." => {
                // All of expected_path is non-symlinks, so we can treat ".."
                // lexically. If pop() fails, then we are at the root and we
                // must ignore this ".." component.
                if !expected_path.pop() {
                    current = Rc::clone(&root);
                    continue;
                }
            }
            _ => {
                // This part might be a symlink, but we clean that up later.
                expected_path.push(&part);

                // Ensure that part doesn't contain any "/"s. It's critical we
                // are only touching the final component in the path. If there
                // are any other path components we must bail. This shouldn't
                // ever happen, but it's better to be safe.
                ensure!(
                    !part.as_bytes().contains(&b'/'),
                    error::SafetyViolationSnafu {
                        description: "component of path resolution contains '/'",
                    }
                );
            }
        };

        // Get our next element.
        let next = syscalls::openat(
            current.as_raw_fd(),
            &part,
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
        )
        .context(error::RawOsSnafu {
            operation: "open next component of resolution",
        })?;

        // Make sure that the path is what we expect. If not, there was a racing
        // rename and we should bail out here -- otherwise we might be tricked
        // into revealing information outside the rootfs through error or
        // timing-related attacks.
        //
        // The safety argument for only needing to check ".." is identical to
        // the kernel implementation (namely, walking down is safe
        // by-definition). However, unlike the in-kernel version we don't have
        // the luxury of only doing this check when there was a racing rename --
        // we have to do it every time.
        if part.as_bytes() == b".." {
            check_current(&next, root.as_ref(), &expected_path)
                .wrap("check next '..' component didn't escape")?;
        }

        // Is the next dirfd a symlink or an ordinary path?
        // NOTE: File::metadata definitely does an fstat(2) here.
        let next_type = next
            .metadata()
            .context(error::OsSnafu {
                operation: "fstat of next component",
            })?
            .file_type();

        // If we're an ordinary dirent, we just update current and move on
        // to the next component. Nothing special here.
        if !next_type.is_symlink() {
            // TODO: Use an enum to avoid making a needless Rc for this case.
            current = Rc::new(next);
            continue;
        }

        // Don't continue walking if user asked for no symlinks.
        if flags.contains(ResolverFlags::NO_SYMLINKS) {
            return error::SafetyViolationSnafu {
                description: "next is a symlink and symlink resolution disabled",
            }
            .fail();
        }

        // Check if it's safe for us to touch. In principle this should
        // never be an actual security issue (since we readlink(2) the
        // symlink) but it's much better to be safe than sorry here.
        if next
            .is_dangerous()
            .wrap("check if next is on a dangerous filesystem")?
        {
            return error::SafetyViolationSnafu {
                description: "next is a symlink on a dangerous filesystem",
            }
            .fail();
        }

        // We need a limit on the number of symlinks we traverse to
        // avoid hitting filesystem loops and DoSing.
        symlink_traversals += 1;
        if symlink_traversals >= MAX_SYMLINK_TRAVERSALS {
            return Err(IOError::from_raw_os_error(libc::ELOOP)).context(error::OsSnafu {
                operation: "emulated symlink resolution",
            })?;
        }

        let link_target =
            syscalls::readlinkat(next.as_raw_fd(), "").context(error::RawOsSnafu {
                operation: "readlink next symlink component",
            })?;

        // Remove the link component from our expectex path.
        expected_path.pop();

        // Add contents of the symlink to the set of components we are looping
        // over.
        link_target
            .raw_components()
            .prepend(&mut remaining_components);

        // Absolute symlinks reset our current state.
        if link_target.is_absolute() {
            current = Rc::clone(&root);
            expected_path = PathBuf::from("/");
        }
    }

    // Make sure that the path is what we expect...
    check_current(&current, &*root, &expected_path).wrap("check final handle didn't escape")?;

    // Drop root in case current is a reference to it.
    std::mem::drop(root);
    // We are now sure that there is only a single reference to whatever current
    // points to. There is nowhere else we could've stashed a reference, and we
    // only do Rc::clone for root (which we've dropped).
    let current = Rc::into_inner(current)
        .expect("current handle in lookup should only have a single Rc reference");

    // Everything is Kosher here -- convert to a handle.
    Ok(Handle::from_file_unchecked(current))
}

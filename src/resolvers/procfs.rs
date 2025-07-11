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

//!
//! [`ProcfsResolver`](crate::resolvers::procfs::ProcfsResolver) is a very
//! minimal resolver that doesn't allow:
//!
//!  1. Any ".." components (with `openat2` this is slightly relaxed).
//!  2. Any absolute symlinks.
//!  3. (If `statx` or `openat2` is supported), any mount-point crossings.
//!
//! This allows us to avoid using any `/proc` checks, and thus this resolver can
//! be used within the `pathrs::procfs` helpers that are used by other parts of
//! libpathrs.

use crate::{
    error::{Error, ErrorExt, ErrorImpl},
    flags::{OpenFlags, ResolverFlags},
    procfs,
    resolvers::MAX_SYMLINK_TRAVERSALS,
    syscalls::{self, OpenHow},
    utils::{self, FdExt, PathIterExt, RawProcfsRoot},
};

use std::{
    collections::VecDeque,
    io::Error as IOError,
    os::unix::{
        ffi::OsStrExt,
        io::{AsFd, OwnedFd},
    },
    path::Path,
};

/// Used internally for tests to force the usage of a specific resolver. You
/// should always use the default.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProcfsResolver {
    Openat2,
    RestrictedOpath,
}

impl Default for ProcfsResolver {
    fn default() -> Self {
        if *syscalls::OPENAT2_IS_SUPPORTED {
            Self::Openat2
        } else {
            Self::RestrictedOpath
        }
    }
}

impl ProcfsResolver {
    pub(crate) fn resolve(
        &self,
        proc_rootfd: RawProcfsRoot<'_>,
        root: impl AsFd,
        path: impl AsRef<Path>,
        oflags: OpenFlags,
        rflags: ResolverFlags,
    ) -> Result<OwnedFd, Error> {
        // These flags don't make sense for procfs and will just result in
        // confusing errors during lookup. O_TMPFILE contains multiple flags
        // (including O_DIRECTORY!) so we have to check it separately.
        let invalid_flags = OpenFlags::O_CREAT | OpenFlags::O_EXCL;
        if !oflags.intersection(invalid_flags).is_empty() || oflags.contains(OpenFlags::O_TMPFILE) {
            Err(ErrorImpl::InvalidArgument {
                name: "flags".into(),
                description: format!(
                    "invalid flags {:?} specified",
                    oflags.intersection(invalid_flags)
                )
                .into(),
            })?
        }

        match *self {
            Self::Openat2 => openat2_resolve(root, path, oflags, rflags),
            Self::RestrictedOpath => opath_resolve(proc_rootfd, root, path, oflags, rflags),
        }
    }
}

/// [`openat2`][openat2.2]-based implementation of [`ProcfsResolver`].
///
/// [openat2.2]: https://www.man7.org/linux/man-pages/man2/openat2.2.html
fn openat2_resolve(
    root: impl AsFd,
    path: impl AsRef<Path>,
    oflags: OpenFlags,
    rflags: ResolverFlags,
) -> Result<OwnedFd, Error> {
    if !*syscalls::OPENAT2_IS_SUPPORTED {
        Err(ErrorImpl::NotSupported {
            feature: "openat2".into(),
        })?
    }

    // Copy the O_NOFOLLOW and RESOLVE_NO_SYMLINKS bits from rflags.
    let oflags = oflags.bits() as u64;
    let rflags =
        libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV | rflags.bits();

    syscalls::openat2_follow(
        root,
        path,
        OpenHow {
            flags: oflags,
            resolve: rflags,
            ..Default::default()
        },
    )
    .map_err(|err| {
        ErrorImpl::RawOsError {
            operation: "open subpath in procfs".into(),
            source: err,
        }
        .into()
    })
}

/// `O_PATH`-based implementation of [`ProcfsResolver`].
fn opath_resolve(
    proc_rootfd: RawProcfsRoot<'_>,
    root: impl AsFd,
    path: impl AsRef<Path>,
    oflags: OpenFlags,
    rflags: ResolverFlags,
) -> Result<OwnedFd, Error> {
    let root = root.as_fd();
    let root_mnt_id = utils::fetch_mnt_id(proc_rootfd, root, "")?;

    // We only need to keep track of our current dirfd, since we are applying
    // the components one-by-one.
    let mut current = root
        .try_clone_to_owned()
        .map_err(|err| ErrorImpl::OsError {
            operation: "dup root handle as starting point of resolution".into(),
            source: err,
        })?;

    // In order to match the behaviour of RESOLVE_BENEATH, we need to error out
    // if we get asked to resolve an absolute path.
    let path = path.as_ref();
    if path.is_absolute() {
        Err(ErrorImpl::OsError {
            operation: "emulated RESOLVE_BENEATH".into(),
            source: IOError::from_raw_os_error(libc::EXDEV),
        })
        .wrap(format!(
            "requested subpath {path:?} is absolute but this is forbidden by RESOLVE_BENEATH",
        ))?
    }

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
        // We cannot walk into ".." without checking if there was a breakout
        // with /proc (a-la opath::resolve) so return an error if we hit "..".
        if part.as_bytes() == b".." {
            Err(ErrorImpl::OsError {
                operation: "step into '..'".into(),
                source: IOError::from_raw_os_error(libc::EXDEV),
            })
            .wrap("cannot walk into '..' with restricted procfs resolver")?
        }

        // Get our next element.
        let next = syscalls::openat(
            &current,
            &part,
            OpenFlags::O_PATH | OpenFlags::O_NOFOLLOW,
            0,
        )
        .map_err(|err| ErrorImpl::RawOsError {
            operation: "open next component of resolution".into(),
            source: err,
        })?;

        // Check that the next component is on the same mountpoint.
        // NOTE: If the root is the host /proc mount, this is only safe if there
        // are no racing mounts.
        procfs::verify_same_mnt(proc_rootfd, root_mnt_id, &next, "")
            .with_wrap(|| format!("open next component {part:?}"))
            .wrap("emulated procfs resolver RESOLVE_NO_XDEV")?;

        let next_meta = next.metadata().wrap("fstat of next component")?;

        // If this is the last component, try to open the same component again
        // with with the requested flags. Unlike the other Handle resolvers, we
        // can't re-open the file through procfs (since this is the resolver
        // used for procfs lookups) so we need to do it this way.
        //
        // Because we force O_NOFOLLOW for safety reasons, we can't just blindly
        // return the error we get from openat here (in particular, if the user
        // specifies O_PATH or O_DIRECTORY without O_NOFOLLOW, you will get the
        // wrong results). The following is a table of the relevant cases.
        //
        // Each entry of the form [a](b) means that the user expects [a] to
        // happen but because of O_NOFOLLOW we get (b). **These are the cases
        // which we need to handle with care.**
        //
        //                   symlink        directory    other-file
        //
        // OPATH         [cont](ret-sym) *1    ret           ret
        // ODIR          [cont](ENOTDIR) *2    ret         ENOTDIR
        // OPATH|ODIR    [cont](ENOTDIR) *3    ret         ENOTDIR
        // ONF               ELOOP             ret           ret
        // ONF|OPATH        ret-sym      *4    ret           ret
        // ONF|ODIR         ENOTDIR            ret         ENOTDIR
        // ONF|OPATH|ODIR   ENOTDIR            ret         EDOTDIR
        //
        // Legend:
        // - Flags:
        //   - OPATH = O_PATH, ODIR = O_DIRECTORY, ONF = O_NOFOLLOW
        // - Actions:
        //   - ret     = return this handle as the final component
        //   - ret-sym = return this *symlink* handle as the final component
        //   - cont    = continue iterating (for symlinks)
        //   - EFOO    = returns an error EFOO
        //
        // Unfortunately, note that you -ENOTDIR for most of the file and
        // symlink cases, but we need to differentiate between them. That's why
        // we need to do the O_PATH|O_NOFOLLOW first -- we need to figure out
        // whether we are dealing with a symlink or not. If we are dealing with
        // a symlink, we want to continue walking in all cases (except plain
        // O_NOFOLLOW and O_DIRECTORY|O_NOFOLLOW).
        //
        // NOTE: There is a possible race here -- the file type might've changed
        // after we opened it. This is unlikely under procfs because the
        // structure is basically static (an attacker could bind-mount something
        // but we detect bind-mounts already), but even if it did happen the
        // worst case result is that we return an error.
        //
        // NOTE: Most of these cases don't apply to the ProcfsResolver because
        // it handles trailing-symlink follows manually and auto-applies
        // O_NOFOLLOW if the trailing component is not a symlink. However, we
        // handle them all for correctness reasons (and we have tests for the
        // resolver itself to verify the behaviour).
        if remaining_components.is_empty()
            // Case (*1):
            // If the user specified *just* O_PATH (without O_NOFOLLOW nor
            // O_DIRECTORY), we can continue to parse as normal (if next_type is
            // a non-symlink we will return it, if it is a symlink we will
            // continue walking).
            && oflags.intersection(OpenFlags::O_PATH | OpenFlags::O_NOFOLLOW | OpenFlags::O_DIRECTORY) != OpenFlags::O_PATH
        {
            match syscalls::openat(&current, &part, oflags | OpenFlags::O_NOFOLLOW, 0) {
                Ok(final_reopen) => {
                    // Re-verify the next component is on the same mount.
                    procfs::verify_same_mnt(proc_rootfd, root_mnt_id, &final_reopen, "")
                        .wrap("re-open final component")
                        .wrap("emulated procfs resolver RESOLVE_NO_XDEV")?;
                    return Ok(final_reopen);
                }
                Err(err) => {
                    // Cases (*2) and (*3):
                    //
                    // If all of the following are true:
                    //
                    //  1. The user didn't ask for O_NOFOLLOW.
                    //  2. The user did ask for O_DIRECTORY.
                    //  3. The error is ENOTDIR.
                    //  4. The next component was a symlink.
                    //
                    // We want to continue walking, rather than return an error.
                    if oflags.contains(OpenFlags::O_NOFOLLOW)
                        || !oflags.contains(OpenFlags::O_DIRECTORY)
                        || err.root_cause().raw_os_error() != Some(libc::ENOTDIR)
                        || !next_meta.is_symlink()
                    {
                        Err(ErrorImpl::RawOsError {
                            operation: format!("open last component of resolution with {oflags:?}")
                                .into(),
                            source: err,
                        })?
                    }
                }
            }
        }

        // Is the next dirfd a symlink or an ordinary path? If we're an ordinary
        // dirent, we just update current and move on to the next component.
        // Nothing special here.
        if !next_meta.is_symlink() {
            current = next;
            continue;
        }

        // Don't continue walking if user asked for no symlinks.
        if rflags.contains(ResolverFlags::NO_SYMLINKS) {
            Err(ErrorImpl::OsError {
                operation: "emulated symlink resolution".into(),
                source: IOError::from_raw_os_error(libc::ELOOP),
            })
            .wrap(format!(
                "component {part:?} is a symlink but symlink resolution is disabled",
            ))?
        }

        // We need a limit on the number of symlinks we traverse to avoid
        // hitting filesystem loops and DoSing.
        //
        // Given all of the other restrictions of this lookup code, it seems
        // unlikely that you could even run into a symlink loop (procfs doesn't
        // have regular symlink loops) but we should avoid it just in case.
        symlink_traversals += 1;
        if symlink_traversals >= MAX_SYMLINK_TRAVERSALS {
            Err(ErrorImpl::OsError {
                operation: "emulated symlink resolution".into(),
                source: IOError::from_raw_os_error(libc::ELOOP),
            })
            .wrap("exceeded symlink limit")?
        }

        let link_target = syscalls::readlinkat(&next, "").map_err(|err| ErrorImpl::RawOsError {
            operation: "readlink next symlink component".into(),
            source: err,
        })?;

        // The hardened resolver is called using a root that is a subdir of
        // /proc (such as /proc/self or /proc/thread-self), so it makes no sense
        // to try to scope absolute symlinks. Also, we shouldn't expect to walk
        // into an absolute symlink (which is almost certainly a magic-link --
        // though we can't detect that directly without openat2).
        if link_target.is_absolute() {
            Err(ErrorImpl::OsError {
                operation: "emulated RESOLVE_NO_MAGICLINKS".into(),
                source: IOError::from_raw_os_error(libc::ELOOP),
            })
            .wrap(format!("step into absolute symlink {link_target:?}"))
            .wrap("cannot walk into absolute symlinks with restricted procfs resolver")?
        }

        link_target
            .raw_components()
            .prepend(&mut remaining_components);
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use crate::{
        error::{Error as PathrsError, ErrorKind},
        flags::{OpenFlags, ResolverFlags},
        resolvers::procfs::ProcfsResolver,
        syscalls,
        tests::common as tests_common,
        utils::{FdExt, RawProcfsRoot},
    };

    use std::{fs::File, path::PathBuf};

    use anyhow::Error;

    type ExpectedResult = Result<PathBuf, ErrorKind>;

    macro_rules! procfs_resolver_tests {
        ($($test_name:ident ($root:expr, $path:expr, $($oflag:ident)|+, $rflags:expr) == $expected_result:expr);* $(;)?) => {
            $(
                paste::paste! {
                    #[test]
                    fn [<procfs_openat2_resolver_ $test_name>]() -> Result<(), Error> {
                        if !*syscalls::OPENAT2_IS_SUPPORTED {
                            // skip test
                            return Ok(());
                        }
                        let root_dir: PathBuf = $root.into();
                        let root = File::open(&root_dir)?;
                        let expected: ExpectedResult = $expected_result.map(|p: PathBuf| root_dir.join(p));
                        let oflags = $(OpenFlags::$oflag)|*;
                        let res = ProcfsResolver::Openat2
                            .resolve(RawProcfsRoot::UnsafeGlobal, &root, $path, oflags, $rflags)
                            .as_ref()
                            .map(|f| {
                                f.as_unsafe_path_unchecked()
                                    .expect("get actual path of resolved handle")
                            })
                            .map_err(PathrsError::kind);
                        assert_eq!(
                            res, expected,
                            "expected resolve({:?}, {:?}, {:?}, {:?}) to give {:?}, got {:?}",
                            $root, $path, oflags, $rflags, expected, res
                        );
                        Ok(())
                    }

                    #[test]
                    fn [<procfs_opath_resolver_ $test_name>]() -> Result<(), Error> {
                        let root_dir: PathBuf = $root.into();
                        let root = File::open(&root_dir)?;
                        let expected: ExpectedResult = $expected_result.map(|p: PathBuf| root_dir.join(p));
                        let oflags = $(OpenFlags::$oflag)|*;
                        let res = ProcfsResolver::RestrictedOpath
                            .resolve(RawProcfsRoot::UnsafeGlobal, &root, $path, oflags, $rflags)
                            .as_ref()
                            .map(|f| {
                                f.as_unsafe_path_unchecked()
                                    .expect("get actual path of resolved handle")
                            })
                            .map_err(PathrsError::kind);
                        assert_eq!(
                            res, expected,
                            "expected resolve({:?}, {:?}, {:?}, {:?}) to give {:?}, got {:?}",
                            $root, $path, oflags, $rflags, expected, res
                        );
                        Ok(())
                    }
                }
            )*
        };
    }

    procfs_resolver_tests! {
        xdev("/", "proc", O_DIRECTORY, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::EXDEV)));
        xdev_dotdot("/proc", "..", O_DIRECTORY, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::EXDEV)));
        xdev_abs_slash("/proc", "/", O_DIRECTORY, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::EXDEV)));
        xdev_abs_path("/proc", "/etc/passwd", O_DIRECTORY, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::EXDEV)));
        bad_flag_ocreat("/tmp", "foobar", O_CREAT|O_RDWR, ResolverFlags::empty()) == Err(ErrorKind::InvalidArgument);
        bad_flag_otmpfile("/tmp", "foobar", O_TMPFILE|O_RDWR, ResolverFlags::empty()) == Err(ErrorKind::InvalidArgument);

        // Check RESOLVE_NO_SYMLINKS handling.
        resolve_no_symlinks1("/proc", "self", O_DIRECTORY, ResolverFlags::NO_SYMLINKS) == Err(ErrorKind::OsError(Some(libc::ELOOP)));
        resolve_no_symlinks2("/proc", "self/status", O_RDONLY, ResolverFlags::NO_SYMLINKS) == Err(ErrorKind::OsError(Some(libc::ELOOP)));
        resolve_no_symlinks3("/proc", "self/../cgroups", O_RDONLY, ResolverFlags::NO_SYMLINKS) == Err(ErrorKind::OsError(Some(libc::ELOOP)));

        // Check symlink loops.
        symloop(tests_common::create_basic_tree()?.keep(), "loop/basic-loop1", O_PATH, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ELOOP)));
        symloop_opath_onofollow(tests_common::create_basic_tree()?.keep(), "loop/basic-loop1", O_PATH|O_NOFOLLOW, ResolverFlags::empty()) == Ok("loop/basic-loop1".into());

        // Check that our {O_PATH, O_NOFOLLOW, O_DIRECTORY} logic is correct,
        // based on the table in opath_resolve().

        // OPATH         [cont](ret)     *1    ret           ret
        sym_opath("/proc", "self", O_PATH, ResolverFlags::empty()) == Ok(format!("/proc/{}", syscalls::getpid()).into());
        dir_opath("/proc", "tty", O_PATH, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_opath("/proc", "filesystems", O_PATH, ResolverFlags::empty()) == Ok("/proc/filesystems".into());
        // ODIR          [cont](ENOTDIR) *2    ret         ENOTDIR
        sym_odir("/proc", "self", O_DIRECTORY, ResolverFlags::empty()) == Ok(format!("/proc/{}", syscalls::getpid()).into());
        dir_odir("/proc", "tty", O_DIRECTORY, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_odir("/proc", "filesystems", O_DIRECTORY, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        // OPATH|ODIR    [cont](ENOTDIR) *3    ret         ENOTDIR
        sym_opath_odir("/proc", "self", O_PATH|O_DIRECTORY, ResolverFlags::empty()) == Ok(format!("/proc/{}", syscalls::getpid()).into());
        dir_opath_odir("/proc", "tty", O_PATH|O_DIRECTORY, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_opath_odir("/proc", "filesystems", O_PATH|O_DIRECTORY, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        // ONF               ELOOP             ret           ret
        sym_onofollow("/proc", "self", O_NOFOLLOW, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ELOOP)));
        dir_onofollow("/proc", "tty", O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_onofollow("/proc", "filesystems", O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/filesystems".into());
        // ONF|OPATH        ret-sym            ret           ret
        sym_opath_onofollow("/proc", "self", O_PATH|O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/self".into());
        dir_opath_onofollow("/proc", "tty", O_PATH|O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_opath_onofollow("/proc", "filesystems", O_PATH|O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/filesystems".into());
        // ONF|ODIR         ENOTDIR            ret         ENOTDIR
        sym_odir_onofollow("/proc", "self", O_DIRECTORY|O_NOFOLLOW, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        dir_odir_onofollow("/proc", "tty", O_DIRECTORY|O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_odir_onofollow("/proc", "filesystems", O_DIRECTORY|O_NOFOLLOW, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        // ONF|OPATH|ODIR   ENOTDIR            ret         EDOTDIR
        sym_opath_odir_onofollow("/proc", "self", O_PATH|O_DIRECTORY|O_NOFOLLOW, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
        dir_opath_odir_onofollow("/proc", "tty", O_PATH|O_DIRECTORY|O_NOFOLLOW, ResolverFlags::empty()) == Ok("/proc/tty".into());
        file_opath_odir_onofollow("/proc", "filesystems", O_PATH|O_DIRECTORY|O_NOFOLLOW, ResolverFlags::empty()) == Err(ErrorKind::OsError(Some(libc::ENOTDIR)));
    }
}

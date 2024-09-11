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
    error::{Error, ErrorExt, ErrorImpl},
    flags::OpenFlags,
    procfs::ProcfsHandle,
};

use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    str::FromStr,
};

pub(crate) fn sysctl_read_line(procfs: &ProcfsHandle, sysctl: &str) -> Result<String, Error> {
    // "/proc/sys"
    let mut sysctl_path = PathBuf::from("sys");
    // Convert "foo.bar.baz" to "foo/bar/baz".
    sysctl_path.push(sysctl.replace(".", "/"));

    let sysctl_file = procfs.open_raw(sysctl_path, OpenFlags::O_RDONLY)?;

    // Just read the first line.
    let mut reader = BufReader::new(sysctl_file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|err| ErrorImpl::OsError {
            operation: format!("read first line of {sysctl:?} sysctl").into(),
            source: err,
        })?;

    // Strip newlines.
    Ok(line.trim_end_matches("\n").into())
}

pub(crate) fn sysctl_read_parse<T>(procfs: &ProcfsHandle, sysctl: &str) -> Result<T, Error>
where
    T: FromStr,
    Error: From<T::Err>,
{
    sysctl_read_line(procfs, sysctl).and_then(|s| {
        s.parse()
            .map_err(Error::from)
            .with_wrap(|| format!("could not parse int sysctl {sysctl:?}"))
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        error::{Error, ErrorKind},
        procfs::GLOBAL_PROCFS_HANDLE,
    };

    #[test]
    fn bad_sysctl_file_noexist() {
        assert!(matches!(
            super::sysctl_read_line(&GLOBAL_PROCFS_HANDLE, "nonexistent.dummy.sysctl.path")
                .as_ref()
                .map_err(Error::kind),
            Err(ErrorKind::OsError(Some(libc::ENOENT)))
        ));
        assert!(matches!(
            super::sysctl_read_parse::<u32>(&GLOBAL_PROCFS_HANDLE, "nonexistent.sysctl.path")
                .as_ref()
                .map_err(Error::kind),
            Err(ErrorKind::OsError(Some(libc::ENOENT)))
        ));
    }

    #[test]
    fn bad_sysctl_file_noread() {
        assert!(matches!(
            super::sysctl_read_line(&GLOBAL_PROCFS_HANDLE, "vm.drop_caches")
                .as_ref()
                .map_err(Error::kind),
            Err(ErrorKind::OsError(Some(libc::EACCES)))
        ));
        assert!(matches!(
            super::sysctl_read_parse::<u32>(&GLOBAL_PROCFS_HANDLE, "vm.drop_caches")
                .as_ref()
                .map_err(Error::kind),
            Err(ErrorKind::OsError(Some(libc::EACCES)))
        ));
    }

    #[test]
    fn bad_sysctl_parse_invalid_multinumber() {
        assert!(super::sysctl_read_line(&GLOBAL_PROCFS_HANDLE, "kernel.printk").is_ok());
        assert!(matches!(
            super::sysctl_read_parse::<u32>(&GLOBAL_PROCFS_HANDLE, "kernel.printk")
                .as_ref()
                .map_err(Error::kind),
            Err(ErrorKind::ParseError)
        ));
    }

    #[test]
    fn bad_sysctl_parse_invalid_nonnumber() {
        assert!(super::sysctl_read_line(&GLOBAL_PROCFS_HANDLE, "kernel.random.uuid").is_ok());
        assert!(matches!(
            super::sysctl_read_parse::<u32>(&GLOBAL_PROCFS_HANDLE, "kernel.random.uuid")
                .as_ref()
                .map_err(Error::kind),
            Err(ErrorKind::ParseError)
        ));
    }

    #[test]
    fn sysctl_parse_int() {
        assert!(super::sysctl_read_line(&GLOBAL_PROCFS_HANDLE, "kernel.pid_max").is_ok());
        assert!(super::sysctl_read_parse::<u64>(&GLOBAL_PROCFS_HANDLE, "kernel.pid_max").is_ok());
    }
}

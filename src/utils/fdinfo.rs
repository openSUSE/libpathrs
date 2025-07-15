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
    error::{Error, ErrorExt, ErrorImpl, ErrorKind},
    utils::FdExt,
};

use std::{
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::{
        fs::MetadataExt,
        io::{AsFd, AsRawFd},
    },
    str::FromStr,
};

/// Parse a `/proc/self/fdinfo` file contents and return the first value that
/// matches `want_field_name`.
fn parse_and_find_fdinfo_field<T>(
    rdr: &mut impl Read,
    want_field_name: &str,
) -> Result<Option<T>, Error>
where
    T: FromStr,
    T::Err: Into<Error>,
{
    let rdr = BufReader::new(rdr);

    // The fdinfo format is:
    //   name:\tvalue1
    //   othername:\tvalue2
    //   foo_bar_baz:\tvalue3
    let want_prefix = format!("{want_field_name}:");
    for line in rdr.lines() {
        let line = line.map_err(|err| ErrorImpl::OsError {
            operation: "read line from fdinfo".into(),
            source: err,
        })?;

        // In practice, field names won't contain colons, but we can provide
        // more flexibility (and a simpler implementation) if we just treat the
        // value section (with a colon) as a simple prefix to strip. Also, the
        // separator is basically always tab, but stripping all whitespace is
        // probably better.
        if let Some(value) = line.strip_prefix(&want_prefix) {
            // return the first line that matches
            return value.trim().parse().map(Some).map_err(Into::into);
        }
    }

    // field not found
    Ok(None)
}

/// Parse a `/proc/self/fdinfo` file, and fetch the first value that matches
/// `want_field_name`, with some extra verification.
///
/// This function will verify that the `fdinfo` file contains an `ino` field
/// that matches the actual inode number of the passed `fd`. This is intended to
/// make it very difficult for an attacker to create a convincingly fake
/// `fdinfo` file (as a final fallback for `RESOLVE_NO_XDEV` emulation).
pub(crate) fn fd_get_verify_fdinfo<T>(
    rdr: &mut (impl Read + Seek),
    fd: impl AsFd,
    want_field_name: &str,
) -> Result<Option<T>, Error>
where
    T: FromStr,
    T::Err: Into<Error>,
{
    let fd = fd.as_fd();

    // Verify that the "ino" field in fdinfo matches the real inode number
    // of our file descriptor. This makes attacks harder (if not near
    // impossible, outside of very constrained situations):
    //
    //  * An attacker would probably struggle to always accurately guess the inode
    //    number of files that the process is trying to operate on. Yes, if they
    //    know the victim process's access patterns of procfs they could probably
    //    make an educated guess, but most files do not have stable inode numbers in
    //    procfs.
    //
    //  * An attacker can no longer bind-mount their own fdinfo directory with just
    //    a buch of handles to "/proc" open (assuming the attacker is trying to
    //    spoof "mnt_id"), because the inode numbers won't match.
    //
    //    They also can't really fake inode numbers in real procfs fdinfo
    //    files, so they would need to create fake fdinfo files using
    //    individual file arbitrary-data gadgets (like /proc/self/environ).
    //    However, every program only has one environment so they would need
    //    to create a new child process for every fd they are trying to
    //    attack simultaneously (and accurately update their environment
    //    data to avoid detection).
    //
    // This isn't perfect protection by any means, but it's probably the
    // best we can do for very old kernels (given the constraints). At the very
    // least, it makes exploitation _much_ harder than if we didn't do anything
    // at all.
    let actual_ino: u64 = fd.metadata().wrap("get inode number of fd")?.ino();
    let fdinfo_ino: u64 =
        match parse_and_find_fdinfo_field(rdr, "ino").map_err(|err| (err.kind(), err)) {
            Ok(Some(ino)) => Ok(ino),
            // "ino" *must* exist as a field -- make sure we return a
            // SafetyViolation here if it is missing or an invalid value
            // (InternalError), otherwise an attacker could silence this check
            // by creating a "ino"-less fdinfo.
            // TODO: Should we actually match for ErrorImpl::ParseIntError here?
            Ok(None) | Err((ErrorKind::InternalError, _)) => Err(ErrorImpl::SafetyViolation {
                description: format!(
                    r#"fd {:?} has a fake fdinfo: invalid or missing "ino" field"#,
                    fd.as_raw_fd(),
                )
                .into(),
            }
            .into()),
            // Pass through any other errors.
            Err((_, err)) => Err(err),
        }?;
    if actual_ino != fdinfo_ino {
        Err(ErrorImpl::SafetyViolation {
                description: format!(
                    "fd {:?} has a fake fdinfo: wrong inode number (ino is {fdinfo_ino:X} not {actual_ino:X})",
                    fd.as_raw_fd()
                )
                .into(),
            })?;
    }

    // Reset the position in the fdinfo file, and re-parse it to look for
    // the requested field.
    rdr.seek(SeekFrom::Start(0))
        .map_err(|err| ErrorImpl::OsError {
            operation: format!("seek to start of fd {:?} fdinfo", fd.as_raw_fd()).into(),
            source: err,
        })?;
    parse_and_find_fdinfo_field(rdr, want_field_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    use std::{
        fmt::Debug,
        fs::File,
        io::Cursor,
        net::{AddrParseError, Ipv4Addr, SocketAddrV4},
    };

    use anyhow::{bail, Context, Error};
    use indoc::{formatdoc, indoc};
    use pretty_assertions::{assert_matches, Comparison};

    impl From<AddrParseError> for ErrorImpl {
        fn from(err: AddrParseError) -> Self {
            unimplemented!("this test-only impl is only needed for type reasons -- {err:?}")
        }
    }

    fn check_parse_and_find_fdinfo_field<T>(
        rdr: &mut impl Read,
        want_field_name: &str,
        expected: Result<Option<T>, ErrorKind>,
    ) -> Result<(), Error>
    where
        T: FromStr + PartialEq + Debug,
        T::Err: Into<Error> + Into<ErrorImpl>,
    {
        let got = match parse_and_find_fdinfo_field(rdr, want_field_name) {
            Ok(res) => Ok(res),
            Err(err) => {
                if expected.is_ok() {
                    // Don't panic yet -- this is just for debugging purposes.
                    eprintln!("unexpected error: {err:?}");
                }
                Err(err.kind())
            }
        };

        if got != expected {
            eprintln!("{}", Comparison::new(&got, &expected));
            bail!(
                "unexpected result when parsing {want_field_name:?} field (as {:?}) from fdinfo (should be {expected:?})",
                std::any::type_name::<T>()
            );
        }

        Ok(())
    }

    #[test]
    fn parse_and_find_fdinfo_field_basic() {
        const FAKE_FDINFO: &[u8] = indoc! {b"
            foo:\t123456
            bar_baz:\t1
            invalid line that should be skipped
            lorem ipsum: dolor sit amet
            : leading colon with no tab
            multiple: colons: in: one: line:
            repeated colons:: are not:: deduped
            repeated:\t1
            repeated:\t2
            repeated:\t3
            last:\t  \t127.0.0.1:8080\t\t
        "};

        // Basic integer parsing.
        check_parse_and_find_fdinfo_field(&mut &FAKE_FDINFO[..], "foo", Ok(Some(123456u64)))
            .expect(r#"parse "foo: 123456" line"#);
        check_parse_and_find_fdinfo_field(&mut &FAKE_FDINFO[..], "bar_baz", Ok(Some(1u8)))
            .expect(r#"parse "bar_baz: 1" line"#);

        // String "parsing".
        check_parse_and_find_fdinfo_field(
            &mut &FAKE_FDINFO[..],
            "",
            Ok(Some("leading colon with no tab".to_string())),
        )
        .expect(r#"parse ": leading colon with no tab" line"#);

        // Repeated lines.
        check_parse_and_find_fdinfo_field(&mut &FAKE_FDINFO[..], "repeated", Ok(Some(1i16)))
            .expect(r#"first matching entry should be returned"#);

        // Parse last line.
        check_parse_and_find_fdinfo_field(
            &mut &FAKE_FDINFO[..],
            "last",
            Ok(Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080))),
        )
        .expect(r#"first matching entry should be returned"#);

        // Non-existent fields should give us Ok(None).
        check_parse_and_find_fdinfo_field::<u32>(&mut &FAKE_FDINFO[..], "does_not_exist", Ok(None))
            .expect(r#"non-existent field"#);

        // Make sure the entire field name (and only the field name) is being
        // matched.
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "lorem ipsum",
            Ok(Some("dolor sit amet".to_string())),
        )
        .expect(r#"parse "lorem ipsum: dolor sit amet" line"#);
        check_parse_and_find_fdinfo_field::<String>(&mut &FAKE_FDINFO[..], "lorem ipsu", Ok(None))
            .expect(r#"parse "lorem ipsum: dolor sit amet" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "lorem ipsum:",
            Ok(None),
        )
        .expect(r#"parse "lorem ipsum: dolor sit amet" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "lorem ipsum: dolor sit amet",
            Ok(None),
        )
        .expect(r#"parse "lorem ipsum: dolor sit amet" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "lorem ipsum: dolor sit amet",
            Ok(None),
        )
        .expect(r#"parse "lorem ipsum: dolor sit amet" line"#);

        // Lines with multiple colons get parsed properly. This won't happen in
        // practice, but it's worth checking.
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "multiple: colons: in: one: line:",
            Ok(None),
        )
        .expect(r#"parse "multiple: colons: in: one: line:" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "multiple: colons: in: one: line",
            Ok(Some("".to_string())),
        )
        .expect(r#"parse "multiple: colons: in: one: line:" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "multiple: colons: in: one",
            Ok(Some("line:".to_string())),
        )
        .expect(r#"parse "multiple: colons: in: one: line:" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "multiple: colons: in",
            Ok(Some("one: line:".to_string())),
        )
        .expect(r#"parse "multiple: colons: in: one: line:" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "multiple: colons",
            Ok(Some("in: one: line:".to_string())),
        )
        .expect(r#"parse "multiple: colons: in: one: line:" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "multiple",
            Ok(Some("colons: in: one: line:".to_string())),
        )
        .expect(r#"parse "multiple: colons: in: one: line:" line"#);

        // Repeated colons must not be deduplicated.
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "repeated colons:: are not:",
            Ok(Some("deduped".to_string())),
        )
        .expect(r#"parse "repeated colons:: are not:: deduped" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "repeated colons:: are not",
            Ok(Some(": deduped".to_string())),
        )
        .expect(r#"parse "repeated colons:: are not:: deduped" line"#);
        check_parse_and_find_fdinfo_field::<String>(
            &mut &FAKE_FDINFO[..],
            "repeated colons:: are not::",
            Ok(None),
        )
        .expect(r#"parse "repeated colons:: are not:: deduped" line"#);
    }

    #[test]
    fn parse_and_find_fdinfo_field_parse_error() {
        const FAKE_FDINFO: &[u8] = indoc! {b"
            nonint:\tnonint
            nonint_leading:\ta123
            nonint_trailing:\t456a
            nonuint: -15
        "};

        check_parse_and_find_fdinfo_field::<isize>(
            &mut &FAKE_FDINFO[..],
            "nonint",
            Err(ErrorKind::InternalError),
        )
        .expect(r#"parse "nonint: nonint" line"#);
        assert_matches!(
            parse_and_find_fdinfo_field::<isize>(&mut &FAKE_FDINFO[..], "nonint")
                .expect_err("should not be able to parse fdinfo for 'nonint'")
                .into_inner(),
            ErrorImpl::ParseIntError(_),
            "non-integer 'nonint' field should fail with ParseIntError"
        );

        check_parse_and_find_fdinfo_field::<i32>(
            &mut &FAKE_FDINFO[..],
            "nonint_leading",
            Err(ErrorKind::InternalError),
        )
        .expect(r#"parse "nonint_leading: a123" line"#);
        assert_matches!(
            parse_and_find_fdinfo_field::<i32>(&mut &FAKE_FDINFO[..], "nonint_leading")
                .expect_err("should not be able to parse fdinfo for 'nonint_leading'")
                .into_inner(),
            ErrorImpl::ParseIntError(_),
            "non-integer 'nonint_leading' field should fail with ParseIntError"
        );

        check_parse_and_find_fdinfo_field::<i64>(
            &mut &FAKE_FDINFO[..],
            "nonint_trailing",
            Err(ErrorKind::InternalError),
        )
        .expect(r#"parse "nonint_trailing: 456a" line"#);
        assert_matches!(
            parse_and_find_fdinfo_field::<i64>(&mut &FAKE_FDINFO[..], "nonint_trailing")
                .expect_err("should not be able to parse fdinfo for 'nonint_trailing'")
                .into_inner(),
            ErrorImpl::ParseIntError(_),
            "non-integer 'nonint_trailing' field should fail with ParseIntError"
        );

        check_parse_and_find_fdinfo_field::<isize>(&mut &FAKE_FDINFO[..], "nonuint", Ok(Some(-15)))
            .expect(r#"parse "nonuint: -15" line"#);
        check_parse_and_find_fdinfo_field::<usize>(
            &mut &FAKE_FDINFO[..],
            "nonuint",
            Err(ErrorKind::InternalError),
        )
        .expect(r#"parse "nonuint: -15" line"#);
        assert_matches!(
            parse_and_find_fdinfo_field::<usize>(&mut &FAKE_FDINFO[..], "nonuint")
                .expect_err("should not be able to parse fdinfo for 'nonuint'")
                .into_inner(),
            ErrorImpl::ParseIntError(_),
            "signed integer 'nonuint' field parsing as unsigned should fail with ParseIntError"
        );
    }

    fn check_fd_get_verify_fdinfo<T>(
        rdr: &mut (impl Read + Seek),
        fd: impl AsFd,
        want_field_name: &str,
        expected: Result<Option<T>, ErrorKind>,
    ) -> Result<(), Error>
    where
        T: FromStr + PartialEq + Debug,
        T::Err: Into<Error> + Into<ErrorImpl>,
    {
        let got = match fd_get_verify_fdinfo(rdr, fd, want_field_name) {
            Ok(res) => Ok(res),
            Err(err) => {
                if expected.is_ok() {
                    // Don't panic yet -- this is just for debugging purposes.
                    eprintln!("unexpected error: {err:?}");
                }
                Err(err.kind())
            }
        };

        if got != expected {
            eprintln!("{}", Comparison::new(&got, &expected));
            bail!(
                "unexpected result when parsing {want_field_name:?} field (as {:?}) from fdinfo (should be {expected:?})",
                std::any::type_name::<T>()
            );
        }

        Ok(())
    }

    #[test]
    fn fd_get_verify_fdinfo_real_ino() -> Result<(), Error> {
        let file = File::open("/").context("open dummy file")?;
        let real_ino = file.metadata().context("get dummy file metadata")?.ino();

        let fake_fdinfo = formatdoc! {"
            ino:\t{real_ino}
            mnt_id: 12345
        "};

        check_fd_get_verify_fdinfo(
            &mut Cursor::new(&fake_fdinfo),
            &file,
            "mnt_id",
            Ok(Some(12345)),
        )
        .expect(r#"get "mnt_id" from fdinfo with correct ino"#);

        check_fd_get_verify_fdinfo(
            &mut Cursor::new(&fake_fdinfo),
            &file,
            "ino",
            Ok(Some(real_ino)),
        )
        .expect(r#"get "ino" from fdinfo with correct ino"#);

        check_fd_get_verify_fdinfo::<String>(
            &mut Cursor::new(&fake_fdinfo),
            &file,
            "non_exist",
            Ok(None),
        )
        .expect(r#"get "non_exist" from fdinfo with correct ino"#);

        Ok(())
    }

    #[test]
    fn fd_get_verify_fdinfo_bad_ino() -> Result<(), Error> {
        let file = File::open(".").context("open dummy file")?;
        let fake_ino = file.metadata().context("get dummy file metadata")?.ino() + 32;

        let fake_fdinfo = formatdoc! {"
            ino:\t{fake_ino}
            mnt_id: 12345
        "};

        check_fd_get_verify_fdinfo::<u64>(
            &mut Cursor::new(&fake_fdinfo),
            &file,
            "mnt_id",
            Err(ErrorKind::SafetyViolation),
        )
        .expect(r#"get "mnt_id" from fdinfo with incorrect ino"#);

        check_fd_get_verify_fdinfo::<u64>(
            &mut Cursor::new(&fake_fdinfo),
            &file,
            "ino",
            Err(ErrorKind::SafetyViolation),
        )
        .expect(r#"get "ino" from fdinfo with incorrect ino"#);

        check_fd_get_verify_fdinfo::<String>(
            &mut Cursor::new(&fake_fdinfo),
            &file,
            "non_exist",
            Err(ErrorKind::SafetyViolation),
        )
        .expect(r#"get "non_exist" from fdinfo with incorrect ino"#);

        Ok(())
    }

    // Make sure that a missing "ino" entry also fails.
    #[test]
    fn fd_get_verify_fdinfo_no_ino() -> Result<(), Error> {
        const FAKE_FDINFO: &[u8] = indoc! {b"
            foo: abcdef
            mnt_id: 12345
        "};

        let file = File::open(".").context("open dummy file")?;

        check_fd_get_verify_fdinfo::<u64>(
            &mut Cursor::new(&FAKE_FDINFO),
            &file,
            "mnt_id",
            Err(ErrorKind::SafetyViolation),
        )
        .expect(r#"get "mnt_id" from fdinfo with missing ino"#);

        check_fd_get_verify_fdinfo::<u64>(
            &mut Cursor::new(&FAKE_FDINFO),
            &file,
            "ino",
            Err(ErrorKind::SafetyViolation),
        )
        .expect(r#"get "ino" from fdinfo with missing ino"#);

        check_fd_get_verify_fdinfo::<String>(
            &mut Cursor::new(&FAKE_FDINFO),
            &file,
            "non_exist",
            Err(ErrorKind::SafetyViolation),
        )
        .expect(r#"get "non_exist" from fdinfo with missing ino"#);

        Ok(())
    }

    // Make sure that an "ino" entry with the wrong type results in a
    // SafetyViolation error, not an integer parsing error.
    #[test]
    fn fd_get_verify_fdinfo_wrongtype_ino() -> Result<(), Error> {
        const FAKE_FDINFO_I64: &[u8] = indoc! {b"
            ino: -1234
            mnt_id: 12345
        "};
        const FAKE_FDINFO_STR: &[u8] = indoc! {b"
            ino: foobar
            mnt_id: 12345
        "};

        let file = File::open(".").context("open dummy file")?;

        for fake_fdinfo in [&FAKE_FDINFO_I64, &FAKE_FDINFO_STR] {
            check_fd_get_verify_fdinfo::<u64>(
                &mut Cursor::new(fake_fdinfo),
                &file,
                "mnt_id",
                Err(ErrorKind::SafetyViolation),
            )
            .expect(r#"get "mnt_id" from fdinfo with non-u64 ino"#);

            check_fd_get_verify_fdinfo::<u64>(
                &mut Cursor::new(fake_fdinfo),
                &file,
                "ino",
                Err(ErrorKind::SafetyViolation),
            )
            .expect(r#"get "ino" from fdinfo with non-u64 ino"#);

            check_fd_get_verify_fdinfo::<String>(
                &mut Cursor::new(fake_fdinfo),
                &file,
                "non_exist",
                Err(ErrorKind::SafetyViolation),
            )
            .expect(r#"get "non_exist" from fdinfo with non-u64 ino"#);
        }

        Ok(())
    }
}

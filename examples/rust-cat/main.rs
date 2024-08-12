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

/*
 * File: examples/rust-cat/main.rs
 *
 * An example program which opens a file inside a root and outputs its
 * contents using libpathrs.
 */

use pathrs::{flags::OpenFlags, Root};

use std::io::{prelude::*, BufReader};

use anyhow::{Context, Error};
use clap::{Arg, Command};

fn main() -> Result<(), Error> {
    let m = Command::new("cat")
        // MSRV(1.67): Use clap::crate_authors!.
        .author("Aleksa Sarai <cyphar@cyphar.com>")
        .version(clap::crate_version!())
        .arg(Arg::new("root").value_name("ROOT"))
        .arg(Arg::new("unsafe-path").value_name("PATH"))
        .about("")
        .get_matches();

    let root_path = m
        .get_one::<String>("root")
        .context("required root argument not provided")?;
    let unsafe_path = m
        .get_one::<String>("unsafe-path")
        .context("required unsafe-path argument not provided")?;

    let root = Root::open(root_path).context("open root failed")?;
    let handle = root
        .resolve(unsafe_path)
        .context("resolve unsafe path in root")?;

    let file = handle
        .reopen(OpenFlags::O_RDONLY)
        .context("reopen path with O_RDONLY")?;

    let reader = BufReader::new(file);
    for line in reader.lines() {
        println!("{}", line.context("read lines")?);
    }
    Ok(())
}

#!/usr/bin/env python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019-2024 SUSE LLC
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# File: examples/python/sysctl.py
#
# An example program which does sysctl operations using the libpathrs safe
# procfs API.

import os
import sys

sys.path.append(os.path.dirname(__file__) + "/../contrib/bindings/python")
import pathrs


def bail(*args):
    print("[!]", *args)
    os.exit(1)


def chomp(s: str) -> str:
    for nl in ["\r\n", "\r", "\n"]:
        if s.endswith(nl):
            return s[: -len(nl)]
    return s


def sysctl_subpath(name: str) -> str:
    # "kernel.foo.bar" -> /proc/sys/kernel/foo/bar
    return "sys/" + name.replace(".", "/")


def sysctl_write(name: str, value: str) -> None:
    subpath = sysctl_subpath(name)
    with pathrs.proc_open(pathrs.PROC_ROOT, subpath, "w") as f:
        f.write(value)


def sysctl_read(name: str, *, value_only: bool = False) -> None:
    subpath = sysctl_subpath(name)
    with pathrs.proc_open(pathrs.PROC_ROOT, subpath, "r") as f:
        value = chomp(f.read())
        if value_only:
            print(f"{value}")
        else:
            print(f"{name} = {value}")


def main(*args):
    import argparse

    parser = argparse.ArgumentParser(
        prog="sysctl.py",
        description="A minimal implementation of sysctl(8) but using the libpathrs procfs API.",
    )
    parser.add_argument(
        "-n",
        "--values",
        dest="value_only",
        action="store_true",
        help="print only values of the given variable(s)",
    )
    parser.add_argument(
        "-w",
        "--write",
        action="store_true",
        help="enable writing a value to a variable",
    )
    parser.add_argument(
        "sysctls",
        nargs="*",
        metavar="variable[=value]",
        help="sysctl variable name (such as 'kernel.overflowuid')",
    )

    args = parser.parse_args(args)

    for sysctl in args.sysctls:
        if "=" in sysctl:
            if not args.write:
                bail("you must pass -w to enable sysctl writing")
            name, value = sysctl.split("=", maxsplit=1)
            sysctl_write(name, value)
        else:
            sysctl_read(sysctl, value_only=args.value_only)


if __name__ == "__main__":
    main(*sys.argv[1:])

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
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

# File: examples/python/cat.py
#
# An example program which opens a file inside a root and outputs its contents
# using libpathrs.

import os
import sys

sys.path.append(os.path.dirname(__file__) + "/../contrib/bindings/python")
import pathrs


def chomp(s):
    for nl in ["\r\n", "\r", "\n"]:
        if s.endswith(nl):
            return s[: -len(nl)]
    return s


def main(root_path, unsafe_path):
    # Test that context managers work properly with WrappedFd:
    with pathrs.Root(root_path) as root:
        with root.open(unsafe_path, "r") as f:
            for line in f:
                line = chomp(line)
                print(line)


if __name__ == "__main__":
    main(*sys.argv[1:])

// libpathrs: safe path resolution on Linux
// Copyright (C) 2020 Maxim Zhiburt <zhiburt@gmail.com>
// Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2019-2021 SUSE LLC
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

// Package main implements a program which print file content to stdout
// safely resolving paths with libpathrs.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/openSUSE/libpathrs/go-pathrs"
)

func usage() {
	fmt.Println("usage: cat <root> <unsafe-path>")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		usage()
	}

	rootPath := os.Args[1]
	path := os.Args[2]

	root, err := pathrs.OpenRoot(rootPath)
	if err != nil {
		printPathError(err)
	}
	defer root.Close()

	handle, err := root.Resolve(path)
	if err != nil {
		printPathError(err)
	}
	defer handle.Close()

	file, err := handle.Open()
	if err != nil {
		printPathError(err)
	}
	defer file.Close()

	fmt.Fprintf(os.Stderr, "file %q (from root %q):\n", file.Name(), root.IntoFile().Name())

	_, err = io.Copy(os.Stdout, file)
	if err != nil {
		fmt.Printf("Cannot write content of file to stdout, %v\n", err)
		os.Exit(1)
	}
}

func printPathError(err error) {
	fmt.Println("Error", err)
	fmt.Println("Unwrapped error", errors.Unwrap(err))
	os.Exit(1)
}

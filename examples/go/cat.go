// libpathrs: safe path resolution on Linux
// Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2019-2024 SUSE LLC
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

// Original author of this example code:
// Copyright (C) 2020 Maxim Zhiburt <zhiburt@gmail.com>

// File: examples/c/cat.c
//
// An example program which opens a file inside a root and outputs its contents
// using libpathrs.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cyphar/libpathrs/go-pathrs"
)

func Main(args []string) error {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cat <root> <unsafe-path>")
		os.Exit(1)
	}

	rootPath, unsafePath := args[0], args[1]

	root, err := pathrs.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open root %q: %w", rootPath, err)
	}
	defer root.Close()

	file, err := root.Open(unsafePath)
	if err != nil {
		return fmt.Errorf("open %q: %w", unsafePath, err)
	}
	defer file.Close()

	fmt.Fprintf(os.Stderr, "== file %q (from root %q) ==\n", file.Name(), root.IntoFile().Name())

	if _, err := io.Copy(os.Stdout, file); err != nil {
		return fmt.Errorf("copy file contents to stdout: %w", err)
	}
	return nil
}

func main() {
	if err := Main(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		fmt.Fprintf(os.Stderr, "Source: %v", errors.Unwrap(err))
		os.Exit(1)
	}
}

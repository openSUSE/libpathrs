//go:build linux

// libpathrs: safe path resolution on Linux
// Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2019-2024 SUSE LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pathrs

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// dupFd makes a duplicate of the given fd.
func dupFd(fd uintptr, name string) (*os.File, error) {
	newFd, err := unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("fcntl(F_DUPFD_CLOEXEC): %w", err)
	}
	return os.NewFile(uintptr(newFd), name), nil
}

func toUnixMode(mode os.FileMode) (uint32, error) {
	sysMode := uint32(mode.Perm())
	switch mode & os.ModeType {
	case 0:
		sysMode |= unix.S_IFREG
	case os.ModeDir:
		sysMode |= unix.S_IFDIR
	case os.ModeSymlink:
		sysMode |= unix.S_IFLNK
	case os.ModeCharDevice | os.ModeDevice:
		sysMode |= unix.S_IFCHR
	case os.ModeDevice:
		sysMode |= unix.S_IFBLK
	case os.ModeNamedPipe:
		sysMode |= unix.S_IFIFO
	case os.ModeSocket:
		sysMode |= unix.S_IFSOCK
	default:
		return 0, fmt.Errorf("invalid mode filetype %+o", mode)
	}
	if mode&os.ModeSetuid != 0 {
		sysMode |= unix.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		sysMode |= unix.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		sysMode |= unix.S_ISVTX
	}
	return sysMode, nil
}

// withFileFd is a more ergonomic wrapper around file.SyscallConn().Control().
func withFileFd[T any](file *os.File, fn func(fd uintptr) (T, error)) (T, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return *new(T), err
	}
	var (
		ret      T
		innerErr error
	)
	if err := conn.Control(func(fd uintptr) {
		ret, innerErr = fn(fd)
	}); err != nil {
		return *new(T), err
	}
	return ret, innerErr
}

// dupFile makes a duplicate of the given file.
func dupFile(file *os.File) (*os.File, error) {
	return withFileFd(file, func(fd uintptr) (*os.File, error) {
		return dupFd(fd, file.Name())
	})
}

// randName generates a random hexadecimal name that is used for the Go-level
// "file name" of libpathrs-generated fds, and can be used to help with
// debugging.
func randName(k int) (string, error) {
	randBuf := make([]byte, k/2)

	if n, err := rand.Read(randBuf); err != nil {
		return "", err
	} else if n != len(randBuf) {
		return "", fmt.Errorf("rand.Read didn't return enough bytes (%d != %d)", n, len(randBuf))
	}

	var nameBuf strings.Builder
	nameBuf.WriteString("//pathrs-fd:")
	for _, b := range randBuf {
		nameBuf.WriteString(fmt.Sprintf("%.2x", b))
	}
	return nameBuf.String(), nil
}

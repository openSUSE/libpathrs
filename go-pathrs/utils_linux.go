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
	"fmt"
	"os"

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

// mkFile creates a new *os.File from the provided file descriptor. However,
// unlike os.NewFile, the file's Name is based on the real path (provided by
// /proc/self/fd/$n).
func mkFile(fd uintptr) (*os.File, error) {
	fdPath := fmt.Sprintf("fd/%d", fd)
	fdName, err := ProcReadlink(ProcBaseThreadSelf, fdPath)
	if err != nil {
		_ = unix.Close(int(fd))
		return nil, fmt.Errorf("failed to fetch real name of fd %d: %w", fd, err)
	}
	// TODO: Maybe we should prefix this name with something to indicate to
	// users that they must not use this path as a "safe" path. Something like
	// "//pathrs-handle:/foo/bar"?
	return os.NewFile(fd, fdName), nil
}

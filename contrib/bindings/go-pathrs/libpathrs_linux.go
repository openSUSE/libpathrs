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
	"syscall"
	"unsafe"
)

// TODO: Switch to pkg-config.

// #cgo CFLAGS: -I${SRCDIR}/../../../include
// #cgo LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lpathrs
// #include <pathrs.h>
import "C"

func newError(e *C.pathrs_error_t) error {
	if e == nil {
		return nil
	}

	err := &Error{
		errno:       syscall.Errno(e.saved_errno),
		description: C.GoString(e.description),
	}

	if e.backtrace != nil {
		head := uintptr(unsafe.Pointer(e.backtrace.head))
		length := uintptr(e.backtrace.length)
		sizeof := uintptr(C.sizeof___pathrs_backtrace_entry_t)
		for ptr := head; ptr < head+length*sizeof; ptr += sizeof {
			entry := (*C.__pathrs_backtrace_entry_t)(unsafe.Pointer(ptr))
			line := backtraceLine{
				ip:       uintptr(entry.ip),
				sAddress: uintptr(entry.symbol_address),
				sLineno:  uint32(entry.symbol_lineno),
				sFile:    C.GoString(entry.symbol_file),
				sName:    C.GoString(entry.symbol_name),
			}
			err.backtrace = append(err.backtrace, line)
		}
	}

	return err
}

func fetchError(errId C.int) error {
	if errId >= 0 {
		return nil
	}
	err := C.pathrs_errorinfo(errId)
	defer C.pathrs_errorinfo_free(err)
	return newError(err)
}

func pathrsOpen(path string) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_root_open(cPath)
	return uintptr(fd), fetchError(fd)
}

func pathrsReopen(fd uintptr, flags int) (uintptr, error) {
	newFd := C.pathrs_reopen(C.int(fd), C.int(flags))
	return uintptr(newFd), fetchError(newFd)
}

func pathrsResolve(rootFd uintptr, path string) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_resolve(C.int(rootFd), cPath)
	return uintptr(fd), fetchError(fd)
}

func pathrsCreat(rootFd uintptr, path string, flags int, mode uint32) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_creat(C.int(rootFd), cPath, C.int(flags), C.uint(mode))
	return uintptr(fd), fetchError(fd)
}

func pathrsRename(rootFd uintptr, src, dst string, flags uint) error {
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))

	cDst := C.CString(dst)
	defer C.free(unsafe.Pointer(cDst))

	err := C.pathrs_rename(C.int(rootFd), cSrc, cDst, C.uint(flags))
	return fetchError(err)
}

func pathrsMkdir(rootFd uintptr, path string, mode uint32) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_mkdir(C.int(rootFd), cPath, C.uint(mode))
	return fetchError(err)
}

func pathrsMknod(rootFd uintptr, path string, mode uint32, dev uint64) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_mknod(C.int(rootFd), cPath, C.uint(mode), C.dev_t(dev))
	return fetchError(err)
}

func pathrsSymlink(rootFd uintptr, path, target string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	err := C.pathrs_symlink(C.int(rootFd), cPath, cTarget)
	return fetchError(err)
}

func pathrsHardlink(rootFd uintptr, path, target string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	err := C.pathrs_hardlink(C.int(rootFd), cPath, cTarget)
	return fetchError(err)
}

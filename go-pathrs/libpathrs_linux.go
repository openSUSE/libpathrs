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

// #cgo pkg-config: pathrs
// #include <pathrs.h>
import "C"

func fetchError(errId C.int) error {
	if errId >= 0 {
		return nil
	}
	cErr := C.pathrs_errorinfo(errId)
	defer C.pathrs_errorinfo_free(cErr)

	var err error
	if cErr != nil {
		err = &Error{
			errno:       syscall.Errno(cErr.saved_errno),
			description: C.GoString(cErr.description),
		}
	}
	return err
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

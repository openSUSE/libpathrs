//go:build linux

/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2024 SUSE LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pathrs

import (
	"fmt"
	"syscall"
	"unsafe"
)

/*
// TODO: Figure out if we need to add support for linking against libpathrs
//       statically even if in dynamically linked builds in order to make
//       packaging a bit easier (using "-Wl,-Bstatic -lpathrs -Wl,-Bdynamic" or
//       "-l:pathrs.a").
#cgo pkg-config: pathrs
#include <pathrs.h>

// This is a workaround for unsafe.Pointer() not working for non-void pointers.
char *cast_ptr(void *ptr) { return ptr; }
*/
import "C"

func fetchError(errID C.int) error {
	if errID >= 0 {
		return nil
	}
	cErr := C.pathrs_errorinfo(errID)
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

func pathrsOpenRoot(path string) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_open_root(cPath)
	return uintptr(fd), fetchError(fd)
}

func pathrsReopen(fd uintptr, flags int) (uintptr, error) {
	newFd := C.pathrs_reopen(C.int(fd), C.int(flags))
	return uintptr(newFd), fetchError(newFd)
}

func pathrsInRootResolve(rootFd uintptr, path string) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_inroot_resolve(C.int(rootFd), cPath)
	return uintptr(fd), fetchError(fd)
}

func pathrsInRootResolveNoFollow(rootFd uintptr, path string) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_inroot_resolve_nofollow(C.int(rootFd), cPath)
	return uintptr(fd), fetchError(fd)
}

func pathrsInRootOpen(rootFd uintptr, path string, flags int) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_inroot_open(C.int(rootFd), cPath, C.int(flags))
	return uintptr(fd), fetchError(fd)
}

func pathrsInRootReadlink(rootFd uintptr, path string) (string, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	size := 128
	for {
		linkBuf := make([]byte, size)
		n := C.pathrs_inroot_readlink(C.int(rootFd), cPath, C.cast_ptr(unsafe.Pointer(&linkBuf[0])), C.ulong(len(linkBuf)))
		switch {
		case int(n) < 0:
			return "", fetchError(n)
		case int(n) <= len(linkBuf):
			return string(linkBuf[:int(n)]), nil
		default:
			// The contents were truncated. Unlike readlinkat, pathrs returns
			// the size of the link when it checked. So use the returned size
			// as a basis for the reallocated size (but in order to avoid a DoS
			// where a magic-link is growing by a single byte each iteration,
			// make sure we are a fair bit larger).
			size += int(n)
		}
	}
}

func pathrsInRootRmdir(rootFd uintptr, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_inroot_rmdir(C.int(rootFd), cPath)
	return fetchError(err)
}

func pathrsInRootUnlink(rootFd uintptr, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_inroot_unlink(C.int(rootFd), cPath)
	return fetchError(err)
}

func pathrsInRootRemoveAll(rootFd uintptr, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_inroot_remove_all(C.int(rootFd), cPath)
	return fetchError(err)
}

func pathrsInRootCreat(rootFd uintptr, path string, flags int, mode uint32) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_inroot_creat(C.int(rootFd), cPath, C.int(flags), C.uint(mode))
	return uintptr(fd), fetchError(fd)
}

func pathrsInRootRename(rootFd uintptr, src, dst string, flags uint) error {
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))

	cDst := C.CString(dst)
	defer C.free(unsafe.Pointer(cDst))

	err := C.pathrs_inroot_rename(C.int(rootFd), cSrc, cDst, C.uint(flags))
	return fetchError(err)
}

func pathrsInRootMkdir(rootFd uintptr, path string, mode uint32) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_inroot_mkdir(C.int(rootFd), cPath, C.uint(mode))
	return fetchError(err)
}

func pathrsInRootMkdirAll(rootFd uintptr, path string, mode uint32) (uintptr, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_inroot_mkdir_all(C.int(rootFd), cPath, C.uint(mode))
	return uintptr(fd), fetchError(fd)
}

func pathrsInRootMknod(rootFd uintptr, path string, mode uint32, dev uint64) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	err := C.pathrs_inroot_mknod(C.int(rootFd), cPath, C.uint(mode), C.dev_t(dev))
	return fetchError(err)
}

func pathrsInRootSymlink(rootFd uintptr, path, target string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	err := C.pathrs_inroot_symlink(C.int(rootFd), cPath, cTarget)
	return fetchError(err)
}

func pathrsInRootHardlink(rootFd uintptr, path, target string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	err := C.pathrs_inroot_hardlink(C.int(rootFd), cPath, cTarget)
	return fetchError(err)
}

type pathrsProcBase C.pathrs_proc_base_t

// FIXME: We need to open-code the constants because CGo unfortunately will
// implicitly convert any non-literal constants (i.e. those resolved using gcc)
// to signed integers. See <https://github.com/golang/go/issues/39136> for some
// more information on the underlying issue (though.
const (
	pathrsProcRoot       pathrsProcBase = 0xFFFF_FFFE_7072_6F63 // C.PATHRS_PROC_ROOT
	pathrsProcSelf       pathrsProcBase = 0xFFFF_FFFE_091D_5E1F // C.PATHRS_PROC_SELF
	pathrsProcThreadSelf pathrsProcBase = 0xFFFF_FFFE_3EAD_5E1F // C.PATHRS_PROC_THREAD_SELF

	pathrsProcBaseTypeMask pathrsProcBase = 0xFFFF_FFFF_0000_0000 // C.__PATHRS_PROC_TYPE_MASK
	pathrsProcBaseTypePid  pathrsProcBase = 0x8000_0000_0000_0000 // C.__PATHRS_PROC_TYPE_PID
)

// Verify that the values above match the actual C values. Unfortunately, Go
// only allows us to forcefully cast int64 to uint64 if you use a temporary
// variable, which means we cannot do it in a const context and thus need to do
// it at runtime (even though it is a check that fundamentally could be done at
// compile-time)...
func init() {
	assertEqual := func(a, b pathrsProcBase, msg string) {
		if a != b {
			panic(fmt.Sprintf("%s ((%T) %#v != (%T) %#v)", msg, a, a, b, b))
		}
	}

	var (
		actualProcRoot       int64 = C.PATHRS_PROC_ROOT
		actualProcSelf       int64 = C.PATHRS_PROC_SELF
		actualProcThreadSelf int64 = C.PATHRS_PROC_THREAD_SELF
	)

	assertEqual(pathrsProcRoot, pathrsProcBase(actualProcRoot), "PATHRS_PROC_ROOT")
	assertEqual(pathrsProcSelf, pathrsProcBase(actualProcSelf), "PATHRS_PROC_SELF")
	assertEqual(pathrsProcThreadSelf, pathrsProcBase(actualProcThreadSelf), "PATHRS_PROC_THREAD_SELF")

	var (
		actualProcBaseTypeMask uint64 = C.__PATHRS_PROC_TYPE_MASK
		actualProcBaseTypePid  uint64 = C.__PATHRS_PROC_TYPE_PID
	)

	assertEqual(pathrsProcBaseTypeMask, pathrsProcBase(actualProcBaseTypeMask), "__PATHRS_PROC_TYPE_MASK")
	assertEqual(pathrsProcBaseTypePid, pathrsProcBase(actualProcBaseTypePid), "__PATHRS_PROC_TYPE_PID")
}

func pathrsProcPid(pid uint32) pathrsProcBase { return pathrsProcBaseTypePid | pathrsProcBase(pid) }

func pathrsProcOpen(base pathrsProcBase, path string, flags int) (uintptr, error) {
	cBase := C.pathrs_proc_base_t(base)

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd := C.pathrs_proc_open(cBase, cPath, C.int(flags))
	return uintptr(fd), fetchError(fd)
}

func pathrsProcReadlink(base pathrsProcBase, path string) (string, error) {
	// TODO: See if we can unify this code with pathrsInRootReadlink.

	cBase := C.pathrs_proc_base_t(base)

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	size := 128
	for {
		linkBuf := make([]byte, size)
		n := C.pathrs_proc_readlink(cBase, cPath, C.cast_ptr(unsafe.Pointer(&linkBuf[0])), C.ulong(len(linkBuf)))
		switch {
		case int(n) < 0:
			return "", fetchError(n)
		case int(n) <= len(linkBuf):
			return string(linkBuf[:int(n)]), nil
		default:
			// The contents were truncated. Unlike readlinkat, pathrs returns
			// the size of the link when it checked. So use the returned size
			// as a basis for the reallocated size (but in order to avoid a DoS
			// where a magic-link is growing by a single byte each iteration,
			// make sure we are a fair bit larger).
			size += int(n)
		}
	}
}

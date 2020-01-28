// Copyright (C) 2019, 2020 Aleksa Sarai <cyphar@cyphar.com>
// Copyright (C) 2020 Maxim Zhiburt <zhiburt@gmail.com>
// Copyright (C) 2019, 2020 SUSE LLC
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

// Package pathrs provides bindings for libpathrs, a library for safe path
// resolution on Linux.
package pathrs

// #cgo LDFLAGS: -lpathrs
// #include <pathrs.h>
import "C"

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"
)

// pathrsObject is implemented by all wrappers of FFI-managed objects.
type pathrsObject interface {
	// inner returns the (type, pointer) tuple for the underlying FFI-managed
	// object.
	inner() (C.pathrs_type_t, unsafe.Pointer)
}

// Ensure that all FFI-managed objects implement pathrsObject at compile-time.
var _ pathrsObject = &Root{}
var _ pathrsObject = &Handle{}

// Root is a handle to the root of a directory tree to resolve within. The only
// purpose of this "root handle" is to perform operations within the directory
// tree, or to get Handles to inodes within the directory tree.
//
// At the time of writing, it is considered a *VERY BAD IDEA* to open a Root
// inside a possibly-attacker-controlled directory tree. While we do have
// protections that should defend against it (for both drivers), it's far more
// dangerous than just opening a directory tree which is not inside a
// potentially-untrusted directory.
type Root struct {
	root *C.pathrs_root_t
}

// inner returns the (type, pointer) tuple for the underlying FFI-managed
// object.
func (r *Root) inner() (C.pathrs_type_t, unsafe.Pointer) {
	return C.PATHRS_ROOT, unsafe.Pointer(r.root)
}

// Open creates a new Root handle to the directory at the given path.
func Open(path string) (*Root, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rootInner := C.pathrs_open(C.CString(path))
	root := &Root{root: rootInner}
	return root, fetchError(root)
}

// RootFromRaw constructs a new file-based libpathrs object of root from a file descriptor
// Uses often in combination with Root.IntoRaw methood
func RootFromRaw(file *os.File) (*Root, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := file.Fd()
	rootInner := (*C.pathrs_root_t)(C.pathrs_from_fd(C.PATHRS_ROOT, C.int(fd)))
	root := &Root{root: rootInner}
	return root, fetchError(root)
}

// Resolve resolves the given path within the given root's tree
// and return a handle to that path. The path must
// already exist, otherwise an error will occur.
func (r *Root) Resolve(path string) (*Handle, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	handle := C.pathrs_resolve(r.root, C.CString(path))
	if err := fetchError(r); err != nil {
		return nil, err
	}
	return &Handle{handle: handle}, nil
}

// Create creates a file with a such mode by path according with the root path
func (r *Root) Create(path string, mode uint) (*Handle, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	handle := C.pathrs_creat(r.root, C.CString(path), C.uint(mode))
	if err := fetchError(r); err != nil {
		return nil, err
	}
	return &Handle{handle: handle}, nil
}

// Rename Within the given root's tree, perform the rename of src to dst,
// or change flags on this file if the names are the same it's only change the flags
func (r *Root) Rename(src, dst string, flags int) error {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	C.pathrs_rename(r.root, C.CString(src), C.CString(dst), C.int(flags))
	return fetchError(r)
}

// Mkdir creates a directory with a such mode by path
func (r *Root) Mkdir(path string, mode uint) error {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	C.pathrs_mkdir(r.root, C.CString(path), C.uint(mode))
	return fetchError(r)
}

// Mknod creates a filesystem node named path
// with attributes mode and dev
func (r *Root) Mknod(path string, mode uint, dev int) error {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	C.pathrs_mknod(r.root, C.CString(path), C.uint(mode), C.dev_t(dev))
	return fetchError(r)
}

// Hardlink creates a hardlink of file named target and place it to path
func (r *Root) Hardlink(path, target string) error {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	C.pathrs_hardlink(r.root, C.CString(path), C.CString(target))
	return fetchError(r)
}

// Symlink creates a symlink of file named target and place it to path
func (r *Root) Symlink(path, target string) error {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	C.pathrs_symlink(r.root, C.CString(path), C.CString(target))
	return fetchError(r)
}

// IntoRaw unwraps a file-based libpathrs object to obtain its underlying file
// descriptor.
//
// It is critical that you do not operate on this file descriptor yourself,
// because the security properties of libpathrs depend on users doing all
// relevant filesystem operations through libpathrs.
//
// After this operation, the root should still be freed with root.Close() but
// the root is otherwise invalid and libpathrs will produce an error each time
// it is used.
func (r *Root) IntoRaw() (*os.File, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := int(C.pathrs_into_fd(r.inner()))
	if err := fetchError(r); err != nil {
		return nil, err
	}

	name, err := randName(32)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "pathrs-raw-root:"+name), nil
}

// Clone creates a copy of root handle the new object will have a separate lifetime
// from the original, but will refer to the same underlying file
func (r *Root) Clone() (*Root, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	newRoot := (*C.pathrs_root_t)(C.pathrs_duplicate(r.inner()))
	if err := fetchError(r); err != nil {
		return nil, err
	}
	return &Root{root: newRoot}, nil
}

// Close frees underling caught resources
func (r *Root) Close() {
	if r != nil {
		C.pathrs_free(r.inner())
	}
}

// Handle represents an handle pathrs api interface
type Handle struct {
	handle *C.pathrs_handle_t
}

// inner returns the (type, pointer) tuple for the underlying FFI-managed
// object.
func (h *Handle) inner() (C.pathrs_type_t, unsafe.Pointer) {
	return C.PATHRS_HANDLE, unsafe.Pointer(h.handle)
}

// HandleFromRaw constructs a new file-based libpathrs object of handle from a file descriptor
// Uses often in combination with Handle.IntoRaw methood
func HandleFromRaw(file *os.File) (*Handle, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := file.Fd()
	handleInner := (*C.pathrs_handle_t)(C.pathrs_from_fd(C.PATHRS_HANDLE, C.int(fd)))
	handle := &Handle{handle: handleInner}
	return handle, fetchError(handle)
}

// Open upgrade the handle to a file representation
// which holds a usable fd, suitable for reading
func (h *Handle) Open() (*os.File, error) {
	return h.OpenFile(os.O_RDONLY)
}

// OpenFile upgrade the handle to a file representation
// which holds a usable fd, with a specific settings by provided flags
func (h *Handle) OpenFile(flags int) (*os.File, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := C.pathrs_reopen(h.handle, C.int(flags))
	if err := fetchError(h); err != nil {
		return nil, err
	}

	name, err := randName(32)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "pathrs-handle:"+name), nil
}

// IntoRaw unwraps a file-based libpathrs object to obtain its underlying file
// descriptor.
//
// It is critical that you do not operate on this file descriptor yourself,
// because the security properties of libpathrs depend on users doing all
// relevant filesystem operations through libpathrs.
//
// After this operation, the handle should still be freed with handle.Close()
// but the handle is otherwise invalid and libpathrs will produce an error each
// time it is used.
func (h *Handle) IntoRaw() (*os.File, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := int(C.pathrs_into_fd(h.inner()))
	if fd < 0 {
		return nil, fetchError(h)
	}

	name, err := randName(32)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "pathrs-raw-handle:"+name), nil
}

// Clone creates a copy of root handle the new object will have a separate lifetime
// from the original, but will refer to the same underlying file
func (h *Handle) Clone() (*Handle, error) {
	// Needed because libpathrs has per-thread errors.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	newHandle := (*C.pathrs_handle_t)(C.pathrs_duplicate(h.inner()))
	if err := fetchError(h); err != nil {
		return nil, err
	}
	return &Handle{handle: newHandle}, nil
}

// Close frees underling caught resources
func (h *Handle) Close() {
	if h != nil {
		C.pathrs_free(h.inner())
	}
}

func randName(len int) (string, error) {
	var nameBuf strings.Builder
	lenBuf := len / 2
	randBuf := make([]byte, lenBuf)

	n, err := rand.Read(randBuf)
	if n != lenBuf || err != nil {
		return "", fmt.Errorf("rand.Read didn't return %d bytes: %v", len, err)
	}

	for _, b := range randBuf {
		nameBuf.WriteString(fmt.Sprintf("%.2x", b))
	}

	return nameBuf.String(), nil
}

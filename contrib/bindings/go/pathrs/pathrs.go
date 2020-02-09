// libpathrs: safe path resolution on Linux
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
	"sync"
	"unsafe"
)

var (
	// ErrInvalidObject is returned if an operation is being attempted on a
	// nil-valued (or otherwise invalid) libpathrs object.
	ErrInvalidObject = fmt.Errorf("cannot operate on nil libpathrs object")

	// ErrClosedObject is returned if an operation is being attempted on a
	// libpathrs object which has had its Close method called.
	ErrClosedObject = fmt.Errorf("cannot operate on closed libpathrs object")
)

// pathrsObject is implemented by all wrappers of FFI-managed objects.
type pathrsObject interface {
	// inner returns the (type, pointer) tuple for the underlying FFI-managed
	// object.
	inner() (C.pathrs_type_t, unsafe.Pointer)

	// withInner runs a callback such that it is safe to operate on the pointer
	// returned from inner(). ErrClosedObject will be returned if the object
	// has been Close()'d, and ErrInvalidObject if the object is invalid.
	withInner(fn func(pathrsObject) error) error
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
	lock sync.RWMutex
	ptr  *C.pathrs_root_t
}

// inner returns the (type, pointer) tuple for the underlying FFI-managed
// object. Must be called with an active reference to the Root.
func (r *Root) inner() (C.pathrs_type_t, unsafe.Pointer) {
	return C.PATHRS_ROOT, unsafe.Pointer(r.ptr)
}

// withInner runs a callback such that it is safe to operate on the pointer
// returned from inner(). ErrClosedObject will be returned if the object
// has been Close()'d, and ErrInvalidObject if the object is invalid.
func (r *Root) withInner(fn func(pathrsObject) error) error {
	if r == nil {
		return ErrInvalidObject
	}

	// libpathrs has thread-local error handling, so we can't allow Go to
	// switch us between threads between the operation and fetching the error.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Protects the libpathrs object from being freed underneath us.
	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.ptr == nil {
		return ErrClosedObject
	}
	return fn(r)
}

// Open creates a new Root handle to the directory at the given path.
func Open(path string) (*Root, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	inner := C.pathrs_open(cPath)
	root := &Root{ptr: inner}
	if err := fetchError(root); err != nil {
		return nil, err
	} else if inner == nil {
		return nil, ErrClosedObject
	}
	return root, nil
}

// RootFromRaw creates a new Root handle from an exisitng file handle. The
// handle will be copied by this method, so the original handle should still be
// freed by the caller.
//
// This is effectively the inverse operation of Root.IntoRaw, and is used for
// "deserialising" pathrs root handles.
func RootFromRaw(file *os.File) (*Root, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := file.Fd()

	inner := (*C.pathrs_root_t)(C.pathrs_from_fd(C.PATHRS_ROOT, C.int(fd)))
	root := &Root{ptr: inner}
	return root, fetchError(root)
}

// Resolve resolves the given path within the Root's directory tree, and return
// a Handle to the resolved path. The path must already exist, otherwise an
// error will occur.
func (r *Root) Resolve(path string) (*Handle, error) {
	var handle *Handle
	err := r.withInner(func(_ pathrsObject) error {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		inner := C.pathrs_resolve(r.ptr, cPath)
		if err := fetchError(r); err != nil {
			return err
		} else if inner == nil {
			return ErrClosedObject
		}

		handle = &Handle{ptr: inner}
		return nil
	})
	return handle, err
}

// Create creates a file within the Root's directory tree at the given path,
// and returns a handle to the file. The provided mode is used for the new file
// (the process's umask applies).
func (r *Root) Create(path string, mode os.FileMode) (*Handle, error) {
	var handle *Handle
	err := r.withInner(func(_ pathrsObject) error {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		inner := C.pathrs_creat(r.ptr, cPath, C.uint(mode))
		if err := fetchError(r); err != nil {
			return err
		} else if inner == nil {
			return ErrClosedObject
		}

		handle = &Handle{ptr: inner}
		return nil
	})
	return handle, err
}

// Rename two paths within a Root's directory tree. The flags argument is
// identical to the RENAME_* flags to the renameat2(2) system call.
func (r *Root) Rename(src, dst string, flags int) error {
	return r.withInner(func(_ pathrsObject) error {
		cSrc := C.CString(src)
		defer C.free(unsafe.Pointer(cSrc))

		cDst := C.CString(dst)
		defer C.free(unsafe.Pointer(cDst))

		ret := C.pathrs_rename(r.ptr, cSrc, cDst, C.int(flags))
		if err := fetchError(r); err != nil {
			return err
		} else if ret < 0 {
			return ErrClosedObject
		}
		return nil
	})
}

// Mkdir creates a directory within a Root's directory tree. The provided mode
// is used for the new directory (the process's umask applies).
func (r *Root) Mkdir(path string, mode os.FileMode) error {
	return r.withInner(func(_ pathrsObject) error {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		ret := C.pathrs_mkdir(r.ptr, cPath, C.uint(mode))
		if err := fetchError(r); err != nil {
			return err
		} else if ret < 0 {
			return ErrClosedObject
		}
		return nil
	})
}

// Mknod creates a new device inode of the given type within a Root's directory
// tree. The provided mode is used for the new directory (the process's umask
// applies).
func (r *Root) Mknod(path string, mode os.FileMode, dev int) error {
	return r.withInner(func(_ pathrsObject) error {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		ret := C.pathrs_mknod(r.ptr, cPath, C.uint(mode), C.dev_t(dev))
		if err := fetchError(r); err != nil {
			return err
		} else if ret < 0 {
			return ErrClosedObject
		}
		return nil
	})
}

// Hardlink creates a hardlink within a Root's directory tree. The hardlink is
// created at @path and is a link to @target. Both paths are within the Root's
// directory tree (you cannot hardlink to a different Root or the host).
func (r *Root) Hardlink(path, target string) error {
	return r.withInner(func(_ pathrsObject) error {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		cTarget := C.CString(target)
		defer C.free(unsafe.Pointer(cTarget))

		ret := C.pathrs_hardlink(r.ptr, cPath, cTarget)
		if err := fetchError(r); err != nil {
			return err
		} else if ret < 0 {
			return ErrClosedObject
		}
		return nil
	})
}

// Symlink creates a symlink within a Root's directory tree. The symlink is
// created at @path and is a link to @target.
func (r *Root) Symlink(path, target string) error {
	return r.withInner(func(_ pathrsObject) error {
		cPath := C.CString(path)
		defer C.free(unsafe.Pointer(cPath))

		cTarget := C.CString(target)
		defer C.free(unsafe.Pointer(cTarget))

		ret := C.pathrs_symlink(r.ptr, cPath, cTarget)
		if err := fetchError(r); err != nil {
			return err
		} else if ret < 0 {
			return ErrClosedObject
		}
		return nil
	})
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
	// TODO: Make an abstracted version of IntoRaw that just uses pathrsObject.
	var file *os.File
	err := r.withInner(func(_ pathrsObject) error {
		name, err := randName(32)
		if err != nil {
			return err
		}

		fd := int(C.pathrs_into_fd(r.inner()))
		if err := fetchError(r); err != nil {
			return err
		} else if fd < 0 {
			return ErrClosedObject
		}

		file = os.NewFile(uintptr(fd), "pathrs-raw-root:"+name)
		return nil
	})
	return file, err
}

// Clone creates a copy of a Root handle, such that it has a separate lifetime
// to the original (while refering to the same underlying directory).
func (r *Root) Clone() (*Root, error) {
	var root *Root
	err := r.withInner(func(_ pathrsObject) error {
		newInner := (*C.pathrs_root_t)(C.pathrs_duplicate(r.inner()))
		if err := fetchError(r); err != nil {
			return err
		} else if newInner == nil {
			return ErrClosedObject
		}

		root = &Root{ptr: newInner}
		return nil
	})
	return root, err
}

// Close frees all of the resources used by the Root handle. The handle must
// not be used for any future operations.
func (r *Root) Close() error {
	if r == nil {
		return ErrInvalidObject
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	// Free the underlying structure.
	C.pathrs_free(r.inner())
	// Make sure we don't double-free by clearing the inner pointer.
	r.ptr = nil
	return nil
}

// Handle is a handle for a path within a given Root. This handle references an
// already-resolved path which can be used for only one purpose -- to "re-open"
// the handle and get an actual fs::File which can be used for ordinary
// operations.
//
// It is critical that perform all relevant operations through this Handle
// (rather than fetching the file descriptor yourself with IntoRaw), because
// the security properties of libpathrs depend on users doing all relevant
// filesystem operations through libpathrs.
type Handle struct {
	lock sync.RWMutex
	ptr  *C.pathrs_handle_t
}

// inner returns the (type, pointer) tuple for the underlying FFI-managed
// object.
func (h *Handle) inner() (C.pathrs_type_t, unsafe.Pointer) {
	return C.PATHRS_HANDLE, unsafe.Pointer(h.ptr)
}

// withInner runs a callback such that it is safe to operate on the pointer
// returned from inner(). ErrClosedObject will be returned if the object
// has been Close()'d, and ErrInvalidObject if the object is invalid.
func (h *Handle) withInner(fn func(pathrsObject) error) error {
	if h == nil {
		return ErrInvalidObject
	}

	// libpathrs has thread-local error handling, so we can't allow Go to
	// switch us between threads between the operation and fetching the error.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Protects the libpathrs object from being freed underneath us.
	h.lock.RLock()
	defer h.lock.RUnlock()

	if h.ptr == nil {
		return ErrClosedObject
	}
	return fn(h)
}

// HandleFromRaw creates a new Handle from an exisitng file handle. The handle
// will be copied by this method, so the original handle should still be freed
// by the caller.
//
// This is effectively the inverse operation of Handle.IntoRaw, and is used for
// "deserialising" pathrs root handles.
func HandleFromRaw(file *os.File) (*Handle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fd := file.Fd()

	inner := (*C.pathrs_handle_t)(C.pathrs_from_fd(C.PATHRS_HANDLE, C.int(fd)))
	handle := &Handle{ptr: inner}
	if err := fetchError(handle); err != nil {
		return nil, err
	} else if inner == nil {
		return nil, ErrClosedObject
	}
	return handle, nil
}

// Open creates an "upgraded" file handle to the file referenced by the Handle.
// Note that the original Handle is not consumed by this operation, and can be
// opened multiple times.
//
// The handle returned is only usable for reading, and this is method is
// shorthand for handle.OpenFile(os.O_RDONLY).
//
// TODO: Rename these to "Reopen" or something.
func (h *Handle) Open() (*os.File, error) {
	return h.OpenFile(os.O_RDONLY)
}

// OpenFile creates an "upgraded" file handle to the file referenced by the
// Handle. Note that the original Handle is not consumed by this operation, and
// can be opened multiple times.
//
// The provided flags indicate which open(2) flags are used to create the new
// handle.
//
// TODO: Rename these to "Reopen" or something.
func (h *Handle) OpenFile(flags int) (*os.File, error) {
	var file *os.File
	err := h.withInner(func(_ pathrsObject) error {
		name, err := randName(32)
		if err != nil {
			return err
		}

		fd := C.pathrs_reopen(h.ptr, C.int(flags))
		if err := fetchError(h); err != nil {
			return err
		} else if fd < 0 {
			return ErrClosedObject
		}

		file = os.NewFile(uintptr(fd), "pathrs-reopened:"+name)
		return nil
	})
	return file, err
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
	// TODO: Make an abstracted version of IntoRaw that just uses pathrsObject.
	var file *os.File
	err := h.withInner(func(_ pathrsObject) error {
		name, err := randName(32)
		if err != nil {
			return err
		}

		fd := int(C.pathrs_into_fd(h.inner()))
		if err := fetchError(h); err != nil {
			return err
		} else if fd < 0 {
			return ErrClosedObject
		}

		file = os.NewFile(uintptr(fd), "pathrs-raw-handle:"+name)
		return nil
	})
	return file, err
}

// Clone creates a copy of a Handle, such that it has a separate lifetime to
// the original (while refering to the same underlying file).
func (h *Handle) Clone() (*Handle, error) {
	var handle *Handle
	err := h.withInner(func(_ pathrsObject) error {
		newInner := (*C.pathrs_handle_t)(C.pathrs_duplicate(h.inner()))
		if err := fetchError(h); err != nil {
			return err
		} else if newInner == nil {
			return ErrClosedObject
		}
		handle = &Handle{ptr: newInner}
		return nil
	})
	return handle, err
}

// Close frees all of the resources used by the Handle. The handle must not be
// used for any future operations.
func (h *Handle) Close() error {
	if h == nil {
		return ErrInvalidObject
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	// Free the underlying structure.
	C.pathrs_free(h.inner())
	// Make sure we don't double-free by clearing the inner pointer.
	h.ptr = nil
	return nil
}

// randName generates a random hexadecimal name that is used for the Go-level
// "file name" of libpathrs-generated files, and can be used to help with
// debugging.
func randName(k int) (string, error) {
	randBuf := make([]byte, k/2)

	if n, err := rand.Read(randBuf); err != nil {
		return "", err
	} else if n != len(randBuf) {
		return "", fmt.Errorf("rand.Read didn't return enough bytes (%d != %d)", n, len(randBuf))
	}

	var nameBuf strings.Builder
	for _, b := range randBuf {
		nameBuf.WriteString(fmt.Sprintf("%.2x", b))
	}
	return nameBuf.String(), nil
}

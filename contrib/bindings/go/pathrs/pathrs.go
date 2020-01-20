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

// Package pathrs provides a bindings for libpathrs, a library for safe path resolution on Linux.
package pathrs

// #cgo LDFLAGS: -lpathrs
// #include <pathrs.h>
import "C"
import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Root holds the responsibility to provide safe api to functions of pathrs root api
type Root struct {
	root *C.pathrs_root_t
}

// Open opens directory as a root directory
func Open(path string) (*Root, error) {
	root := C.pathrs_open(C.CString(path))
	err := handleErr(C.PATHRS_ROOT, unsafe.Pointer(root))
	if err != nil {
		return nil, err
	}

	return &Root{root: root}, nil
}

// RootFromFile constructs a new file-based libpathrs object of root from a file descriptor
// Uses often in combination with Root.IntoFile methood
func RootFromFile(file *os.File) (*Root, error) {
	fd := file.Fd()
	root := (*C.pathrs_root_t)(C.pathrs_from_fd(C.PATHRS_ROOT, C.int(fd)))
	err := handleErr(C.PATHRS_ROOT, unsafe.Pointer(root))
	if err != nil {
		return nil, err
	}

	return &Root{root: root}, nil
}

// Resolve resolves the given path within the given root's tree
// and return a handle to that path. The path must
// already exist, otherwise an error will occur.
func (r *Root) Resolve(path string) (*Handle, error) {
	handler := C.pathrs_resolve(r.root, C.CString(path))
	if handler == nil {
		return nil, handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
	}

	return &Handle{handle: handler}, nil
}

// Create creates a file with a such mode by path according with the root path
func (r *Root) Create(path string, mode uint) (*Handle, error) {
	handler := C.pathrs_creat(r.root, C.CString(path), C.uint(mode))
	if handler == nil {
		return nil, handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
	}

	return &Handle{handle: handler}, nil
}

// Rename Within the given root's tree, perform the rename of src to dst,
// or change flags on this file if the names are the same it's only change the flags
func (r *Root) Rename(src, dst string, flags int) error {
	C.pathrs_rename(r.root, C.CString(src), C.CString(dst), C.int(flags))
	return handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
}

// Mkdir creates a directory with a such mode by path
func (r *Root) Mkdir(path string, mode uint) error {
	C.pathrs_mkdir(r.root, C.CString(path), C.uint(mode))
	return handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
}

// Mknod creates a filesystem node named path
// with attributes mode and dev
func (r *Root) Mknod(path string, mode uint, dev int) error {
	C.pathrs_mknod(r.root, C.CString(path), C.uint(mode), C.dev_t(dev))
	return handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
}

// Hardlink creates a hardlink of file named target and place it to path
func (r *Root) Hardlink(path, target string) error {
	C.pathrs_hardlink(r.root, C.CString(path), C.CString(target))
	return handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
}

// Symlink creates a symlink of file named target and place it to path
func (r *Root) Symlink(path, target string) error {
	C.pathrs_symlink(r.root, C.CString(path), C.CString(target))
	return handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
}

// IntoFile unwraps a file-based libpathrs object to obtain its underlying file
// descriptor.
//
// It is critical that you do not operate on this file descriptor yourself,
// because the security properties of libpathrs depend on users doing all
// relevant filesystem operations through libpathrs.
func (r *Root) IntoFile() (*os.File, error) {
	cloned, err := r.Clone()
	if err != nil {
		return nil, err
	}

	fd := int(C.pathrs_into_fd(C.PATHRS_ROOT, unsafe.Pointer(cloned.root)))
	if fd < 0 {
		return nil, handleErr(C.PATHRS_ROOT, unsafe.Pointer(cloned.root))
	}

	name, err := randName(32)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(fd), "pathrs-root:"+name), nil
}

// Clone creates a copy of root handler the new object will have a separate lifetime
// from the original, but will refer to the same underlying file
func (r *Root) Clone() (*Root, error) {
	newRoot := (*C.pathrs_root_t)(C.pathrs_duplicate(C.PATHRS_ROOT, unsafe.Pointer(r.root)))
	err := handleErr(C.PATHRS_ROOT, unsafe.Pointer(r.root))
	if err != nil {
		return nil, err
	}

	return &Root{root: newRoot}, nil
}

// Close frees underling caught resources
func (r *Root) Close() {
	if r != nil {
		C.pathrs_free(C.PATHRS_ROOT, unsafe.Pointer(r.root))
	}
}

// Handle represents an handle pathrs api interface
type Handle struct {
	handle *C.pathrs_handle_t
}

// HandleFromFd constructs a new file-based libpathrs object of handle from a file descriptor
// Uses often in combination with Handle.IntoFd methood
func HandleFromFd(fd int) (*Handle, error) {
	handler := (*C.pathrs_handle_t)(C.pathrs_from_fd(C.PATHRS_HANDLE, C.int(fd)))
	err := handleErr(C.PATHRS_HANDLE, unsafe.Pointer(handler))
	if err != nil {
		return nil, err
	}

	return &Handle{handle: handler}, nil
}

// Open upgrade the handle to a file representation
// which holds a usable fd, suitable for reading
func (h *Handle) Open() (*os.File, error) {
	return h.OpenFile(os.O_RDONLY)
}

// OpenFile upgrade the handle to a file representation
// which holds a usable fd, with a specific settings by provided flags
func (h *Handle) OpenFile(flags int) (*os.File, error) {
	fd := C.pathrs_reopen(h.handle, C.int(flags))
	err := handleErr(C.PATHRS_HANDLE, unsafe.Pointer(h.handle))
	if err != nil {
		return nil, err
	}

	name, err := randName(32)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "pathrs-handle:"+name)
	return file, nil
}

// IntoFd unwraps a file-based libpathrs object to obtain its underlying file
// descriptor.
//
// It is critical that you do not operate on this file descriptor yourself,
// because the security properties of libpathrs depend on users doing all
// relevant filesystem operations through libpathrs.
func (h *Handle) IntoFd() (int, error) {
	fd := int(C.pathrs_into_fd(C.PATHRS_HANDLE, unsafe.Pointer(h.handle)))
	if fd < 0 {
		return 0, handleErr(C.PATHRS_HANDLE, unsafe.Pointer(h.handle))
	}

	return fd, nil
}

// Clone creates a copy of root handler the new object will have a separate lifetime
// from the original, but will refer to the same underlying file
func (h *Handle) Clone() (*Handle, error) {
	newHandler := (*C.pathrs_handle_t)(C.pathrs_duplicate(C.PATHRS_HANDLE, unsafe.Pointer(h.handle)))
	err := handleErr(C.PATHRS_HANDLE, unsafe.Pointer(h.handle))
	if err != nil {
		return nil, err
	}

	return &Handle{handle: newHandler}, nil
}

// Close frees underling caught resources
func (h *Handle) Close() {
	if h != nil {
		C.pathrs_free(C.PATHRS_HANDLE, unsafe.Pointer(h.handle))
	}
}

// Error representation of rust error
// particularly useful to not frighten to lost controll of pointer which can be rewritten.
type Error struct {
	description string
	errno       uint64
	backtrace   []backtraceLine
}

type backtraceLine struct {
	ip       uintptr
	sAddress uintptr
	sName    string
	sFile    string
	sLineno  uint32
}

func (err *Error) Error() string {
	return err.description
}

func (e *Error) Unwrap() error {
	if e.errno != 0 {
		return syscall.Errno(e.errno)
	}

	return nil
}

// Backtrace flush backtrace of underlying error to string.
//
// Its not passed to realization of Error interface on purpose since
// the main error should remain clear and simple
func (err *Error) Backtrace() string {
	buf := strings.Builder{}

	for _, line := range err.backtrace {
		if line.sName != "" {
			buf.WriteString(fmt.Sprintf("'%s'@", line.sName))
		}
		buf.WriteString(fmt.Sprintf("<0x%x>+0x%x\n", line.sAddress, line.ip-line.sAddress))
		if line.sFile != "" {
			buf.WriteString(fmt.Sprintf("  in file '%s':%d\n", line.sFile, line.sLineno))
		}
	}

	return buf.String()
}

func newError(e *C.pathrs_error_t) error {
	if e == nil {
		return nil
	}

	err := &Error{
		errno:       uint64(e.saved_errno),
		description: C.GoString(e.description),
		backtrace:   nil,
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

func handleErr(ptrType C.pathrs_type_t, ptr unsafe.Pointer) error {
	err := C.pathrs_error(ptrType, ptr)
	defer C.pathrs_free(C.PATHRS_ERROR, unsafe.Pointer(err))
	return newError(err)
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

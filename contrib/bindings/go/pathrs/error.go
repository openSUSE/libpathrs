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

package pathrs

// #cgo LDFLAGS: -lpathrs
// #include <pathrs.h>
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Error represents an underlying libpathrs error.
type Error struct {
	description string
	errno       syscall.Errno
	backtrace   []backtraceLine
}

type backtraceLine struct {
	ip       uintptr
	sAddress uintptr
	sName    string
	sFile    string
	sLineno  uint32
}

// Error returns a textual description of the error.
func (err *Error) Error() string {
	return err.description
}

// Unwrap returns the underlying error which was wrapped by this error (if
// applicable).
func (err *Error) Unwrap() error {
	if err.errno != 0 {
		return err.errno
	}
	return nil
}

// Backtrace returns a textual backtrace of the the call-stack when the error
// was triggered within libpathrs. Depending on the (build and runtime)
// configuration of libpathrs, this may return differing levels of information.
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

func fetchError(obj pathrsObject) error {
	err := C.pathrs_error(obj.inner())
	defer C.pathrs_free(C.PATHRS_ERROR, unsafe.Pointer(err))
	return newError(err)
}

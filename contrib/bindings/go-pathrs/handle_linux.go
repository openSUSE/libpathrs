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
)

// Handle is a handle for a path within a given Root. This handle references an
// already-resolved path which can be used for only one purpose -- to "re-open"
// the handle and get an actual *os.File which can be used for ordinary
// operations.
//
// It is critical that perform all relevant operations through this Handle
// (rather than fetching the file descriptor yourself with IntoRaw), because
// the security properties of libpathrs depend on users doing all relevant
// filesystem operations through libpathrs.
type Handle struct {
	inner *os.File
}

// HandleFromFile creates a new Handle from an exisitng file handle. The handle
// will be copied by this method, so the original handle should still be freed
// by the caller.
//
// This is effectively the inverse operation of Handle.IntoRaw, and is used for
// "deserialising" pathrs root handles.
func HandleFromFile(file *os.File) (*Handle, error) {
	newFile, err := dupFile(file)
	if err != nil {
		return nil, fmt.Errorf("duplicate handle fd: %w", err)
	}
	return &Handle{inner: newFile}, nil
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
	return withFileFd(h.inner, func(fd uintptr) (*os.File, error) {
		newFd, err := pathrsReopen(fd, flags)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(newFd), h.inner.Name()), nil
	})
}

// IntoFile unwraps the Handle into its underlying *os.File.
//
// You almost certainly want to use OpenFile() to get a non-O_PATH version of
// this Handle.
//
// This operation returns the internal *os.File of the Handle directly, so
// Close()ing the Handle will also close any copies of the returned *os.File.
// If you want to get an independent copy, use Clone().IntoFile().
func (h *Handle) IntoFile() *os.File {
	// TODO: Figure out if we really don't want to make a copy.
	// TODO: We almost certainly want to clear r.inner here, but we can't do
	//       that easily atomically (we could use atomic.Value but that'll make
	//       things quite a bit uglier).
	return h.inner
}

// Clone creates a copy of a Handle, such that it has a separate lifetime to
// the original (while refering to the same underlying file).
func (h *Handle) Clone() (*Handle, error) {
	return HandleFromFile(h.inner)
}

// Close frees all of the resources used by the Handle.
func (h *Handle) Close() error {
	return h.inner.Close()
}

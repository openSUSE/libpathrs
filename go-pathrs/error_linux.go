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
)

// Error represents an underlying libpathrs error.
type Error struct {
	description string
	errno       syscall.Errno
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

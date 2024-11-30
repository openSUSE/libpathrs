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
	"errors"
	"fmt"
	"os"
	"syscall"
)

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
	inner *os.File
}

// OpenRoot creates a new Root handle to the directory at the given path.
func OpenRoot(path string) (*Root, error) {
	fd, err := pathrsOpenRoot(path)
	if err != nil {
		return nil, err
	}
	file, err := mkFile(fd)
	if err != nil {
		return nil, err
	}
	return &Root{inner: file}, nil
}

// RootFromFile creates a new Root handle from an *os.File referencing a
// directory. The provided file will be duplicated, so the original file should
// still be Close()d by the caller.
//
// This is effectively the inverse operation of Root.IntoFile.
func RootFromFile(file *os.File) (*Root, error) {
	newFile, err := dupFile(file)
	if err != nil {
		return nil, fmt.Errorf("duplicate root fd: %w", err)
	}
	return &Root{inner: newFile}, nil
}

// Resolve resolves the given path within the Root's directory tree, and return
// a Handle to the resolved path. The path must already exist, otherwise an
// error will occur.
//
// All symlinks (including trailing symlinks) are followed, but they are
// resolved within the rootfs. If you wish to open a handle to the symlink
// itself, use ResolveNoFollow.
func (r *Root) Resolve(path string) (*Handle, error) {
	return withFileFd(r.inner, func(rootFd uintptr) (*Handle, error) {
		handleFd, err := pathrsInRootResolve(rootFd, path)
		if err != nil {
			return nil, err
		}
		handleFile, err := mkFile(handleFd)
		if err != nil {
			return nil, err
		}
		return &Handle{inner: handleFile}, nil
	})
}

// ResolveNoFollow is effectively an O_NOFOLLOW version of Resolve. Their
// behaviour is identical, except that *trailing* symlinks will not be
// followed. If the final component is a trailing symlink, an O_PATH|O_NOFOLLOW
// handle to the symlink itself is returned.
func (r *Root) ResolveNoFollow(path string) (*Handle, error) {
	return withFileFd(r.inner, func(rootFd uintptr) (*Handle, error) {
		handleFd, err := pathrsInRootResolveNoFollow(rootFd, path)
		if err != nil {
			return nil, err
		}
		handleFile, err := mkFile(handleFd)
		if err != nil {
			return nil, err
		}
		return &Handle{inner: handleFile}, nil
	})
}

// Create creates a file within the Root's directory tree at the given path,
// and returns a handle to the file. The provided mode is used for the new file
// (the process's umask applies).
func (r *Root) Create(path string, flags int, mode os.FileMode) (*os.File, error) {
	unixMode, err := toUnixMode(mode)
	if err != nil {
		return nil, err
	}
	return withFileFd(r.inner, func(rootFd uintptr) (*os.File, error) {
		handleFd, err := pathrsInRootCreat(rootFd, path, flags, unixMode)
		if err != nil {
			return nil, err
		}
		return mkFile(handleFd)
	})
}

// Rename two paths within a Root's directory tree. The flags argument is
// identical to the RENAME_* flags to the renameat2(2) system call.
func (r *Root) Rename(src, dst string, flags uint) error {
	_, err := withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootRename(rootFd, src, dst, flags)
		return struct{}{}, err
	})
	return err
}

// RemoveDir removes the named empty directory within a Root's directory tree.
func (r *Root) RemoveDir(path string) error {
	_, err := withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootRmdir(rootFd, path)
		return struct{}{}, err
	})
	return err
}

// RemoveFile removes the named file within a Root's directory tree.
func (r *Root) RemoveFile(path string) error {
	_, err := withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootUnlink(rootFd, path)
		return struct{}{}, err
	})
	return err
}

// Remove removes the named file or (empty) directory within a Root's directory
// tree. This is designed to match the semantics of os.Remove.
func (r *Root) Remove(path string) error {
	// In order to match os.Remove's implementation we need to also do both
	// syscalls unconditionally and adjust the error based on whether
	// pathrs_inroot_rmdir() returned ENOTDIR.
	unlinkErr := r.RemoveFile(path)
	if unlinkErr == nil {
		return nil
	}
	rmdirErr := r.RemoveDir(path)
	if rmdirErr == nil {
		return nil
	}
	// Both failed, adjust the error in the same way that os.Remove does.
	err := rmdirErr
	if errors.Is(err, syscall.ENOTDIR) {
		err = unlinkErr
	}
	return err
}

// RemoveAll recursively deletes a path and all of its children. This is
// designed to match the semantics of os.RemoveAll.
func (r *Root) RemoveAll(path string) error {
	_, err := withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootRemoveAll(rootFd, path)
		return struct{}{}, err
	})
	return err
}

// Mkdir creates a directory within a Root's directory tree. The provided mode
// is used for the new directory (the process's umask applies).
func (r *Root) Mkdir(path string, mode os.FileMode) error {
	unixMode, err := toUnixMode(mode)
	if err != nil {
		return err
	}

	_, err = withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootMkdir(rootFd, path, unixMode)
		return struct{}{}, err
	})
	return err
}

// MkdirAll creates a directory (and any parent path components if they don't
// exist) within a Root's directory tree. The provided mode is used for any
// directories created by this function (the process's umask applies).
//
// This is effectively equivalent to os.MkdirAll.
func (r *Root) MkdirAll(path string, mode os.FileMode) (*Handle, error) {
	unixMode, err := toUnixMode(mode)
	if err != nil {
		return nil, err
	}

	return withFileFd(r.inner, func(rootFd uintptr) (*Handle, error) {
		handleFd, err := pathrsInRootMkdirAll(rootFd, path, unixMode)
		if err != nil {
			return nil, err
		}
		handleFile, err := mkFile(handleFd)
		if err != nil {
			return nil, err
		}
		return &Handle{inner: handleFile}, err
	})
}

// Mknod creates a new device inode of the given type within a Root's directory
// tree. The provided mode is used for the new directory (the process's umask
// applies).
func (r *Root) Mknod(path string, mode os.FileMode, dev uint64) error {
	unixMode, err := toUnixMode(mode)
	if err != nil {
		return err
	}

	_, err = withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootMknod(rootFd, path, unixMode, dev)
		return struct{}{}, err
	})
	return err
}

// Symlink creates a symlink within a Root's directory tree. The symlink is
// created at @path and is a link to @target.
func (r *Root) Symlink(path, target string) error {
	_, err := withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootSymlink(rootFd, path, target)
		return struct{}{}, err
	})
	return err
}

// Hardlink creates a hardlink within a Root's directory tree. The hardlink is
// created at @path and is a link to @target. Both paths are within the Root's
// directory tree (you cannot hardlink to a different Root or the host).
func (r *Root) Hardlink(path, target string) error {
	_, err := withFileFd(r.inner, func(rootFd uintptr) (struct{}, error) {
		err := pathrsInRootHardlink(rootFd, path, target)
		return struct{}{}, err
	})
	return err
}

// IntoFile unwraps the Root into its underlying *os.File.
//
// It is critical that you do not operate on this file descriptor yourself,
// because the security properties of libpathrs depend on users doing all
// relevant filesystem operations through libpathrs.
//
// This operation returns the internal *os.File of the Root directly, so
// Close()ing the Root will also close any copies of the returned *os.File. If
// you want to get an independent copy, use Clone().IntoFile().
func (r *Root) IntoFile() *os.File {
	// TODO: Figure out if we really don't want to make a copy.
	// TODO: We almost certainly want to clear r.inner here, but we can't do
	//       that easily atomically (we could use atomic.Value but that'll make
	//       things quite a bit uglier).
	return r.inner
}

// Clone creates a copy of a Root handle, such that it has a separate lifetime
// to the original (while referring to the same underlying directory).
func (r *Root) Clone() (*Root, error) {
	return RootFromFile(r.inner)
}

// Close frees all of the resources used by the Root handle.
func (r *Root) Close() error {
	return r.inner.Close()
}

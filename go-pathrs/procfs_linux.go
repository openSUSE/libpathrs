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
	"os"
	"runtime"
)

// ProcBase is used with [ProcReadlink] and related functions to indicate what
// /proc subpath path operations should be done relative to.
type ProcBase struct {
	inner pathrsProcBase
}

var (
	// ProcBaseRoot indicates to use /proc. Note that this mode may be more
	// expensive because we have to take steps to try to avoid leaking unmasked
	// procfs handles, so you should use [ProcBaseSelf] if you can.
	ProcBaseRoot = ProcBase{inner: pathrsProcRoot}
	// ProcBaseSelf indicates to use /proc/self. For most programs, this is the
	// standard choice.
	ProcBaseSelf = ProcBase{inner: pathrsProcSelf}
	// ProcBaseThreadSelf indicates to use /proc/thread-self. In multi-threaded
	// programs where one thread has a different CLONE_FS, it is possible for
	// /proc/self to point the wrong thread and so /proc/thread-self may be
	// necessary.
	ProcBaseThreadSelf = ProcBase{inner: pathrsProcThreadSelf}
)

// ProcBasePid returns a ProcBase which indicates to use /proc/$pid for the
// given PID (or TID). Be aware that due to PID recycling, using this is
// generally not safe except in certain circumstances. Namely:
//
//   - PID 1 (the init process), as that PID cannot ever get recycled.
//   - Your current PID (though you should just use [ProcBaseSelf]).
//   - Your current TID if you have used [runtime.LockOSThread] (though you
//     should just use [ProcBaseThreadSelf]).
//   - PIDs of child processes (as long as you are sure that no other part of
//     your program incorrectly catches or ignores SIGCHLD, and that you do it
//     *before* you call wait(2)or any equivalent method that could reap
//     zombies).
func ProcBasePid(pid int) ProcBase {
	if pid < 0 || pid >= 1<<31 {
		panic("invalid ProcBasePid value") // TODO: should this be an error?
	}
	return ProcBase{inner: pathrsProcPid(uint32(pid))}
}

func (b ProcBase) namePrefix() string {
	switch b {
	case ProcBaseRoot:
		return "/proc/"
	case ProcBaseSelf:
		return "/proc/self/"
	case ProcBaseThreadSelf:
		return "/proc/thread-self/"
	}
	switch b.inner & pathrsProcBaseTypeMask { //nolint:exhaustive // we only care about some types
	case pathrsProcBaseTypePid:
		return fmt.Sprintf("/proc/%d/", b.inner&^pathrsProcBaseTypeMask)
	default:
	}
	return "<invalid procfs base>/"
}

// ProcHandleCloser is a callback that needs to be called when you are done
// operating on an [os.File] fetched using [ProcThreadSelfOpen].
//
// [os.File]: https://pkg.go.dev/os#File
type ProcHandleCloser func()

// TODO: Should we expose procOpen?
func procOpen(base ProcBase, path string, flags int) (*os.File, ProcHandleCloser, error) {
	namePrefix := base.namePrefix()

	switch base {
	case ProcBaseThreadSelf:
		runtime.LockOSThread()
		fd, err := pathrsProcOpen(base.inner, path, flags)
		if err != nil {
			runtime.UnlockOSThread()
			return nil, nil, err
		}
		return os.NewFile(fd, namePrefix+path), runtime.UnlockOSThread, nil
	default:
		fd, err := pathrsProcOpen(base.inner, path, flags)
		if err != nil {
			return nil, nil, err
		}
		return os.NewFile(fd, namePrefix+path), nil, nil
	}
}

// ProcRootOpen safely opens a given path from inside /proc/.
//
// This function must only be used for accessing global information from procfs
// (such as /proc/cpuinfo) or information about other processes (such as
// /proc/1). Accessing your own process information should be done using
// [ProcSelfOpen] or [ProcThreadSelfOpen].
func ProcRootOpen(path string, flags int) (*os.File, error) {
	file, closer, err := procOpen(ProcBaseRoot, path, flags)
	if closer != nil {
		// should not happen
		panic("non-zero closer returned from procOpen(ProcBaseRoot)")
	}
	return file, err
}

// ProcSelfOpen safely opens a given path from inside /proc/self/.
//
// This method is recommend for getting process information about the current
// process for almost all Go processes *except* for cases where there are
// [runtime.LockOSThread] threads that have changed some aspect of their state
// (such as through unshare(CLONE_FS) or changing namespaces).
//
// For such non-heterogeneous processes, /proc/self may reference to a task
// that has different state from the current goroutine and so it may be
// preferable to use [ProcThreadSelfOpen]. The same is true if a user really
// wants to inspect the current OS thread's information (such as
// /proc/thread-self/stack or /proc/thread-self/status which is always uniquely
// per-thread).
//
// Unlike [ProcThreadSelfOpen], this method does not involve locking the
// goroutine to the current OS thread and so is simpler to use and
// theoretically has slightly less overhead.
//
// [runtime.LockOSThread]: https://pkg.go.dev/runtime#LockOSThread
func ProcSelfOpen(path string, flags int) (*os.File, error) {
	file, closer, err := procOpen(ProcBaseSelf, path, flags)
	if closer != nil {
		// should not happen
		panic("non-zero closer returned from procOpen(ProcBaseSelf)")
	}
	return file, err
}

// ProcPidOpen safely opens a given path from inside /proc/$pid/, where pid can
// be either a PID or TID.
//
// This is effectively equivalent to calling [ProcRootOpen] with the pid
// prefixed to the subpath.
//
// Be aware that due to PID recycling, using this is generally not safe except
// in certain circumstances. See the documentation of [ProcBasePid] for more
// details.
func ProcPidOpen(pid int, path string, flags int) (*os.File, error) {
	file, closer, err := procOpen(ProcBasePid(pid), path, flags)
	if closer != nil {
		// should not happen
		panic("non-zero closer returned from procOpen(ProcPidOpen)")
	}
	return file, err
}

// ProcThreadSelfOpen safely opens a given path from inside /proc/thread-self/.
//
// Most Go processes have heterogeneous threads (all threads have most of the
// same kernel state such as CLONE_FS) and so [ProcSelfOpen] is preferable for
// most users.
//
// For non-heterogeneous threads, or users that actually want thread-specific
// information (such as /proc/thread-self/stack or /proc/thread-self/status),
// this method is necessary.
//
// Because Go can change the running OS thread of your goroutine without notice
// (and then subsequently kill the old thread), this method will lock the
// current goroutine to the OS thread (with [runtime.LockOSThread]) and the
// caller is responsible for unlocking the the OS thread with the
// ProcHandleCloser callback once they are done using the returned file. This
// callback MUST be called AFTER you have finished using the returned
// [os.File]. This callback is completely separate to [os.File.Close], so it
// must be called regardless of how you close the handle.
//
// [runtime.LockOSThread]: https://pkg.go.dev/runtime#LockOSThread
// [os.File]: https://pkg.go.dev/os#File
// [os.File.Close]: https://pkg.go.dev/os#File.Close
func ProcThreadSelfOpen(path string, flags int) (*os.File, ProcHandleCloser, error) {
	return procOpen(ProcBaseThreadSelf, path, flags)
}

// ProcReadlink safely reads the contents of a symlink from the given procfs
// base.
//
// This is effectively equivalent to doing a Proc*Open(O_PATH|O_NOFOLLOW) of
// the path and then doing unix.Readlinkat(fd, ""), but with the benefit that
// thread locking is not necessary for [ProcBaseThreadSelf].
func ProcReadlink(base ProcBase, path string) (string, error) {
	return pathrsProcReadlink(base.inner, path)
}

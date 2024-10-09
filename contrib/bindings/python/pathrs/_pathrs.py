#!/usr/bin/python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019-2024 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import os
import re
import sys
import copy
import errno
import fcntl

import typing
from types import TracebackType
from typing import Any, Dict, IO, Optional, TextIO, Type, TypeVar, Union

# TODO: Remove this once we only support Python >= 3.11.
from typing_extensions import Self, TypeAlias

from ._libpathrs_cffi import lib as libpathrs_so

if typing.TYPE_CHECKING:
    # mypy apparently cannot handle the "ffi: cffi.api.FFI" definition in
    # _libpathrs_cffi/__init__.pyi so we need to explicitly reference the type
    # from cffi here.
    import cffi

    ffi = cffi.FFI()
    CString: TypeAlias = cffi.FFI.CData
    CBuffer: TypeAlias = cffi.FFI.CData
else:
    from ._libpathrs_cffi import ffi

    CString: TypeAlias = ffi.CData
    CBuffer: TypeAlias = ffi.CData

__all__ = [
    # core api
    "Root",
    "Handle",
    # procfs api
    "PROC_ROOT",
    "PROC_SELF",
    "PROC_THREAD_SELF",
    "proc_open",
    "proc_open_raw",
    "proc_readlink",
    # error api
    "Error",
]


def _cstr(pystr: str) -> CString:
    return ffi.new("char[]", pystr.encode("utf8"))


def _pystr(cstr: CString) -> str:
    s = ffi.string(cstr)
    assert isinstance(s, bytes)  # typing
    return s.decode("utf8")


def _cbuffer(size: int) -> CBuffer:
    return ffi.new("char[%d]" % (size,))


class Error(Exception):
    """
    Represents a libpathrs error. All libpathrs errors have a description
    (Error.message) and errors that were caused by an underlying OS error (or
    can be translated to an OS error) also include the errno value
    (Error.errno).
    """

    message: str
    errno: Optional[int]
    strerror: Optional[str]

    def __init__(self, message: str, /, *, errno: Optional[int] = None):
        # Construct Exception.
        super().__init__(message)

        # Basic arguments.
        self.message = message
        self.errno = errno

        # Pre-format the errno.
        self.strerror = None
        if errno is not None:
            try:
                self.strerror = os.strerror(errno)
            except ValueError:
                self.strerror = str(errno)

    @classmethod
    def _fetch(cls, err_id: int, /) -> Optional[Self]:
        if err_id >= 0:
            return None

        err = libpathrs_so.pathrs_errorinfo(err_id)
        if err == ffi.NULL:  # type: ignore # TODO: Make this check nicer...
            return None

        description = _pystr(err.description)
        errno = err.saved_errno or None

        # TODO: Should we use ffi.gc()? mypy doesn't seem to like our types...
        libpathrs_so.pathrs_errorinfo_free(err)
        del err

        return cls(description, errno=errno)

    def __str__(self) -> str:
        if self.errno is None:
            return self.message
        else:
            return "%s (%s)" % (self.message, self.strerror)

    def __repr__(self) -> str:
        return "Error(%r, errno=%r)" % (self.message, self.errno)

    def pprint(self, out: TextIO = sys.stdout) -> None:
        "Pretty-print the error to the given @out file."
        # Basic error information.
        if self.errno is None:
            print("pathrs error:", file=out)
        else:
            print("pathrs error [%s]:" % (self.strerror,), file=out)
        print("  %s" % (self.message,), file=out)


INTERNAL_ERROR = Error("tried to fetch libpathrs error but no error found")


class FilenoFile(typing.Protocol):
    def fileno(self) -> int: ...


FileLike = Union[FilenoFile, int]


def _fileno(file: FileLike) -> int:
    if isinstance(file, int):
        # file is a plain fd
        return file
    else:
        # Assume there is a fileno method.
        return file.fileno()


def _clonefile(file: FileLike) -> int:
    return fcntl.fcntl(_fileno(file), fcntl.F_DUPFD_CLOEXEC)


# TODO: Switch to def foo[T](...): ... syntax with Python >= 3.12.
Fd = TypeVar("Fd", bound="WrappedFd")


class WrappedFd(object):
    """
    Represents a file descriptor that allows for manual lifetime management,
    unlike os.fdopen() which are tracked by the GC with no way of "leaking" the
    file descriptor for FFI purposes.

    pathrs will return WrappedFds for most operations that return an fd.
    """

    _fd: Optional[int]

    def __init__(self, file: FileLike, /):
        """
        Construct a WrappedFd from any file-like object.

        For most cases, the WrappedFd will take ownership of the lifetime of
        the file handle. This means you should  So a raw file descriptor must
        only be turned into a WrappedFd *once* (unless you make sure to use
        WrappedFd.leak() to ensure there is only ever one owner of the handle
        at a given time).

        However, for os.fdopen() (or similar Pythonic file objects that are
        tracked by the GC), we have to create a clone and so the WrappedFd is a
        copy.
        """
        # TODO: Maybe we should always clone to make these semantics less
        # confusing...?
        fd = _fileno(file)
        if isinstance(file, io.IOBase):
            # If this is a regular open file, we need to make a copy because
            # you cannot leak files and so the GC might close it from
            # underneath us.
            fd = _clonefile(fd)
        self._fd = fd

    def fileno(self) -> int:
        """
        Return the file descriptor number of this WrappedFd.

        Note that the file can still be garbage collected by Python after this
        call, so the file descriptor number might become invalid (or worse, be
        reused for an unrelated file).

        If you want to convert a WrappedFd to a file descriptor number and stop
        the GC from the closing the file, use WrappedFd.into_raw_fd().
        """
        if self._fd is None:
            raise OSError(errno.EBADF, "Closed file descriptor")
        return self._fd

    def leak(self) -> None:
        """
        Clears this WrappedFd without closing the underlying file, to stop GC
        from closing the file.

        Note that after this operation, all operations on this WrappedFd will
        return an error. If you want to get the underlying file handle and then
        leak the WrappedFd, just use WrappedFd.into_raw_fd() which does both
        for you.
        """
        self._fd = None

    def fdopen(self, mode: str = "r") -> IO[Any]:
        """
        Convert this WrappedFd into an os.fileopen() handle.

        This operation implicitly calls WrappedFd.leak(), so the WrappedFd will
        no longer be useful and you should instead use the returned os.fdopen()
        handle.
        """
        fd = self.fileno()
        try:
            file = os.fdopen(fd, mode)
            self.leak()
            return file
        except:
            # "Unleak" the file if there was an error.
            self._fd = fd
            raise

    @classmethod
    def from_raw_fd(cls: Type[Fd], fd: int, /) -> Fd:
        "Shorthand for WrappedFd(fd)."
        return cls(fd)

    @classmethod
    def from_file(cls: Type[Fd], file: FileLike, /) -> Fd:
        "Shorthand for WrappedFd(file)."
        return cls(file)

    def into_raw_fd(self) -> int:
        """
        Convert this WrappedFd into a raw file descriptor that GC won't touch.

        This is just shorthand for WrappedFd.fileno() to get the fileno,
        followed by WrappedFd.leak().
        """
        fd = self.fileno()
        self.leak()
        return fd

    def isclosed(self) -> bool:
        """
        Returns whether the underlying file descriptor is closed or the
        WrappedFd has been leaked.
        """
        return self._fd is None

    def close(self) -> None:
        """
        Manually close the underlying file descriptor for this WrappedFd.

        WrappedFds are garbage collected, so this is usually unnecessary unless
        you really care about the point where a file is closed.
        """
        if not self.isclosed():
            assert self._fd is not None  # typing
            os.close(self._fd)
            self._fd = None

    def clone(self) -> Self:
        "Create a clone of this WrappedFd that has a separate lifetime."
        if self.isclosed():
            raise ValueError("cannot clone closed file")
        assert self._fd is not None  # typing
        return self.__class__(_clonefile(self._fd))

    def __copy__(self) -> Self:
        "Identical to WrappedFd.clone()"
        # A "shallow copy" of a file is the same as a deep copy.
        return copy.deepcopy(self)

    def __deepcopy__(self, memo: Dict[int, Any]) -> Self:
        "Identical to WrappedFd.clone()"
        return self.clone()

    def __del__(self) -> None:
        "Identical to WrappedFd.close()"
        self.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_traceback: Optional[TracebackType],
    ) -> None:
        self.close()


# XXX: This is _super_ ugly but so is the one in CPython.
def _convert_mode(mode: str) -> int:
    mode_set = set(mode)
    flags = os.O_CLOEXEC

    # We don't support O_CREAT or O_EXCL with libpathrs -- use creat().
    if "x" in mode_set:
        raise ValueError("pathrs doesn't support mode='x', use Root.creat()")
    # Basic sanity-check to make sure we don't accept garbage modes.
    if len(mode_set & {"r", "w", "a"}) > 1:
        raise ValueError("must have exactly one of read/write/append mode")

    read = False
    write = False

    if "+" in mode_set:
        read = True
        write = True
    if "r" in mode_set:
        read = True
    if "w" in mode_set:
        write = True
        flags |= os.O_TRUNC
    if "a" in mode_set:
        write = True
        flags |= os.O_APPEND

    if read and write:
        flags |= os.O_RDWR
    elif write:
        flags |= os.O_WRONLY
    else:
        flags |= os.O_RDONLY

    # We don't care about "b" or "t" since that's just a Python thing.
    return flags


# TODO: Switch to "type ..." syntax once we switch to Python >= 3.12...?
ProcfsBase: TypeAlias = int

#: Resolve proc_* operations relative to the /proc root. Note that this mode
#: may be more expensive because we have to take steps to try to avoid leaking
#: unmasked procfs handles, so you should use PROC_SELF if you can.
PROC_ROOT: ProcfsBase = libpathrs_so.PATHRS_PROC_ROOT

#: Resolve proc_* operations relative to /proc/self. For most programs, this is
#: the standard choice.
PROC_SELF: ProcfsBase = libpathrs_so.PATHRS_PROC_SELF

#: Resolve proc_* operations relative to /proc/thread-self. In multi-threaded
#: programs where one thread has a different CLONE_FS, it is possible for
#: /proc/self to point the wrong thread and so /proc/thread-self may be
#: necessary.
PROC_THREAD_SELF: ProcfsBase = libpathrs_so.PATHRS_PROC_THREAD_SELF


def proc_open(
    base: ProcfsBase, path: str, mode: str = "r", /, *, extra_flags: int = 0
) -> IO[Any]:
    """
    Open a procfs file using Pythonic mode strings.

    This function returns an os.fdopen() file handle.

    base indicates what the path should be relative to. Valid values include
    PROC_{ROOT,SELF,THREAD_SELF}.

    path is a relative path to base indicating which procfs file you wish to
    open.

    mode is a Python mode string, and extra_flags can be used to indicate extra
    O_* flags you wish to pass to the open operation. If you do not intend to
    open a symlink, you should pass O_NOFOLLOW to extra_flags to let libpathrs
    know that it can be more strict when opening the path.
    """
    # TODO: Should we default to O_NOFOLLOW or put a separate argument for it?
    flags = _convert_mode(mode) | extra_flags
    with proc_open_raw(base, path, flags) as file:
        return file.fdopen(mode)


def proc_open_raw(base: ProcfsBase, path: str, flags: int, /) -> WrappedFd:
    """
    Open a procfs file using Unix open flags.

    This function returns a WrappedFd file handle.

    base indicates what the path should be relative to. Valid values include
    PROC_{ROOT,SELF,THREAD_SELF}.

    path is a relative path to base indicating which procfs file you wish to
    open.

    flags is the set of O_* flags you wish to pass to the open operation. If
    you do not intend to open a symlink, you should pass O_NOFOLLOW to flags to
    let libpathrs know that it can be more strict when opening the path.
    """
    # TODO: Should we default to O_NOFOLLOW or put a separate argument for it?
    fd = libpathrs_so.pathrs_proc_open(base, _cstr(path), flags)
    if fd < 0:
        raise Error._fetch(fd) or INTERNAL_ERROR
    return WrappedFd(fd)


def proc_readlink(base: ProcfsBase, path: str, /) -> str:
    """
    Fetch the target of a procfs symlink.

    Note that some procfs symlinks are "magic-links" where the returned string
    from readlink() is not how they are actually resolved.

    base indicates what the path should be relative to. Valid values include
    PROC_{ROOT,SELF,THREAD_SELF}.

    path is a relative path to base indicating which procfs file you wish to
    open.
    """
    # TODO: See if we can merge this with Root.readlink.
    cpath = _cstr(path)
    linkbuf_size = 128
    while True:
        linkbuf = _cbuffer(linkbuf_size)
        n = libpathrs_so.pathrs_proc_readlink(base, cpath, linkbuf, linkbuf_size)
        if n < 0:
            raise Error._fetch(n) or INTERNAL_ERROR
        elif n <= linkbuf_size:
            buf = typing.cast(bytes, ffi.buffer(linkbuf, linkbuf_size)[:n])
            return buf.decode("latin1")
        else:
            # The contents were truncated. Unlike readlinkat, pathrs returns
            # the size of the link when it checked. So use the returned size
            # as a basis for the reallocated size (but in order to avoid a DoS
            # where a magic-link is growing by a single byte each iteration,
            # make sure we are a fair bit larger).
            linkbuf_size += n


class Handle(WrappedFd):
    "A handle to a filesystem object, usually resolved using Root.resolve()."

    def reopen(self, mode: str = "r", /, *, extra_flags: int = 0) -> IO[Any]:
        """
        Upgrade a Handle to a os.fdopen() file handle.

        mode is a Python mode string, and extra_flags can be used to indicate
        extra O_* flags you wish to pass to the reopen operation.

        The returned file handle is independent to the original Handle, and you
        can freely call Handle.reopen() on the same Handle multiple times.
        """
        flags = _convert_mode(mode) | extra_flags
        with self.reopen_raw(flags) as file:
            return file.fdopen(mode)

    def reopen_raw(self, flags: int, /) -> WrappedFd:
        """
        Upgrade a Handle to a WrappedFd file handle.

        flags is the set of O_* flags you wish to pass to the open operation.

        The returned file handle is independent to the original Handle, and you
        can freely call Handle.reopen() on the same Handle multiple times.
        """
        fd = libpathrs_so.pathrs_reopen(self.fileno(), flags)
        if fd < 0:
            raise Error._fetch(fd) or INTERNAL_ERROR
        return WrappedFd(fd)


class Root(WrappedFd):
    """
    A handle to a filesystem root, which filesystem operations are all done
    relative to.
    """

    def __init__(self, file_or_path: Union[FileLike, str], /):
        """
        Create a handle from a file-like object or a path to a directory.

        Note that creating a Root in an attacker-controlled directory can allow
        for an attacker to trick you into allowing breakouts. If file_or_path
        is a path string, be aware there are no protections against rename race
        attacks when opening the Root directory handle itself.
        """
        if isinstance(file_or_path, str):
            path = _cstr(file_or_path)
            fd = libpathrs_so.pathrs_root_open(path)
            if fd < 0:
                raise Error._fetch(fd) or INTERNAL_ERROR
            file: FileLike = fd
        else:
            file = file_or_path

        # XXX: Is this necessary?
        super().__init__(file)

    @classmethod
    def open(cls, path: str, /) -> Self:
        "Identical to Root(path)."
        return cls(path)

    def resolve(self, path: str, /, *, follow_trailing: bool = True) -> Handle:
        """
        Resolve the given path inside the Root and return a Handle.

        follow_trailing indicates what resolve should do if the final component
        of the path is a symlink. The default is to continue resolving it, if
        follow_trailing=False then a handle to the symlink itself is returned.
        This has some limited uses, but most users should use the default.

        A pathrs.Error is raised if the path doesn't exist.
        """
        if follow_trailing:
            fd = libpathrs_so.pathrs_resolve(self.fileno(), _cstr(path))
        else:
            fd = libpathrs_so.pathrs_resolve_nofollow(self.fileno(), _cstr(path))
        if fd < 0:
            raise Error._fetch(fd) or INTERNAL_ERROR
        return Handle(fd)

    def readlink(self, path: str, /) -> str:
        """
        Fetch the target of a symlink at the given path in the Root.

        A pathrs.Error is raised if the path is not a symlink or doesn't exist.
        """
        cpath = _cstr(path)
        linkbuf_size = 128
        while True:
            linkbuf = _cbuffer(linkbuf_size)
            n = libpathrs_so.pathrs_readlink(
                self.fileno(), cpath, linkbuf, linkbuf_size
            )
            if n < 0:
                raise Error._fetch(n) or INTERNAL_ERROR
            elif n <= linkbuf_size:
                buf = typing.cast(bytes, ffi.buffer(linkbuf, linkbuf_size)[:n])
                return buf.decode("latin1")
            else:
                # The contents were truncated. Unlike readlinkat, pathrs returns
                # the size of the link when it checked. So use the returned size
                # as a basis for the reallocated size (but in order to avoid a DoS
                # where a magic-link is growing by a single byte each iteration,
                # make sure we are a fair bit larger).
                linkbuf_size += n

    def creat(
        self, path: str, filemode: int, mode: str = "r", /, extra_flags: int = 0
    ) -> IO[Any]:
        """
        Atomically create-and-open a new file at the given path in the Root,
        a-la O_CREAT.

        This method returns an os.fdopen() file handle.

        filemode is the Unix DAC mode you wish the new file to be created with.
        This mode might not be the actual mode of the created file due to a
        variety of external factors (umask, setgid bits, POSIX ACLs).

        mode is a Python mode string, and extra_flags can be used to indicate
        extra O_* flags you wish to pass to the reopen operation. If you wish
        to ensure the new file was created *by you* then you may wish to add
        O_EXCL to extra_flags.
        """
        flags = _convert_mode(mode) | extra_flags
        fd = libpathrs_so.pathrs_creat(self.fileno(), _cstr(path), flags, filemode)
        if fd < 0:
            raise Error._fetch(fd) or INTERNAL_ERROR
        return os.fdopen(fd, mode)

    # TODO: creat_raw?

    def rename(self, src: str, dst: str, flags: int = 0, /) -> None:
        """
        Rename a path from src to dst within the Root.

        flags can be any renameat2(2) flags you wish to use, which can change
        the behaviour of this method substantially. For instance,
        RENAME_EXCHANGE will turn this into an atomic swap operation.
        """
        # TODO: Should we have a separate Root.swap() operation?
        err = libpathrs_so.pathrs_rename(self.fileno(), _cstr(src), _cstr(dst), flags)
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def rmdir(self, path: str, /) -> None:
        """
        Remove an empty directory at the given path within the Root.

        To remove non-empty directories recursively, you can use
        Root.remove_all().
        """
        err = libpathrs_so.pathrs_rmdir(self.fileno(), _cstr(path))
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def unlink(self, path: str, /) -> None:
        """
        Remove a non-directory inode at the given path within the Root.

        To remove empty directories, you can use Root.remove_all(). To remove
        files and non-empty directories recursively, you can use
        Root.remove_all().
        """
        err = libpathrs_so.pathrs_unlink(self.fileno(), _cstr(path))
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def remove_all(self, path: str, /) -> None:
        """
        Remove the file or directory (empty or non-empty) at the given path
        within the Root.
        """
        err = libpathrs_so.pathrs_remove_all(self.fileno(), _cstr(path))
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def mkdir(self, path: str, mode: int, /) -> None:
        """
        Create a directory at the given path within the Root.

        mode is the Unix DAC mode you wish the new directory to be created
        with. This mode might not be the actual mode of the created file due to
        a variety of external factors (umask, setgid bits, POSIX ACLs).

        A pathrs.Error will be raised if the parent directory doesn't exist, or
        the path already exists. To create a directory and all of its parent
        directories (or just reuse an existing directory) you can use
        Root.mkdir_all().
        """
        err = libpathrs_so.pathrs_mkdir(self.fileno(), _cstr(path), mode)
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def mkdir_all(self, path: str, mode: int, /) -> Handle:
        """
        Recursively create a directory and all of its parents at the given path
        within the Root (or reuse an existing directory if the path already
        exists).

        This method returns a Handle to the created directory.

        mode is the Unix DAC mode you wish any new directories to be created
        with. This mode might not be the actual mode of the created file due to
        a variety of external factors (umask, setgid bits, POSIX ACLs). If the
        full path already exists, this mode is ignored and the existing
        directory mode is kept.
        """
        fd = libpathrs_so.pathrs_mkdir_all(self.fileno(), _cstr(path), mode)
        if fd < 0:
            raise Error._fetch(fd) or INTERNAL_ERROR
        return Handle(fd)

    def mknod(self, path: str, mode: int, device: int = 0, /) -> None:
        """
        Create a new inode at the given path within the Root.

        mode both indicates the file type (it must contain a valid bit from
        S_IFMT to indicate what kind of file to create) and what the mode of
        the newly created file should have. This mode might not be the actual
        mode of the created file due to a variety of external factors (umask,
        setgid bits, POSIX ACLs).

        dev is the the (major, minor) device number used for the new inode if
        the mode contains S_IFCHR or S_IFBLK. You can construct the device
        number from a (major, minor) using os.makedev().

        A pathrs.Error is raised if the path already exists.
        """
        err = libpathrs_so.pathrs_mknod(self.fileno(), _cstr(path), mode, device)
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def hardlink(self, path: str, target: str, /) -> None:
        """
        Create a hardlink between two paths inside the Root.

        path is the path to the *new* hardlink, and target is a path to the
        *existing* file.

        A pathrs.Error is raised if the path for the new hardlink already
        exists.
        """
        err = libpathrs_so.pathrs_hardlink(self.fileno(), _cstr(path), _cstr(target))
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

    def symlink(self, path: str, target: str, /) -> None:
        """
        Create a symlink at the given path in the Root.

        path is the path to the *new* symlink, and target is what the symink
        will point to. Note that symlinks contents are not verified on Linux,
        so there are no restrictions on what target you put.

        A pathrs.Error is raised if the path for the new symlink already
        exists.
        """
        err = libpathrs_so.pathrs_symlink(self.fileno(), _cstr(path), _cstr(target))
        if err < 0:
            raise Error._fetch(err) or INTERNAL_ERROR

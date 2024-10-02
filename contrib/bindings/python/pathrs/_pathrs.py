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
import fcntl

from ._libpathrs_cffi import ffi, lib as libpathrs_so

__all__ = [
	# core api
	"Root", "Handle",
	# procfs api
	"PROC_ROOT", "PROC_SELF", "PROC_THREAD_SELF",
	"proc_open", "proc_open_raw", "proc_readlink",
	# error api
	"Error",
]

def _cstr(pystr):
	return ffi.new("char[]", pystr.encode("utf8"))

def _pystr(cstr):
	return ffi.string(cstr).decode("utf8")

def _pyptr(cptr):
	return int(ffi.cast("uintptr_t", cptr))

def _cbuffer(size):
	return ffi.new("char[%d]" % (size,))


class Error(Exception):
	def __init__(self, message, *_, errno=None):
		# Construct Exception.
		super().__init__(message)

		# Basic arguments.
		self.message = message
		self.errno = errno

		# Pre-format the errno.
		self.strerror = None
		if self.errno is not None:
			try:
				self.strerror = os.strerror(errno)
			except ValueError:
				self.strerror = str(errno)

	@classmethod
	def _fetch(cls, err_id):
		if err_id >= 0:
			return None

		err = libpathrs_so.pathrs_errorinfo(err_id)
		if err == ffi.NULL:
			return None

		description = _pystr(err.description)
		errno = err.saved_errno or None

		libpathrs_so.pathrs_errorinfo_free(err)
		del err

		return cls(description, errno=errno)

	def __str__(self):
		if self.errno is None:
			return self.message
		else:
			return "%s (%s)" % (self.message, self.strerror)

	def __repr__(self):
		return "Error(%r, errno=%r)" % (self.message, self.errno)

	def pprint(self, out=sys.stdout):
		# Basic error information.
		if self.errno is None:
			print("pathrs error:", file=out)
		else:
			print("pathrs error [%s]:" % (self.strerror,), file=out)
		print("  %s" % (self.message,), file=out)


INTERNAL_ERROR = Error("tried to fetch libpathrs error but no error found")


def _fileno(file):
	if isinstance(file, int):
		# file is a plain fd
		return file
	else:
		# Assume there is a fileno method.
		return file.fileno()

def _clonefile(file):
	return fcntl.fcntl(fileno(file), fcntl.F_DUPFD_CLOEXEC)


class WrappedFd(object):
	def __init__(self, file):
		fd = _fileno(file)
		if isinstance(file, io.IOBase):
			# If this is a regular open file, we need to make a copy because
			# you cannot leak files and so the GC might close it from
			# underneath us.
			fd = clonefd(fd)
		self._fd = fd

	def fileno(self):
		if self._fd is None:
			raise OSError(errno.EBADF, "Closed file descriptor")
		return self._fd

	def leak(self):
		self._fd = None

	def fdopen(self, mode="r"):
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
	def from_raw_fd(cls, fd):
		return cls(fd)

	def into_raw_fd(self):
		fd = self.fileno()
		self.leak()
		return fd

	def isclosed(self):
		return self._fd is None

	def close(self):
		if not self.isclosed():
			os.close(self._fd)
			self._fd = None

	def clone(self):
		if self.isclosed():
			raise ValueError("cannot clone closed file")
		return self.__class__(_clonefile(self))

	def __copy__(self):
		# A "shallow copy" of a file is the same as a deep copy.
		return copy.deepcopy(self)

	def __deepcopy__(self, memo):
		return self.clone()

	def __del__(self):
		self.close()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, exc_traceback):
		self.close()


# XXX: This is _super_ ugly but so is the one in CPython.
def _convert_mode(mode):
	mode = set(mode)
	flags = os.O_CLOEXEC

	# We don't support O_CREAT or O_EXCL with libpathrs -- use creat().
	if "x" in mode:
		raise ValueError("pathrs doesn't support mode='x', use Root.creat()")
	# Basic sanity-check to make sure we don't accept garbage modes.
	if len(mode & {"r", "w", "a"}) > 1:
		raise ValueError("must have exactly one of read/write/append mode")

	read = False
	write = False

	if "+" in mode:
		read = True
		write = True
	if "r" in mode:
		read = True
	if "w" in mode:
		write = True
		flags |= os.O_TRUNC
	if "a" in mode:
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


PROC_ROOT = libpathrs_so.PATHRS_PROC_ROOT
PROC_SELF = libpathrs_so.PATHRS_PROC_SELF
PROC_THREAD_SELF = libpathrs_so.PATHRS_PROC_THREAD_SELF

def proc_open(base, path, mode="r", extra_flags=0):
	flags = _convert_mode(mode) | extra_flags
	with proc_open_raw(base, path, flags) as file:
		return file.fdopen(mode)

def proc_open_raw(base, path, flags):
	path = _cstr(path)
	fd = libpathrs_so.pathrs_proc_open(base, path, flags)
	if fd < 0:
		raise Error._fetch(fd) or INTERNAL_ERROR
	return WrappedFd(fd)

def proc_readlink(base, path):
	# TODO: See if we can merge this with Root.readlink.
	path = _cstr(path)
	linkbuf_size = 128
	while True:
		linkbuf = _cbuffer(linkbuf_size)
		n = libpathrs_so.pathrs_proc_readlink(base, path, linkbuf, linkbuf_size)
		if n < 0:
			raise Error._fetch(n) or INTERNAL_ERROR
		elif n <= linkbuf_size:
			return ffi.buffer(linkbuf, linkbuf_size)[:n].decode("latin1")
		else:
			# The contents were truncated. Unlike readlinkat, pathrs returns
			# the size of the link when it checked. So use the returned size
			# as a basis for the reallocated size (but in order to avoid a DoS
			# where a magic-link is growing by a single byte each iteration,
			# make sure we are a fair bit larger).
			linkbuf_size += n


class Handle(WrappedFd):
	def __init__(self, file):
		# XXX: Is this necessary?
		super().__init__(file)

	@classmethod
	def from_file(cls, file):
		return cls(file)

	def reopen(self, mode="r", extra_flags=0):
		flags = _convert_mode(mode) | extra_flags
		with self.reopen_raw(flags) as file:
			return file.fdopen(mode)

	def reopen_raw(self, flags):
		fd = libpathrs_so.pathrs_reopen(self.fileno(), flags)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		return WrappedFd(fd)


class Root(WrappedFd):
	def __init__(self, file):
		if isinstance(file, str):
			path = _cstr(file)
			fd = libpathrs_so.pathrs_root_open(path)
			if fd < 0:
				raise Error._fetch(fd) or INTERNAL_ERROR
			file = fd
		# XXX: Is this necessary?
		super().__init__(file)

	@classmethod
	def open(cls, path):
		return cls(path)

	@classmethod
	def from_file(cls, file):
		return cls(file)

	def resolve(self, path, follow_trailing=True):
		path = _cstr(path)
		if follow_trailing:
			fd = libpathrs_so.pathrs_resolve(self.fileno(), path)
		else:
			fd = libpathrs_so.pathrs_resolve_nofollow(self.fileno(), path)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		return Handle(fd)

	def readlink(self, path):
		path = _cstr(path)
		linkbuf_size = 128
		while True:
			linkbuf = _cbuffer(linkbuf_size)
			n = libpathrs_so.pathrs_readlink(self.fileno(), path, linkbuf, linkbuf_size)
			if n < 0:
				raise Error._fetch(n) or INTERNAL_ERROR
			elif n <= linkbuf_size:
				return ffi.buffer(linkbuf, linkbuf_size)[:n].decode("latin1")
			else:
				# The contents were truncated. Unlike readlinkat, pathrs returns
				# the size of the link when it checked. So use the returned size
				# as a basis for the reallocated size (but in order to avoid a DoS
				# where a magic-link is growing by a single byte each iteration,
				# make sure we are a fair bit larger).
				linkbuf_size += n

	def creat(self, path, filemode, mode="r", extra_flags=0):
		path = _cstr(path)
		flags = _convert_mode(mode) | extra_flags
		fd = libpathrs_so.pathrs_creat(self.fileno(), path, flags, filemode)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		return Handle(fd)

	def rename(self, src, dst, flags=0):
		src = _cstr(src)
		dst = _cstr(dst)
		err = libpathrs_so.pathrs_rename(self.fileno(), src, dst, flags)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def rmdir(self, path):
		path = _cstr(path)
		err = libpathrs_so.pathrs_rmdir(self.fileno(), path)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def unlink(self, path):
		path = _cstr(path)
		err = libpathrs_so.pathrs_unlink(self.fileno(), path)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def remove_all(self, path):
		path = _cstr(path)
		err = libpathrs_so.pathrs_remove_all(self.fileno(), path)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def mkdir(self, path, mode):
		path = _cstr(path)
		err = libpathrs_so.pathrs_mkdir(self.fileno(), path, mode)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def mkdir_all(self, path, mode):
		path = _cstr(path)
		fd = libpathrs_so.pathrs_mkdir_all(self.fileno(), path, mode)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		return Handle(fd)

	def mknod(self, path, mode, dev=0):
		path = _cstr(path)
		err = libpathrs_so.pathrs_mknod(self.fileno(), path, mode, dev)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def hardlink(self, path, target):
		path = _cstr(path)
		target = _cstr(target)
		err = libpathrs_so.pathrs_hardlink(self.fileno(), path, target)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def symlink(self, path, target):
		path = _cstr(path)
		target = _cstr(target)
		err = libpathrs_so.pathrs_symlink(self.fileno(), path, target)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

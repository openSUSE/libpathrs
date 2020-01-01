#!/usr/bin/python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019, 2020 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019, 2020 SUSE LLC
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

import re
import os
import sys

from _pathrs import ffi, lib as libpathrs_so

__all__ = ["Root", "Handle", "Error"]

# The global resolver setting.
DEFAULT_RESOLVER = {
	"kernel": libpathrs_so.PATHRS_KERNEL_RESOLVER,
	"emulated": libpathrs_so.PATHRS_EMULATED_RESOLVER,
}.get(os.environ.get("PATHRS_RESOLVER"))

def cstr(pystr):
	return ffi.new("char[]", pystr.encode("utf8"))

def pystr(cstr):
	return ffi.string(cstr).decode("utf8")

def pyptr(cptr):
	return int(ffi.cast("uintptr_t", cptr))

class Error(Exception):
	def __init__(self, message, *_, errno=None, backtrace=None):
		# Construct Exception.
		super().__init__(message)

		# Basic arguments.
		self.message = message
		self.errno = errno
		self.backtrace = backtrace

		# Pre-format the errno.
		self.strerror = None
		if self.errno is not None:
			try:
				self.strerror = os.strerror(errno)
			except ValueError:
				self.strerror = str(errno)

	# NOTE: We probably shouldn't be exporting this...
	@classmethod
	def fetch(cls, typ, obj):
		err = libpathrs_so.pathrs_error(typ, obj)
		if err == ffi.NULL:
			return None

		description = pystr(err.description)
		errno = err.saved_errno or None
		backtrace = Backtrace(err.backtrace) or None

		libpathrs_so.pathrs_free(libpathrs_so.PATHRS_ERROR, err)
		del err

		return cls(description, backtrace=backtrace, errno=errno)

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

		# Backtrace if available.
		if self.backtrace:
			print("rust backtrace:", file=out)
			for entry in self.backtrace:
				print("  %s" % (entry,), file=out)
				if entry.symbol.file is not None:
					print("    in file '%s':%d" % (entry.symbol.file, entry.symbol.lineno), file=out)


class BacktraceSymbol(object):
	def __init__(self, c_entry):
		self.address = pyptr(c_entry.symbol_address)

		self.name = None
		if c_entry.symbol_name != ffi.NULL:
			self.name = pystr(c_entry.symbol_name)

		self.file = None
		self.lineno = None
		if c_entry.symbol_file != ffi.NULL:
			self.file = pystr(c_entry.symbol_file)
			self.lineno = c_entry.symbol_lineno

	def __str__(self):
		string = "<0x%x>" % (self.address,)
		if self.name is not None:
			string = "'%s'@%s" % (self.name, string)
		return string


class BacktraceEntry(object):
	def __init__(self, c_entry):
		self.ip = pyptr(c_entry.ip)
		self.symbol = BacktraceSymbol(c_entry)

	def __str__(self):
		return "%s+0x%x" % (self.symbol, self.ip - self.symbol.address)


class Backtrace(list):
	def __init__(self, c_backtrace):
		super().__init__()

		if c_backtrace == ffi.NULL:
			return

		for idx in range(c_backtrace.length):
			c_entry = c_backtrace.head[idx]
			self.append(BacktraceEntry(c_entry))


class Handle(object):
	# NOTE: We probably shouldn't be exporting the constructor...
	def __init__(self, handle):
		self._type = libpathrs_so.PATHRS_HANDLE
		self._inner = handle

	def __del__(self):
		libpathrs_so.pathrs_free(self._type, self._inner)

	def __copy__(self):
		# "Shallow copy" makes no sense since we are using FFI resources.
		return self.__deepcopy__({})

	def __deepcopy__(self, memo):
		new_inner = libpathrs_so.pathrs_duplicate(self._type, self._inner)
		if new_inner == ffi.NULL:
			raise self._error()
		# Construct a new Root without going through __init__.
		cls = self.__class__
		new = cls.__new__(cls)
		new._type = self._type
		new._inner = new_inner
		return new

	def _error(self):
		return Error.fetch(self._type, self._inner)

	# XXX: This is _super_ ugly but so is the one in CPython.
	@staticmethod
	def _convert_mode(mode):
		mode = set(mode)
		flags = os.O_CLOEXEC

		# We don't support O_CREAT or O_EXCL with libpathrs -- use creat().
		if "x" in mode:
			raise ValueError("pathrs doesn't support mode='x', use creat()")
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

	def reopen(self, mode="r", extra_flags=0):
		flags = self._convert_mode(mode) | extra_flags
		fd = libpathrs_so.pathrs_reopen(self._inner, flags)
		if fd < 0:
			raise self._error()
		try:
			return os.fdopen(fd, mode)
		except Exception as e:
			os.close(fd)
			raise


class Root(object):
	def __init__(self, path, resolver=None):
		path = cstr(path)
		self._type = libpathrs_so.PATHRS_ROOT
		self._inner = libpathrs_so.pathrs_open(path)
		if self._inner == ffi.NULL:
			# This should never actually happen.
			raise Error("pathrs_root allocation failed")

		# If there was an error in pathrs_open, we find out now.
		err = self._error()
		if err:
			raise err

		# Switch resolvers if requested.
		if DEFAULT_RESOLVER is not None:
			new_config = ffi.new("pathrs_config_root_t *")
			new_config.resolver = DEFAULT_RESOLVER

			err = libpathrs_so.pathrs_configure(self._type, self._inner, ffi.NULL, new_config, ffi.sizeof(new_config))
			if err:
				raise self._error()

	def __del__(self):
		if self._inner is not None:
			libpathrs_so.pathrs_free(self._type, self._inner)

	def __copy__(self):
		# "Shallow copy" makes no sense since we are using FFI resources.
		return self.__deepcopy__({})

	def __deepcopy__(self, memo):
		new_inner = libpathrs_so.pathrs_duplicate(self._type, self._inner)
		if new_inner == ffi.NULL:
			raise self._error()
		# Construct a new Root without going through __init__.
		cls = self.__class__
		new = cls.__new__(cls)
		new._type = self._type
		new._inner = new_inner
		return new

	def _error(self):
		return Error.fetch(self._type, self._inner)

	def resolve(self, path):
		path = cstr(path)
		handle = libpathrs_so.pathrs_resolve(self._inner, path)
		if handle == ffi.NULL:
			raise self._error()
		return Handle(handle)

	def rename(self, src, dst, flags=0):
		src = cstr(src)
		dst = cstr(dst)
		err = libpathrs_so.pathrs_rename(self._inner, src, dst, flags)
		if err < 0:
			raise self._error()

	def creat(self, path, mode):
		path = cstr(path)
		handle = libpathrs_so.pathrs_creat(self._inner, path, mode)
		if handle == ffi.NULL:
			raise self._error()
		return Handle(handle)

	def mkdir(self, path, mode):
		path = cstr(path)
		err = libpathrs_so.pathrs_mkdir(self._inner, path, mode)
		if err < 0:
			raise self._error()

	def mknod(self, path, mode, dev):
		path = cstr(path)
		err = libpathrs_so.pathrs_mknod(self._inner, path, mode, dev)
		if err < 0:
			raise self._error()

	def hardlink(self, path, target):
		path = cstr(path)
		target = cstr(target)
		err = libpathrs_so.pathrs_hardlink(self._inner, path, target)
		if err < 0:
			raise self._error()

	def symlink(self, path, target):
		path = cstr(path)
		target = cstr(target)
		err = libpathrs_so.pathrs_symlink(self._inner, path, target)
		if err < 0:
			raise self._error()

#!/usr/bin/python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019 SUSE LLC
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

def objtype(obj):
	if isinstance(obj, Root):
		return libpathrs_so.PATHRS_ROOT
	elif isinstance(obj, Handle):
		return libpathrs_so.PATHRS_HANDLE
	else:
		raise Error("internal error: %r is not a pathrs object" % (obj,))


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


def error(obj):
	try:
		err = libpathrs_so.pathrs_error(objtype(obj), obj.inner)
	except Error:
		# Most likely, obj is a raw pathrs_error_t.
		# TODO: Should probably do an isinstance() check here...
		err = obj
	if err == ffi.NULL:
		return None

	errno = err.saved_errno
	description = pystr(err.description)
	backtrace = Backtrace(err.backtrace)

	libpathrs_so.pathrs_free(libpathrs_so.PATHRS_ERROR, err)
	del err

	return Error(description, backtrace=backtrace or None, errno=errno or None)


class Handle(object):
	def __init__(self, handle):
		self.inner = handle

	def __del__(self):
		libpathrs_so.pathrs_free(objtype(self), self.inner)

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
		fd = libpathrs_so.pathrs_reopen(self.inner, flags)
		if fd < 0:
			raise error(self)
		try:
			return os.fdopen(fd, mode)
		except Exception as e:
			os.close(fd)
			raise


class Root(object):
	def __init__(self, path, resolver=None):
		self.inner = None
		path = cstr(path)
		root = libpathrs_so.pathrs_open(path)
		if root == ffi.NULL:
			# This should never actually happen.
			raise Error("pathrs_root allocation failed")
		self.inner = root

		# If there was an error in pathrs_open, we find out now.
		err = error(self)
		if err:
			raise err

		# Switch resolvers if requested.
		if DEFAULT_RESOLVER is not None:
			new_config = ffi.new("pathrs_config_root_t *")
			new_config.resolver = DEFAULT_RESOLVER

			err = libpathrs_so.pathrs_configure(objtype(self), self.inner, ffi.NULL, new_config, ffi.sizeof(new_config))
			if err:
				raise error(err)

	def __del__(self):
		if self.inner is not None:
			libpathrs_so.pathrs_free(objtype(self), self.inner)

	def resolve(self, path):
		path = cstr(path)
		handle = libpathrs_so.pathrs_resolve(self.inner, path)
		if handle == ffi.NULL:
			raise error(self)
		return Handle(handle)

	def rename(self, src, dst, flags=0):
		src = cstr(src)
		dst = cstr(dst)
		err = libpathrs_so.pathrs_rename(self.inner, src, dst, flags)
		if err < 0:
			raise error(self)

	def creat(self, path, mode):
		path = cstr(path)
		handle = libpathrs_so.pathrs_creat(self.inner, path, mode)
		if handle == ffi.NULL:
			raise error(self)
		return Handle(handle)

	def mkdir(self, path, mode):
		path = cstr(path)
		err = libpathrs_so.pathrs_mkdir(self.inner, path, mode)
		if err < 0:
			raise error(self)

	def mknod(self, path, mode, dev):
		path = cstr(path)
		err = libpathrs_so.pathrs_mknod(self.inner, path, mode, dev)
		if err < 0:
			raise error(self)

	def hardlink(self, path, target):
		path = cstr(path)
		target = cstr(target)
		err = libpathrs_so.pathrs_hardlink(self.inner, path, target)
		if err < 0:
			raise error(self)

	def symlink(self, path, target):
		path = cstr(path)
		target = cstr(target)
		err = libpathrs_so.pathrs_symlink(self.inner, path, target)
		if err < 0:
			raise error(self)

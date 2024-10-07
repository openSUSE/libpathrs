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

def _cbuffer(size):
	return ffi.new("char[%d]" % (size,))


class Error(Exception):
	"""
	Represents a libpathrs error. All libpathrs errors have a description
	(Error.message) and errors that were caused by an underlying OS error (or
	can be translated to an OS error) also include the errno value
	(Error.errno).
	"""

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
		"Pretty-print the error to the given @out file."
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

def _clonefile(file: FileLike) -> int:
	return fcntl.fcntl(_fileno(file), fcntl.F_DUPFD_CLOEXEC)


class WrappedFd(object):
	"""
	Represents a file descriptor that allows for manual lifetime management,
	unlike os.fdopen() which are tracked by the GC with no way of "leaking" the
	file descriptor for FFI purposes.

	pathrs will return WrappedFds for most operations that return an fd.
	"""

	def __init__(self, file):
		"""
		Construct a WrappedFd from any file-like object.

		For most cases, the WrappedFd will take ownership of the lifetime of
		the file handle. This means you should  So a raw file descriptor must
		only be turned into a WrappedFd *once* (unless you make sure to use
		WrappedFd.leak() to ensure there is only ever one owner of the handle
		at a given time).

		However, for os.fdopen() (or simmilar Pythonic file objects that are
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

	def fileno(self):
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

	def leak(self):
		"""
		Clears this WrappedFd without closing the underlying file, to stop GC
		from closing the file.

		Note that after this operation, all operations on this WrappedFd will
		return an error. If you want to get the underlying file handle and then
		leak the WrappedFd, just use WrappedFd.into_raw_fd() which does both
		for you.
		"""
		self._fd = None

	def fdopen(self, mode="r"):
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
	def from_raw_fd(cls, fd):
		"Shorthand for WrappedFd(fd)."
		return cls(fd)

	def into_raw_fd(self):
		"""
		Convert this WrappedFd into a raw file descriptor that GC won't touch.

		This is just shorthand for WrappedFd.fileno() to get the fileno,
		followed by WrappedFd.leak().
		"""
		fd = self.fileno()
		self.leak()
		return fd

	def isclosed(self):
		"""
		Returns whether the underlying file descriptor is closed or the
		WrappedFd has been leaked.
		"""
		return self._fd is None

	def close(self):
		"""
		Manually close the underlying file descriptor for this WrappedFd.

		WrappedFds are garbage collected, so this is usually unnecessary unless
		you really care about the point where a file is closed.
		"""
		if not self.isclosed():
			os.close(self._fd)
			self._fd = None

	def clone(self):
		"Create a clone of this WrappedFd that has a separate lifetime."
		if self.isclosed():
			raise ValueError("cannot clone closed file")
		return self.__class__(_clonefile(self))

	def __copy__(self):
		"Identical to WrappedFd.clone()"
		# A "shallow copy" of a file is the same as a deep copy.
		return copy.deepcopy(self)

	def __deepcopy__(self, memo):
		"Identical to WrappedFd.clone()"
		return self.clone()

	def __del__(self):
		"Identical to WrappedFd.close()"
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

def proc_open_raw(base, path, flags):
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
	path = _cstr(path)
	fd = libpathrs_so.pathrs_proc_open(base, path, flags)
	if fd < 0:
		raise Error._fetch(fd) or INTERNAL_ERROR
	return WrappedFd(fd)

def proc_readlink(base, path):
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
	"A handle to a filesystem object, usually resolved using Root.resolve()."

	def __init__(self, file):
		# XXX: Is this necessary?
		super().__init__(file)

	@classmethod
	def from_file(cls, file):
		"Manually create a Handle from a file-like object."
		return cls(file)

	def reopen(self, mode="r", extra_flags=0):
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

	def reopen_raw(self, flags):
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

	def __init__(self, file_or_path):
		"""
		Create a handle from a file-like object or a path to a directory.

		Note that creating a Root in an attacker-controlled directory can allow
		for an attacker to trick you into allowing breakouts. If file_or_path
		is a path string, be aware there are no protections against rename race
		attacks when opening the Root directory handle itself.
		"""
		file = file_or_path
		if isinstance(file_or_path, str):
			path = _cstr(file_or_path)
			fd = libpathrs_so.pathrs_root_open(path)
			if fd < 0:
				raise Error._fetch(fd) or INTERNAL_ERROR
			file = fd
		# XXX: Is this necessary?
		super().__init__(file)

	@classmethod
	def open(cls, path):
		"Identical to Root(path)."
		return cls(path)

	@classmethod
	def from_file(cls, file):
		"Identical to Root(file)."
		return cls(file)

	def resolve(self, path, follow_trailing=True):
		"""
		Resolve the given path inside the Root and return a Handle.

		follow_trailing indicates what resolve should do if the final component
		of the path is a symlink. The default is to continue resolving it, if
		follow_trailing=False then a handle to the symlink itself is returned.
		This has some limited uses, but most users should use the default.

		A pathrs.Error is raised if the path doesn't exist.
		"""
		path = _cstr(path)
		if follow_trailing:
			fd = libpathrs_so.pathrs_resolve(self.fileno(), path)
		else:
			fd = libpathrs_so.pathrs_resolve_nofollow(self.fileno(), path)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		return Handle(fd)

	def readlink(self, path):
		"""
		Fetch the target of a symlink at the given path in the Root.

		A pathrs.Error is raised if the path is not a symlink or doesn't exist.
		"""
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
		"""
		Atomically create-and-open a new file at the given path in the Root,
		a-la O_CREAT.

		This method returns a Handle.

		filemode is the Unix DAC mode you wish the new file to be created with.
		This mode might not be the actual mode of the created file due to a
		variety of external factors (umask, setgid bits, POSIX ACLs).

		mode is a Python mode string, and extra_flags can be used to indicate
		extra O_* flags you wish to pass to the reopen operation. If you wish
		to ensure the new file was created *by you* then you may wish to add
		O_EXCL to extra_flags.
		"""
		path = _cstr(path)
		flags = _convert_mode(mode) | extra_flags
		fd = libpathrs_so.pathrs_creat(self.fileno(), path, flags, filemode)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		# TODO: This should actually return an os.fdopen.
		return Handle(fd)

	# TODO: creat_raw?

	def rename(self, src, dst, flags=0):
		"""
		Rename a path from src to dst within the Root.

		flags can be any renameat2(2) flags you wish to use, which can change
		the behaviour of this method substantially. For instance,
		RENAME_EXCHANGE will turn this into an atomic swap operation.
		"""
		# TODO: Should we have a separate Root.swap() operation?
		src = _cstr(src)
		dst = _cstr(dst)
		err = libpathrs_so.pathrs_rename(self.fileno(), src, dst, flags)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def rmdir(self, path):
		"""
		Remove an empty directory at the given path within the Root.

		To remove non-empty directories recursively, you can use
		Root.remove_all().
		"""
		path = _cstr(path)
		err = libpathrs_so.pathrs_rmdir(self.fileno(), path)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def unlink(self, path):
		"""
		Remove a non-directory inode at the given path within the Root.

		To remove empty directories, you can use Root.remove_all(). To remove
		files and non-empty directories recursively, you can use
		Root.remove_all().
		"""
		path = _cstr(path)
		err = libpathrs_so.pathrs_unlink(self.fileno(), path)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def remove_all(self, path):
		"""
		Remove the file or directory (empty or non-empty) at the given path
		within the Root.
		"""
		path = _cstr(path)
		err = libpathrs_so.pathrs_remove_all(self.fileno(), path)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def mkdir(self, path, mode):
		"""
		Create a directory at the given path within the Root.

		mode is the Unix DAC mode you wish the new directory to be created
		with. This mode might not be the actual mode of the created file due to
		a variety of external factors (umask, setgid bits, POSIX ACLs).

		A pathrs.Error will be raised if the parent directory doesn't exist, or
		the path already exists. To create a directory and all of its parent
		directories (or just re-use an existing directory) you can use
		Root.mkdir_all().
		"""
		path = _cstr(path)
		err = libpathrs_so.pathrs_mkdir(self.fileno(), path, mode)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def mkdir_all(self, path, mode):
		"""
		Recursively create a directory and all of its parents at the given path
		within the Root (or re-use an existing directory if the path already
		exists).

		This method returns a Handle to the created directory.

		mode is the Unix DAC mode you wish any new directories to be created
		with. This mode might not be the actual mode of the created file due to
		a variety of external factors (umask, setgid bits, POSIX ACLs). If the
		full path already exists, this mode is ignored and the existing
		directory mode is kept.
		"""
		path = _cstr(path)
		fd = libpathrs_so.pathrs_mkdir_all(self.fileno(), path, mode)
		if fd < 0:
			raise Error._fetch(fd) or INTERNAL_ERROR
		return Handle(fd)

	def mknod(self, path, mode, dev=0):
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
		path = _cstr(path)
		err = libpathrs_so.pathrs_mknod(self.fileno(), path, mode, dev)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def hardlink(self, path, target):
		"""
		Create a hardlink between two paths inside the Root.

		path is the path to the *new* hardlink, and target is a path to the
		*existing* file.

		A pathrs.Error is raised if the path for the new hardlink already
		exists.
		"""
		path = _cstr(path)
		target = _cstr(target)
		err = libpathrs_so.pathrs_hardlink(self.fileno(), path, target)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

	def symlink(self, path, target):
		"""
		Create a symlink at the given path in the Root.

		path is the path to the *new* symlink, and target is what the symink
		will point to. Note that symlinks contents are not verified on Linux,
		so there are no restrictions on what target you put.

		A pathrs.Error is raised if the path for the new symlink already
		exists.
		"""
		path = _cstr(path)
		target = _cstr(target)
		err = libpathrs_so.pathrs_symlink(self.fileno(), path, target)
		if err < 0:
			raise Error._fetch(err) or INTERNAL_ERROR

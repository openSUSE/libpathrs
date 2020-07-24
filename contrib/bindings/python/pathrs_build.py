#!/usr/bin/python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019-2020 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019-2020 SUSE LLC
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

# This builds the _pathrs module (only needs to be done during the initial
# build of libpathrs, and can be redistributed alongside the pathrs.py wrapping
# library). It's much better than the ABI-mode of CFFI.

# TODO: Make this work properly with setuptools -- this might take some work.

import re
import os
import sys
import cffi

def load_hdr(ffi, hdr_path):
	with open(hdr_path) as f:
		hdr = f.read()

	# Drop all #-lines.
	hdr = re.sub("^#.*$", "", hdr, flags=re.MULTILINE)

	# Replace each struct-like body that has __CBINDGEN_ALIGNED before it,
	# remove the __CBINDGEN_ALIGNED and add "...;" as the last field in the
	# struct. This is how you tell cffi to get the proper alignment from the
	# compiler (__attribute__((aligned(n))) is not supported by cdef).
	hdr = re.sub(r"__CBINDGEN_ALIGNED\(\d+\)([^{;]*){([^}]+)}", r"\1 {\2 ...;}", hdr, flags=re.MULTILINE)

	# Load the header.
	ffi.cdef(hdr)

def compile_module(**kwargs):
	ffibuilder = cffi.FFI()
	ffibuilder.cdef("typedef uint32_t dev_t;")

	# We need to use cdef to tell cffi what functions we need to FFI to. But we
	# don't need the structs (I hope).
	for include_dir in kwargs["include_dirs"]:
		pathrs_hdr = os.path.join(include_dir, "pathrs.h")
		if os.path.exists(pathrs_hdr):
			load_hdr(ffibuilder, pathrs_hdr)

	# Add a source and link to libpathrs.
	ffibuilder.set_source("_pathrs", "#include <pathrs.h>",
	                      libraries=["pathrs"], **kwargs)

	# Compile the cffi module.
	ffibuilder.compile(verbose=True)

def main():
	# Figure out where the libpathrs source dir is.
	ROOT_DIR = None
	candidate = os.path.dirname(sys.path[0] or os.getcwd())
	while candidate != "/":
		try:
			# Look for a Cargo.toml which says it's pathrs.
			candidate_toml = os.path.join(candidate, "Cargo.toml")
			with open(candidate_toml, "r") as f:
				content = f.read()
			if re.findall(r'^name = "pathrs"$', content, re.MULTILINE):
				ROOT_DIR = candidate
				break
		except:
			pass
		candidate = os.path.dirname(candidate)

	# TODO: Support using the system paths.
	if not ROOT_DIR:
		raise RuntimeError("Could not find pathrs source-dir root.")

	# Figure out which libs are usable.
	lib_paths = []
	for mode in ["debug", "release"]:
		so_path = os.path.join(ROOT_DIR, "target/%s/libpathrs.so" % (mode,))
		if os.path.exists(so_path):
			lib_paths.append(so_path)
	lib_paths = sorted(lib_paths, key=lambda path: -os.path.getmtime(path))
	lib_paths = [os.path.dirname(path) for path in lib_paths]

	# Compile the libpathrs module.
	compile_module(include_dirs=[os.path.join(ROOT_DIR, "include")],
				   library_dirs=lib_paths)

if __name__ == "__main__":
	main()

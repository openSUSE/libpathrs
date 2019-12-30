## `libpathrs` ##

[![build status](https://travis-ci.org/openSUSE/libpathrs.svg?branch=master)](https://travis-ci.org/openSUSE/libpathrs)
[![dependency status](https://deps.rs/repo/github/openSUSE/libpathrs/status.svg)](https://deps.rs/repo/github/openSUSE/libpathrs)

![License: LGPL-3.0-or-later](https://img.shields.io/github/license/openSUSE/libpathrs.svg)

This library implements a set of C-friendly APIs (written in Rust) to make path
resolution within a potentially-untrusted directory safe on GNU/Linux. There
are countless examples of security vulnerabilities caused by bad handling of
paths (symlinks make the issue significantly worse).

I have been working on [kernel patches to make this trivial to do
safely][lwn-atflags] (which morphed into [a new syscall][lwn-openat2]), but in
order to safely use the new kernel API you need to restructure how you handle
paths quite significantly. Since a restructure is necessary anyway, having a
new library is not too much of a downside. In addition, this gives us the
ability to implement the core safety features through userspace emulation on
older kernels.

[lwn-atflags]: https://lwn.net/Articles/767547/
[lwn-openat2]: https://lwn.net/Articles/796868/

### Example ###

Here is a toy example of using this library to open a path (`/etc/passwd`)
inside a root filesystem (`/path/to/root`) safely. More detailed examples can
be found in `examples/` and `tests/`.

```c
#include <pathrs.h>

int get_my_fd(void)
{
	const char *root_path = "/path/to/root";
	const char *unsafe_path = "/etc/passwd";

	int fd = -1;
	pathrs_root_t *root = NULL;
	pathrs_handle_t *handle = NULL;
	pathrs_error_t *error = NULL;

	root = pathrs_open(root_path);
	error = pathrs_error(PATHRS_ROOT, root);
	if (error)
		goto err;

	handle = pathrs_resolve(root, unsafe_path);
	error = pathrs_error(PATHRS_ROOT, root);
	if (error) /* or (!handle) */
		goto err;

	fd = pathrs_reopen(handle, O_RDONLY);
	error = pathrs_error(PATHRS_HANDLE, handle);
	if (error) /* or (fd < 0) */
		goto err;

err:
	if (error)
		fprintf(stderr, "Uh-oh: %s (errno=%d)\n", error->description, error->saved_errno);
	pathrs_free(PATHRS_ROOT, root);
	pathrs_free(PATHRS_HANDLE, handle);
	pathrs_free(PATHRS_ERROR, error);
	return fd;
}
```

### License ###

`libpathrs` is licensed under the GNU LGPLv3 (or any later version).

```
libpathrs: safe path resolution on Linux
Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
Copyright (C) 2019 SUSE LLC

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.
```

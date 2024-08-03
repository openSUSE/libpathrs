## `libpathrs` ##

[![rust-ci build status](https://github.com/openSUSE/libpathrs/actions/workflows/rust.yml/badge.svg)](https://github.com/openSUSE/libpathrs/actions/workflows/rust.yml)
[![bindings-ci build status](https://github.com/openSUSE/libpathrs/actions/workflows/bindings.yml/badge.svg)](https://github.com/openSUSE/libpathrs/actions/workflows/bindings.yml)
[![docs](https://docs.rs/pathrs/badge.svg)](https://docs.rs/pathrs/)
[![dependency status](https://deps.rs/repo/github/openSUSE/libpathrs/status.svg)](https://deps.rs/repo/github/openSUSE/libpathrs)

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

	int liberr = 0;
	int root = -EBADF,
		handle = -EBADF,
		fd = -EBADF;

	root = pathrs_root_open(root_path);
	if (root < 0) {
		liberr = root;
		goto err;
	}

	handle = pathrs_resolve(root, unsafe_path);
	if (handle < 0) {
		liberr = handle;
		goto err;
	}

	fd = pathrs_reopen(handle, O_RDONLY);
	if (fd < 0) {
		liberr = fd;
		goto err;
	}

err:
	if (liberr < 0) {
		pathrs_error_t *error = pathrs_errorinfo(liberr);
		fprintf(stderr, "Uh-oh: %s (errno=%d)\n", error->description, error->saved_errno);
		pathrs_errorinfo_free(error);
	}
	close(root);
	close(handle);
	return fd;
}
```

### License ###

`libpathrs` is licensed under the GNU LGPLv3 (or any later version).

```
libpathrs: safe path resolution on Linux
Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
Copyright (C) 2019-2024 SUSE LLC

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

<hr/>

The language-specific bindings (the code in `contrib/bindings/` and
`go-pathrs/`) are licensed under the Apache-2.0 license, to allow for wider
usage of `libpathrs` from languages where language libraries are not
dynamically linked.

**NOTE**: If you compile libpathrs.so into your binary statically, you still
need to abide by the LGPLv3 license. In practice this means at least providing
the object files necessary to allow someone to recompile your program using a
modified libpathrs. See the LGPLv3 license for more details.

```
libpathrs: safe path resolution on Linux
Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
Copyright (C) 2019-2024 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

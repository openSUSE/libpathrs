## `libpathrs` ##

![License: LGPL-3.0-or-later](https://img.shields.io/github/license/openSUSE/libpathrs.svg)
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
	int fd = -1;
	pathrs_root_t *root = NULL;
	pathrs_handle_t *handle = NULL;
	pathrs_error_t *error = NULL;

	root = pathrs_open("/path/to/root");
	error = pathrs_error(PATHRS_ROOT, root);
	if (error)
		goto err;

	handle = pathrs_resolve(root, "/etc/passwd");
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

out:
	pathrs_free(PATHRS_ROOT, root);
	pathrs_free(PATHRS_HANDLE, handle);
	pathrs_free(PATHRS_ERROR, error);
	return fd;
}
```

### Outstanding Items ###

`libpathrs` is still being developed, and so there are still several aspects
that have yet to be implemented and are considered important before it can be
released to the public (items will be removed from the list as they are
implemented).

* Helper functions to make commonly-used functions easier to implement:
  - `Root::remove_all` (similar to `rm -rf` or Go's `os.RemoveAll`).
  - `Root::mkdir_all` (similar `mkdir -p` or Go's `os.MkdirAll`).
  - `Root::walk` (and similar infrastructure). It's unclear how we'd be able to
	handle (for instance) a safe way to remove a `Handle` from the tree.
  - And more to come...
* Verify that `umoci unpack --rootless` could actually be ported to `libpathrs`
  (either by reimplementing the underlying tricks, or making sure that an
  unprivileged user namespace setup is compatible with `libpathrs`).
* A robust test suite, which tests known (and plausible) attack scenarios both
  in native Rust and using the language bindings. Obviously the tests need to
  exercise all of the resolver backends.
* A `hardcore` resolver which uses `pivot_root` and namespaces to fetch a file
  descriptor completely correctly. This would require a fair amount of finesse
  to make sure it works on as many systems as possible (and we shouldn't use
  `newuidmap` because that smells very bad to me).

[snafu]: https://docs.rs/snafu/

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

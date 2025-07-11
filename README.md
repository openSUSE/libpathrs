## `libpathrs` ##

[![rust-ci build status](https://github.com/openSUSE/libpathrs/actions/workflows/rust.yml/badge.svg)](https://github.com/openSUSE/libpathrs/actions/workflows/rust.yml)
[![bindings-c build status](https://github.com/openSUSE/libpathrs/actions/workflows/bindings-c.yml/badge.svg)](https://github.com/openSUSE/libpathrs/actions/workflows/bindings-c.yml)
[![bindings-go build status](https://github.com/openSUSE/libpathrs/actions/workflows/bindings-go.yml/badge.svg)](https://github.com/openSUSE/libpathrs/actions/workflows/bindings-go.yml)
[![bindings-python build status](https://github.com/openSUSE/libpathrs/actions/workflows/bindings-python.yml/badge.svg)](https://github.com/openSUSE/libpathrs/actions/workflows/bindings-python.yml)
[![docs](https://docs.rs/pathrs/badge.svg)](https://docs.rs/pathrs/)

[![dependency status](https://deps.rs/repo/github/openSUSE/libpathrs/status.svg)](https://deps.rs/repo/github/openSUSE/libpathrs)
[![msrv](https://shields.io/crates/msrv/pathrs)](Cargo.toml)

This library implements a set of C-friendly APIs (written in Rust) to make path
resolution within a potentially-untrusted directory safe on GNU/Linux. There
are countless examples of security vulnerabilities caused by bad handling of
paths (symlinks make the issue significantly worse).

### Example ###

#### Root and Handle API ####

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

	root = pathrs_open_root(root_path);
	if (root < 0) {
		liberr = root;
		goto err;
	}

	handle = pathrs_inroot_resolve(root, unsafe_path);
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

#### Safe `procfs` API ####

`libpathrs` also provides a set of primitives to safely interact with `procfs`.
This is very important for some programs (such as container runtimes), because
`/proc` has several key system administration purposes that make it different
to other filesystems. It particular, `/proc` is used:

1. As a mechanism for doing certain filesystem operations through
   `/proc/self/fd/...` (and other similar magic-links) that cannot be done by
   other means.
1. As a source of true information about processes and the general system (such
   as by looking `/proc/$pid/status`).
1. As an administrative tool for managing processes (such as setting LSM labels
   like `/proc/self/attr/apparmor/exec`).

These operations have stronger requirements than regular filesystems. For (1)
we need to open the magic-link for real (magic-links are symlinks that are not
resolved lexically, they are in-kernel objects that warp you to other files
without doing a regular path lookup) which much harder to do safely (even with
`openat2`). For (2) and (3) we have the requirement that we need to open a
specific file, not just any file within `/proc` (if there are overmounts or
symlinks) which is not the case `pathrs_inroot_resolve()`. As a result, it is
necessary to take far more care when doing operations of `/proc` and
`libpathrs` provides very useful helper to do this. Failure to do so can lead
to security issues such as those in [CVE-2019-16884][cve-2019-16884] and
[CVE-2019-19921][cve-2019-19921].

In addition, with the [new mount API][lwn-newmount] (`fsopen(2)` and
`open_tree(2)` in particular, added in Linux 5.2), it is possible to get a
totally private `procfs` handle that can be used without worrying about racing
mount operations. `libpathrs` will try to use this if it can (this usually
requires root).

Here are a few examples of practical things you might want to do with
`libpathrs`'s `procfs` API:

```c
/*
 * Safely get an fd to /proc/self/exe. This is something runc does to re-exec
 * itself during the container setup process.
 */
int get_self_exe(void)
{
    /* This follows the trailing magic-link! */
    int fd = pathrs_proc_open(PATHRS_PROC_SELF, "exe", O_PATH);
    if (fd < 0) {
        pathrs_error_t *error = pathrs_errorinfo(fd);
        /* ... print the error ... */
        pathrs_errorinfo_free(error);
        return -1;
    }
    return fd;
}

/*
 * Safely set the AppArmor exec label for the current process. This is
 * something runc does while configuring the container process.
 */
int write_apparmor_label(const char *label)
{
    int fd, err;

    /*
     * Note the usage of O_NOFOLLOW here. You should use O_NOFOLLOW except in
     * the very rare case where you need to open a magic-link or you really
     * want to follow a trailing symlink.
     */
    fd = pathrs_proc_open(PATHRS_PROC_SELF, "attr/apparmor/exec",
                          O_WRONLY|O_NOFOLLOW);
    if (fd < 0) {
        pathrs_error_t *error = pathrs_errorinfo(fd);
        /* ... print the error ... */
        pathrs_errorinfo_free(error);
        return -1;
    }

    err = write(fd, label, strlen(label));
    close(fd);
    return err;
}

/*
 * Sometimes you need to get the "real" path of a file descriptor. This path
 * MUST NOT be used for actual filesystem operations, because it's possible for
 * an attacker to move the file or change one of the path components to a
 * symlink, which could lead to you operating on files you didn't expect
 * (including host files if you're a container runtime).
 *
 * In most cases, this kind of function would be used for diagnostic purposes
 * (such as in error messages, to provide context about what file the error is
 * in relation to).
 */
char *get_unsafe_path(int fd)
{
    char *fdpath;

    if (asprintf(&fdpath, "fd/%d", fd) < 0)
        return NULL;

    int linkbuf_size = 128;
    char *linkbuf = malloc(size);
    if (!linkbuf)
        goto err;
    for (;;) {
        int len = pathrs_proc_readlink(PATHRS_PROC_THREAD_SELF,
                                       fdpath, linkbuf, linkbuf_size);
        if (len < 0) {
            pathrs_error_t *error = pathrs_errorinfo(fd);
            /* ... print the error ... */
            pathrs_errorinfo_free(error);
            goto err;
        }

        if (len <= linkbuf_size)
            break;

        linkbuf_size = len;
        linkbuf = realloc(linkbuf, linkbuf_size);
        if (!linkbuf)
            goto err;
    }

    free(fdpath);
    return linkbuf;

err:
    free(fdpath);
    free(linkbuf);
    return NULL;
}
```

[cve-2019-16884]: https://nvd.nist.gov/vuln/detail/CVE-2019-16884
[cve-2019-19921]: https://nvd.nist.gov/vuln/detail/CVE-2019-19921
[lwn-newmount]: https://lwn.net/Articles/759499/

### Kernel Support ###

`libpathrs` is designed to only work with Linux, as it uses several Linux-only
APIs.

`libpathrs` was designed alongside [`openat2(2)`][openat2.2] (available since
Linux 5.6) and dynamically tries to use the latest kernel features to provide
the maximum possible protection against racing attackers. However, it also
provides support for older kernel versions (in theory up to Linux 2.6.39 but we
do not currently test this) by emulating newer kernel features in userspace.

However, we strongly recommend you use at least Linux 5.6 to get a
reasonable amount of protection against various attacks, and ideally at
least Linux 6.8 to make use of all of the protections we have implemented.
See the following table for what kernel features we optionally support and
what they are used for.

| Feature               | Minimum Kernel Version  | Description | Fallback |
| --------------------- | ----------------------- | ----------- | -------- |
| `/proc/thread-self`   | Linux 3.17 (2014-10-05) | Used when operating on the current thread's `/proc` directory for use with `PATHRS_PROC_THREAD_SELF`. | `/proc/self/task/$tid` is used, but this might not be available in some edge cases so `/proc/self` is used as a final fallback. |
| [`open_tree(2)`]      | Linux 4.18 (2018-08-12) | Used to create a private procfs handle when operating on `/proc` (this is a copy of the host `/proc` -- in most cases this will also strip any overmounts). Requires `CAP_SYS_ADMIN` privileges. | Open a regular handle to `/proc`. This can lead to certain race attacks if the attacker can dynamically create mounts. |
| [`fsopen(2)`]         | Linux 5.1 (2019-05-05)  | Used to create a private procfs handle when operating on `/proc` (with a completely fresh copy of `/proc` -- in some cases this operation will fail if there are locked overmounts on top of `/proc`). Requires `CAP_SYS_ADMIN` privileges. | Try to use [`open_tree(2)`] instead -- in the case of errors due to locked overmounts, [`open_tree(2)`] will be used to create a recursive copy that preserves the overmounts. This means that an attacker would not be able to actively change the mounts on top of `/proc` but there might be some overmounts that libpathrs will detect (and reject). |
| [`openat2(2)`]        | Linux 5.6 (2020-03-29)  | In-kernel restrictions of path lookup. This is used extensively by `libpathrs` to safely do path lookups. | Userspace emulated path lookups. |
| `STATX_MNT_ID`        | Linux 5.8 (2020-08-02)  | Used to verify whether there are bind-mounts on top of `/proc` that could result in insecure operations (on systems with `fsopen(2)` or `open_tree(2)` this protection is somewhat redundant for privileged programs -- those kinds of `procfs` handles will typically not have overmounts.) | Parse the `/proc/thread-self/fdinfo/$fd` directly -- for systems with `openat2(2)`, this is guaranteed to be safe against attacks. For systems without `openat2(2)`, we have to fallback to unsafe opens that could be fooled by bind-mounts -- however, we believe that exploitation of this would be difficult in practice (even with an attacker that has the persistent ability to mount to arbitrary paths) due to the way we verify `procfs` accesses. |
| `STATX_MNT_ID_UNIQUE` | Linux 6.8 (2024-03-10)  | Used for the same reason as `STATX_MNT_ID`, but allows us to protect against mount ID recycling. This is effectively a safer version of `STATX_MNT_ID`. | `STATX_MNT_ID` is used (see the `STATX_MNT_ID` fallback if it's not available either). |

For more information about the work behind `openat2(2)`, you can read the
following LWN articles (note that the merged version of `openat2(2)` is
different to the version described by LWN):

 * [New AT_ flags for restricting pathname lookup][lwn-atflags]
 * [Restricting path name lookup with openat2()][lwn-openat2]

[openat2.2]: https://www.man7.org/linux/man-pages/man2/openat2.2.html
[lwn-atflags]: https://lwn.net/Articles/767547/
[lwn-openat2]: https://lwn.net/Articles/796868/

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

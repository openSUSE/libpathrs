/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019 SUSE LLC
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef _PATHRS_H_
#define _PATHRS_H_

#include <stdbool.h>

/*
 * libpathrs has its own error-handling library so when you encounter an error
 * (a pointer-returning function gives NULL, or an int-returning function
 * returns a negative result) the corresponding error message is stored for
 * later retrieval.
 *
 * Please be aware that subsequent libpathrs operations will clear this stored
 * error value, so treat it like errno (get a copy as soon as you notice the
 * error). Memory management of the error buffer is up to you, and all returned
 * lengths *include the trailing NUL byte*.
 */

/*
 * Get the string size currently-stored error (including the trailing NUL
 * byte). A return value of 0 indicates that there is no currently-stored
 * error. Cannot fail.
 */
int pathrs_error_length(void);

/*
 * Copy the currently-stored error string into the provided buffer. If the
 * buffer is not large enough to fit the message (see pathrs_error_length) or
 * is NULL, then -1 is returned. If the operation succeeds, the number of bytes
 * written (including the trailing NUL byte) is returned and the error is
 * cleared from libpathrs's side. If there was no error, then 0 is returned.
 */
int pathrs_error(char *buffer, int length);

/*
 * A handle to the root of a directory tree to resolve within. The only purpose
 * of this "root handle" is to get Handles to inodes within the directory tree.
 *
 * At the time of writing, it is considered a *VERY BAD IDEA* to open a Root
 * inside a possibly-attacker-controlled directory tree. While we do have
 * protections that should defend against it (for both drivers), it's far more
 * dangerous than just opening a directory tree which is not inside a
 * potentially-untrusted directory.
 */
struct pathrs_root_t;

/*
 * A handle to a path within a given Root. This handle references an
 * already-resolved path which can be used for only one purpose -- to "re-open"
 * the handle and get an actual fs::File which can be used for ordinary
 * operations.
 *
 * It is critical for the safety of users of this library that *at no point* do
 * you use interfaces like libc::openat directly on file descriptors you get
 * from using this library (or extract the RawFd from a fs::File). You must
 * always use operations through a Root.
 */
struct pathrs_handle_t;

/*
 * Open a root handle. The correct backend (native/kernel or emulated) to use
 * is auto-detected based on whether the kernel supports openat2(2).
 *
 * The provided path must be an existing directory. If using the emulated
 * driver, it also must be the fully-expanded path to a real directory (with no
 * symlink components) because the given path is used to double-check that the
 * open operation was not affected by an attacker.
 */
pathrs_root_t *pathrs_open(const char *pathname);
/* Free a root handle. */
void pathrs_rfree(pathrs_root_t *root);

/*
 * "Upgrade" the handle to a usable fd, suitable for reading and writing. This
 * does not consume the original handle (allowing for it to be used many
 * times).
 *
 * It should be noted that the use of O_CREAT *is not* supported (and will
 * result in an error). Handles only refer to *existing* files. Instead you
 * need to use inroot_creat().
 */
int handle_reopen(pathrs_handle_t *handle, unsigned long flags);
/* Free a handle. */
void pathrs_hfree(pathrs_handle_t *handle);

/*
 * Within the given root's tree, resolve the given path (with all symlinks
 * being scoped to the root) and return a handle to that path. The path *must
 * already exist*, otherwise an error will occur.
 */
pathrs_handle_t *inroot_resolve(pathrs_root_t *root, const char *pathname);

/*
 * Within the root, create an inode at the path with the given mode. If the
 * path already exists, an error is returned (effectively acting as though
 * O_EXCL is always set). Each inroot_* corresponds to the matching syscall.
 */
int inroot_creat(pathrs_root_t *root, const char *pathname, mode_t mode);
int inroot_mkdir(pathrs_root_t *root, const char *pathname, mode_t mode);
int inroot_mknod(pathrs_root_t *root, const char *pathname, mode_t mode, dev_t dev);

#endif /* _PATHRS_H_ */

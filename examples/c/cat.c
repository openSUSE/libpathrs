/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2021 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2021 SUSE LLC
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

/*
 * File: examples/c/cat.c
 *
 * An example program which opens a file inside a root and outputs its contents
 * using libpathrs.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "../../include/pathrs.h"

#define bail(fmt, ...) \
	do { fprintf(stderr, fmt "\n", #__VA_ARGS__); exit(1); } while (0)

/* Helper to output a pathrs_error_t in a readable format. */
void print_error(pathrs_error_t *error)
{
	int saved_errno = error->saved_errno;

	if (saved_errno)
		printf("ERROR[%s]: %s\n", strerror(saved_errno), error->description);
	else
		printf("ERROR: %s\n", error->description);

	errno = saved_errno;
}

int open_in_root(const char *root_path, const char *unsafe_path)
{
	int liberr = 0;
	int rootfd = -EBADF, fd = -EBADF;

	rootfd = pathrs_open_root(root_path);
	if (rootfd < 0) {
		liberr = rootfd;
		goto err;
	}

	fd = pathrs_inroot_open(rootfd, unsafe_path, O_RDONLY);
	if (fd < 0) {
		liberr = fd;
		goto err;
	}

err:
	close(rootfd);

	if (liberr < 0) {
		pathrs_error_t *error = pathrs_errorinfo(liberr);
		print_error(error);
		pathrs_errorinfo_free(error);
	}
	return fd;
}

void usage(void) {
	printf("usage: cat <root> <unsafe-path>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int fd;
	char *root, *path;

	if (argc != 3)
		usage();

	root = argv[1];
	path = argv[2];

	/*
	 * Safely open the file descriptor. Normally applications would create a
	 * root handle and persist it for longer periods of time, but this is such
	 * a trivial example it's not necessary.
	 */
	fd = open_in_root(root, path);
	if (fd < 0)
		bail("open_in_root failed: %m");

	/* Pipe the contents to stdout. */
	for (;;) {
		ssize_t copied, written;
		char buffer[1024];

		copied = read(fd, buffer, sizeof(buffer));
		if (copied < 0)
			bail("read failed: %m");
		else if (copied == 0)
			break;

		written = write(STDOUT_FILENO, buffer, copied);
		if (written < 0)
			bail("write failed: %m");
		if (written != copied)
			bail("write was short (read %dB, wrote %dB)", copied, written);
	}

	close(fd);
	return 0;
}

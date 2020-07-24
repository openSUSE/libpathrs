/*
 * libpathrs: safe path resolution on Linux
 * Copyright (C) 2019-2020 Aleksa Sarai <cyphar@cyphar.com>
 * Copyright (C) 2019-2020 SUSE LLC
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
 * File: examples/cat.c
 *
 * An example program which opens a file inside a root and outputs its contents
 * using libpathrs.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "../include/pathrs.h"

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

	if (error->backtrace) {
		printf("Rust Backtrace:\n");
		/* We have to iterate over a Rust vector, so this is a bit unwieldy. */
		for (int i = 0; i < error->backtrace->length; i++) {
			const __pathrs_backtrace_entry_t *entry = &error->backtrace->head[i];

			if (entry->symbol_name)
				printf("'%s'@", entry->symbol_name);
			printf("<0x%x>+0x%x\n", entry->symbol_address, entry->ip - entry->symbol_address);
			if (entry->symbol_file)
				printf("  in file '%s':%d\n", entry->symbol_file, entry->symbol_lineno);
		}
	}

	errno = saved_errno;
}

int open_in_root(const char *root_path, const char *unsafe_path)
{
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
		print_error(error);

out:
	pathrs_free(PATHRS_ROOT, root);
	pathrs_free(PATHRS_HANDLE, handle);
	pathrs_free(PATHRS_ERROR, error);
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

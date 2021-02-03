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
 * File: examples/cat_mulithread.c
 *
 * An example program which opens a file inside a root and outputs its contents
 * using libpathrs.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

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

struct args {
	pthread_barrier_t *barrier;
	pathrs_root_t *root;
	const char *path;
};

void *worker(void *_arg) {
	struct args *arg = _arg;

	int root_fd = -1, handle_fd = -1, fd = -1;
	pathrs_root_t *new_root = NULL;
	pathrs_handle_t *handle = NULL;
	pathrs_error_t *error = NULL;

	pthread_barrier_wait(arg->barrier);

	new_root = pathrs_duplicate(PATHRS_ROOT, arg->root);
	error = pathrs_error(PATHRS_ROOT, arg->root);
	if (!new_root || error)
		goto err;

	root_fd = pathrs_into_fd(PATHRS_ROOT, new_root);
	error = pathrs_error(PATHRS_ROOT, new_root);
	if (root_fd < 0 || error)
		goto err;

	pathrs_free(PATHRS_ROOT, new_root);
	new_root = NULL;

	new_root = pathrs_from_fd(PATHRS_ROOT, root_fd);
	error = pathrs_error(PATHRS_ROOT, new_root);
	if (!new_root || error)
		goto err;

	handle = pathrs_resolve(new_root, arg->path);
	error = pathrs_error(PATHRS_ROOT, new_root);
	if (!handle || error)
		goto err;

	handle_fd = pathrs_into_fd(PATHRS_HANDLE, handle);
	error = pathrs_error(PATHRS_HANDLE, handle);
	if (handle_fd < 0 || error)
		goto err;

	pathrs_free(PATHRS_HANDLE, handle);
	handle = NULL;

	handle = pathrs_from_fd(PATHRS_HANDLE, handle_fd);
	error = pathrs_error(PATHRS_HANDLE, handle);
	if (!handle || error)
		goto err;

	fd = pathrs_reopen(handle, O_RDONLY);
	error = pathrs_error(PATHRS_HANDLE, handle);
	if (fd < 0 || error)
		goto err;

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

err:
	if (error)
		print_error(error);
out:
	if (fd >= 0)
		close(fd);
	if (root_fd >= 0)
		close(root_fd);
	if (handle_fd >= 0)
		close(handle_fd);
	pathrs_free(PATHRS_ROOT, new_root);
	pathrs_free(PATHRS_HANDLE, handle);
	pathrs_free(PATHRS_ERROR, error);
	return NULL;
}

void usage(void) {
	printf("usage: cat <root> <unsafe-path>\n");
	exit(1);
}

#define NUM_THREADS 32

int main(int argc, char **argv)
{
	char *path, *root_path;
	pthread_barrier_t barrier;
	pthread_t threads[NUM_THREADS] = {};
	struct args thread_args[NUM_THREADS] = {};

	pathrs_root_t *root = NULL;
	pathrs_error_t *error = NULL;

	if (argc != 3)
		usage();

	root_path = argv[1];
	path = argv[2];

	root = pathrs_open(root_path);
	error = pathrs_error(PATHRS_ROOT, root);
	if (!root || error)
		goto err;

	pthread_barrier_init(&barrier, NULL, NUM_THREADS);
	for (size_t i = 0; i < NUM_THREADS; i++) {
		pthread_t *thread = &threads[i];
		struct args *arg = &thread_args[i];

		*arg = (struct args) {
			.path = path,
			.root = root,
			.barrier = &barrier,
		};
		pthread_create(thread, NULL, worker, arg);
	}

	for (size_t i = 0; i < NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

err:
	if (error)
		print_error(error);

	pathrs_free(PATHRS_ROOT, root);
	pathrs_free(PATHRS_ERROR, error);
	return 0;
}

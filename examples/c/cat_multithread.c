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
 * File: examples/c/cat_multithread.c
 *
 * An example program which opens a file inside a root and outputs its contents
 * using libpathrs, but multithreaded to show that there are no obvious race
 * conditions when using pathrs.
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

	errno = saved_errno;
}

struct args {
	pthread_barrier_t *barrier;
	int rootfd;
	const char *path;
};

void *worker(void *_arg) {
	struct args *arg = _arg;

	int liberr = 0;
	int handlefd = -EBADF, fd = -EBADF;

	pthread_barrier_wait(arg->barrier);

	handlefd = pathrs_resolve(arg->rootfd, arg->path);
	if (handlefd < 0) {
		liberr = handlefd;
		goto err;
	}

	fd = pathrs_reopen(handlefd, O_RDONLY);
	if (fd < 0) {
		liberr = fd;
		goto err;
	}

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
	if (liberr < 0) {
		pathrs_error_t *error = pathrs_errorinfo(liberr);
		print_error(error);
		pathrs_errorinfo_free(error);
	}
	close(fd);
	close(handlefd);
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

	int liberr = 0;
	int rootfd = -EBADF;

	if (argc != 3)
		usage();

	root_path = argv[1];
	path = argv[2];

	rootfd = pathrs_root_open(root_path);
	if (rootfd < 0) {
		liberr = rootfd;
		goto err;
	}

	pthread_barrier_init(&barrier, NULL, NUM_THREADS);
	for (size_t i = 0; i < NUM_THREADS; i++) {
		pthread_t *thread = &threads[i];
		struct args *arg = &thread_args[i];

		*arg = (struct args) {
			.path = path,
			.rootfd = rootfd,
			.barrier = &barrier,
		};
		pthread_create(thread, NULL, worker, arg);
	}

	for (size_t i = 0; i < NUM_THREADS; i++)
		pthread_join(threads[i], NULL);

err:
	if (liberr < 0) {
		pathrs_error_t *error = pathrs_errorinfo(liberr);
		print_error(error);
		pathrs_errorinfo_free(error);
	}

	close(rootfd);
	return 0;
}

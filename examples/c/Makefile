# libpathrs: safe path resolution on Linux
# Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019-2024 SUSE LLC
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

CC ?= gcc

CFLAGS := $(shell pkg-config --cflags pathrs)
LDFLAGS := $(shell pkg-config --libs-only-L --libs-only-other pathrs)
LDLIBS := $(shell pkg-config --libs-only-l pathrs)

.PHONY: all
all: $(patsubst %.c,%,$(wildcard *.c))

cat_multithread: LDLIBS += -lpthread

.PHONY: smoke-test
smoke-test: cat cat_multithread
	./cat . ../../cat.c >/dev/null
	./cat_multithread . ../../cat_multithread.c >/dev/null

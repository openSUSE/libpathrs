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

PYTHON ?= python3
PIP ?= pip3

SRC_FILES := $(wildcard *.py pathrs/*.py)

dist: $(SRC_FILES) pyproject.toml
	$(PYTHON) -m build

.PHONY: clean
clean:
	rm -rf dist/ pathrs.*-info/ pathrs/__pycache__/ pathrs/_libpathrs_cffi.*

.PHONY: lint
lint:
	ruff format --check --diff .
	ruff check .
	mypy .

.PHONY: install
install: dist
	$(PIP) install dist/pathrs*.whl

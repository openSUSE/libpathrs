#!/usr/bin/python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019-2024 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019-2024 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import setuptools

from typing import Any, Dict


# This is only needed for backwards compatibility with older versions.
def parse_pyproject() -> Dict[str, Any]:
    try:
        import tomllib

        openmode = "rb"
    except ImportError:
        # TODO: Remove this once we only support Python >= 3.11.
        import toml as tomllib  # type: ignore

        openmode = "r"

    with open("pyproject.toml", openmode) as f:
        return tomllib.load(f)


pyproject = parse_pyproject()

setuptools.setup(
    # For backwards-compatibility with pre-pyproject setuptools.
    name=pyproject["project"]["name"],
    version=pyproject["project"]["version"],
    install_requires=pyproject["project"]["dependencies"],
    # Configure cffi building.
    ext_package="pathrs",
    platforms=["Linux"],
    cffi_modules=["pathrs/pathrs_build.py:ffibuilder"],
)

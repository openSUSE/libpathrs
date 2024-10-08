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

import importlib
import importlib.metadata

from . import _pathrs
from ._pathrs import *

# In order get pydoc to include the documentation for the re-exported code from
# _pathrs, we need to include all of the members in __all__. Rather than
# duplicating the member list here explicitly, just re-export __all__.
__all__ = []
__all__ += _pathrs.__all__  # pyright doesn't support "=" here.

try:
    # In order to avoid drift between this version and the dist-info/ version
    # information, just fill __version__ with the dist-info/ information.
    __version__ = importlib.metadata.version("pathrs")
except importlib.metadata.PackageNotFoundError:
    # We're being run from a local directory without an installed version of
    # pathrs, so just fill in a dummy version.
    __version__ = "<unknown>"

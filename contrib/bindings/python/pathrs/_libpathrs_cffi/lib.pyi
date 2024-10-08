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

import cffi

from typing import Optional, overload, type_check_only, Union

# TODO: Remove this once we only support Python >= 3.10.
from typing_extensions import TypeAlias, Literal

from .._pathrs import CBuffer, CString, ProcfsBase

# pathrs_errorinfo_t *
@type_check_only
class CError:
    saved_errno: int
    description: CString

ErrorId: TypeAlias = int
RawFd: TypeAlias = int

# TODO: We actually return Union[CError, cffi.FFI.NULL] but we can't express
#       this using the typing stubs for CFFI...
def pathrs_errorinfo(err_id: Union[ErrorId, int]) -> CError: ...
def pathrs_errorinfo_free(err: CError) -> None: ...

PATHRS_PROC_ROOT: ProcfsBase
PATHRS_PROC_SELF: ProcfsBase
PATHRS_PROC_THREAD_SELF: ProcfsBase

def pathrs_proc_open(
    base: ProcfsBase, path: CString, flags: int
) -> Union[RawFd, ErrorId]: ...
def pathrs_proc_readlink(
    base: ProcfsBase, path: CString, linkbuf: CBuffer, linkbuf_size: int
) -> Union[int, ErrorId]: ...
def pathrs_root_open(path: CString) -> Union[RawFd, ErrorId]: ...
def pathrs_reopen(fd: RawFd, flags: int) -> Union[RawFd, ErrorId]: ...
def pathrs_resolve(rootfd: RawFd, path: CString) -> Union[RawFd, ErrorId]: ...
def pathrs_resolve_nofollow(rootfd: RawFd, path: CString) -> Union[RawFd, ErrorId]: ...
def pathrs_creat(
    rootfd: RawFd, path: CString, flags: int, filemode: int
) -> Union[RawFd, ErrorId]: ...
def pathrs_rename(
    rootfd: RawFd, src: CString, dst: CString, flags: int
) -> Union[Literal[0], ErrorId]: ...
def pathrs_rmdir(rootfd: RawFd, path: CString) -> Union[Literal[0], ErrorId]: ...
def pathrs_unlink(rootfd: RawFd, path: CString) -> Union[Literal[0], ErrorId]: ...
def pathrs_remove_all(rootfd: RawFd, path: CString) -> Union[RawFd, ErrorId]: ...
def pathrs_mkdir(
    rootfd: RawFd, path: CString, mode: int
) -> Union[Literal[0], ErrorId]: ...
def pathrs_mkdir_all(
    rootfd: RawFd, path: CString, mode: int
) -> Union[Literal[0], ErrorId]: ...
def pathrs_mknod(
    rootfd: RawFd, path: CString, mode: int, dev: int
) -> Union[Literal[0], ErrorId]: ...
def pathrs_hardlink(
    rootfd: RawFd, path: CString, target: CString
) -> Union[Literal[0], ErrorId]: ...
def pathrs_symlink(
    rootfd: RawFd, path: CString, target: CString
) -> Union[Literal[0], ErrorId]: ...
def pathrs_readlink(
    rootfd: RawFd, path: CString, linkbuf: CBuffer, linkbuf_size: int
) -> Union[int, ErrorId]: ...

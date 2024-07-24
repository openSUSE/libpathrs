#!/bin/bash
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

set -Eeuo pipefail

src_dir="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")"
pushd "$src_dir"

get_crate_info() {
	# TODO: Should we use toml-cli if it's available?
	field="$1"
	sed -En '/^'"$field"'/ s/^.*=\s+"(.*)"/\1/ p' "$src_dir/Cargo.toml"
}
FULLVERSION="$(get_crate_info version)"

get_so_version() {
	# TODO: The soversion should probably be separated from the Crate version
	# -- we only need to bump the soversion if we have to introduce a
	# completely incompatible change to the C API (that can't be kept using
	# symbol versioning and aliases). It seems very unlikely we will ever need
	# to bump this.
	echo "${FULLVERSION%%.*}"
}
SOVERSION="$(get_so_version)"

SONAME="lib$(get_crate_info name).so.$FULLVERSION"

# Try to emulate autoconf's basic flags.
usage() {
	[ "$#" -eq 0 ] || echo "ERROR:" "$@" >&2

	cat >&2 <<-EOF
	usage: ${BASH_SOURCE[0]} [a subset of autoconf args]

	Install libpathrs in a way that should make it easier to package. This
	script takes a small subset of autoconf arguments (such as --prefix) and
	uses them to tailor the installation destinations and generated pkg-config
	manifest so that distributions should be able to just use this script.

	Arguments:

	The following autoconf arguments are accepted by this script. The value in
	brackets is the default value used if the flags are not specified.

	  --prefix[=/usr/local]
	  --exec-prefix[=<prefix>]
	  --includedir=[<prefix>/include]
	  --libdir=[<prefix>/lib(64)]

	As with automake, if the DESTDIR= environment variable is set, this script
	will install the files into DESTDIR as though it were the root of the
	filesystem. This is usually used for distribution packaging.

	Example:

	In an openSUSE rpm spec, this script could be used like this:

	  %install
	  DESTDIR=%{buildroot} ./install.sh \\
	      --prefix=%{_prefix} \\
	      --exec-prefix=%{_exec_prefix} \\
	      --includedir=%{_includedir} \\
	      --libdir=%{_libdir}

	This script is part of the libpathrs project. If you find a bug, please
	report it to <https://github.com/openSUSE/libpathrs>.
	EOF

	exit_code=0
	[ "$#" -gt 0 ] && exit_code=1
	exit "$exit_code"
}
GETOPT="$(getopt -o h --long help,prefix:,exec-prefix:,includedir:,libdir: -- "$@")"
eval set -- "$GETOPT"

DESTDIR="${DESTDIR:-}"
prefix="/usr"
exec_prefix=
includedir=
libdir=
while true; do
	case "$1" in
		--prefix)      prefix="$2";      shift 2 ;;
		--exec-prefix) exec_prefix="$2"; shift 2 ;;
		--includedir)  includedir="$2";  shift 2 ;;
		--libdir)      libdir="$2";      shift 2 ;;
		--) shift; break ;;
		-h | --help) usage ;;
		*)           usage "unknown argument $1" ;;
	esac
done

[ "$#" -eq 0 ] || usage "unknown trailing arguments:" "$@"

find_libdir() {
	exec_prefix="$1"
	if [ -d "$exec_prefix/lib64" ]; then
		echo "$exec_prefix/lib64"
	else
		echo "$exec_prefix/lib"
	fi
}

# Apply default values using $prefix. Do this after parsing the other values so
# that if a user just changes --prefix things still work.
exec_prefix="${exec_prefix:-$prefix}"
includedir="${includedir:-$prefix/include}"
libdir="${libdir:-$(find_libdir "$exec_prefix")}"

cat >"pathrs.pc" <<EOF
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

prefix=$prefix
exec_prefix=$exec_prefix
includedir=$includedir
libdir=$libdir

Name: libpathrs
Version: $FULLVERSION
Description: Safe path resolution library for Linux
URL: https://github.com/openSUSE/libpathrs
Cflags: -I\${includedir}
Libs: -L\${libdir} -lpathrs
EOF
echo "[install] generate pathrs pkg-config"

echo "[install] installing libpathrs into DESTDIR=${DESTDIR:-/}"
set -x
install -Dt "$DESTDIR/$libdir/pkgconfig/" -m 0644 pathrs.pc
install -Dt "$DESTDIR/$includedir/"       -m 0644 include/pathrs.h
install -DT -m 0755 target/release/libpathrs.so "$DESTDIR/$libdir/$SONAME"
ln -sf "$SONAME" "$DESTDIR/$libdir/libpathrs.so.$SOVERSION"
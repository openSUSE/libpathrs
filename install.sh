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
pushd "$src_dir" |:

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
DEFAULT_PREFIX=/usr/local
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

	  --prefix=[$DEFAULT_PREFIX]
	  --exec-prefix=[PREFIX]
	  --includedir=[EPREFIX/include]
	  --libdir=[EPREFIX/lib(64)]              (lib64 is used if available)
	  --pkgconfigdir=[LIBDIR/pkgconfig]

	As with automake, if the DESTDIR= environment variable is set, this script
	will install the files into DESTDIR as though it were the root of the
	filesystem. This is usually used for distribution packaging. You can also
	pass environment variables as command-line arguments.

	Example:

	In an openSUSE rpm spec, this script could be used like this:

	  %install
	  ./install.sh \\
	      DESTDIR=%{buildroot} \\
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
GETOPT="$(getopt -o h --long help,prefix:,exec-prefix:,includedir:,libdir:,pkgconfigdir: -- "$@")"
eval set -- "$GETOPT"

DESTDIR="${DESTDIR:-}"
prefix="$DEFAULT_PREFIX"
exec_prefix=
includedir=
libdir=
pkgconfigdir=
while true; do
	case "$1" in
		--prefix)       prefix="$2";       shift 2 ;;
		--exec-prefix)  exec_prefix="$2";  shift 2 ;;
		--includedir)   includedir="$2";   shift 2 ;;
		--libdir)       libdir="$2";       shift 2 ;;
		--pkgconfigdir) pkgconfigdir="$2"; shift 2 ;;
		--) shift; break ;;
		-h | --help) usage ;;
		*)           usage "unknown argument $1" ;;
	esac
done


for extra_arg in "$@"; do
	if [[ "$extra_arg" = *=* ]]; then
		echo "[options] using $extra_arg from command-line"
		eval "$extra_arg"
	else
		usage "unknown trailing argument $extra_arg"
	fi
done

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
pkgconfigdir="${pkgconfigdir:-$libdir/pkgconfig}"

# TODO: These flags come from RUSTFLAGS="--print=native-static-libs".
# Unfortunately, getting this information from cargo is incredibly unergonomic
# and will hopefully be fixed at some point.
# <https://github.com/rust-lang/rust/pull/43067#issuecomment-330625316>
native_static_libs="-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc"

echo "[pkg-config] generating pathrs pkg-config"
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
Libs.private: $native_static_libs
EOF

echo "[install] installing libpathrs into DESTDIR=${DESTDIR:-/}"
set -x
# pkg-config.
install -Dt "$DESTDIR/$pkgconfigdir/" -m 0644 pathrs.pc
install -Dt "$DESTDIR/$includedir/"   -m 0644 include/pathrs.h
# Static library.
install -Dt "$DESTDIR/$libdir"        -m 0644 target/release/libpathrs.a
# Shared library.
install -DT -m 0755 target/release/libpathrs.so "$DESTDIR/$libdir/$SONAME"
ln -sf "$SONAME" "$DESTDIR/$libdir/libpathrs.so.$SOVERSION"
ln -sf "$SONAME" "$DESTDIR/$libdir/libpathrs.so"

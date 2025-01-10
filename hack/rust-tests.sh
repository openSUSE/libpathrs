#!/bin/bash
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019-2025 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019-2025 SUSE LLC
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

TEMP="$(getopt -o sc: --long sudo,cargo: -- "$@")"
eval set -- "$TEMP"

function bail() {
	echo "rust tests: $*" >&2
	exit 1
}

sudo=
CARGO="${CARGO_NIGHTLY:-cargo +nightly}"
while [ "$#" -gt 0 ]; do
	case "$1" in
		-s|--sudo)
			sudo=1
			shift
			;;
		-c|--cargo)
			CARGO="$2"
			shift 2
			;;
		--)
			shift
			break
			;;
		*)
			bail "unknown option $1"
	esac
done

function nextest_run() {
	features=("capi")

	if [ -v CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER ]; then
		unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER
	fi

	if [ -n "$sudo" ]; then
		features+=("_test_as_root")

		# This CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER magic lets us run Rust
		# tests as root without needing to run the build step as root.
		export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"
	fi

	$CARGO llvm-cov --no-report --branch --features "$(printf "%s," "${features[@]}")" \
		nextest "$@"

	if [ -v CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER ]; then
		unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER
	fi
}

set -x

nextest_run --no-fail-fast

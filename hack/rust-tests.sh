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

function contains() {
	local elem needle="$1"
	shift
	for elem in "$@"; do
		[[ "$elem" == "$needle" ]] && return 0
	done
	return 1
}

function strjoin() {
	local sep="$1"
	shift

	local str=
	until [[ "$#" == 0 ]]; do
		str+="${1:-}"
		shift
		[[ "$#" == 0 ]] && break
		str+="$sep"
	done
	echo "$str"
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

# These are features that do not make sense to add to the powerset of feature
# combinations we test for:
# * "capi" only adds tests and modules in a purely additive way, so re-running
#   the whole suite without them makes no sense.
# * "_test_as_root" requires special handling to enable (the "sudo -E" runner).
SPECIAL_FEATURES=("capi" "_test_as_root")

function nextest_run() {
	local features=("capi")

	if [ -v CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER ]; then
		unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER
	fi

	if [ -n "$sudo" ]; then
		features+=("_test_as_root")

		# This CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER magic lets us run Rust
		# tests as root without needing to run the build step as root.
		export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"
	fi

	# For SPECIAL_FEATURES not explicitly set with --features, we need to add
	# them to --disabled-features to make sure that we don't add them to the
	# powerset.
	local disabled_features=()
	for feature in "${SPECIAL_FEATURES[@]}"; do
		if ! contains "$feature" "${features[@]}"; then
			disabled_features+=("$feature")
		fi
	done
	# By definition the default featureset is going to be included in
	# the powerset, so there's no need to duplicate it as well.
	disabled_features+=("default")

	local cargo_hack_args=()
	if command -v cargo-hack &>/dev/null ; then
		cargo_hack_args=(
			# Do a powerset run.
			"hack" "--feature-powerset"
			# With all disabled features (i.e. _test_as_root when not running
			# as root) dropped completely.
			"--exclude-features=$(strjoin , "${disabled_features[@]}")"
			# Also, since SPECIAL_FEATURES are all guaranteed to either be in
			# --features or --exclude-features, we do not need to do an
			# --all-features run with "cargo hack".
			"--exclude-all-features"
		)
	fi

	$CARGO "${cargo_hack_args[@]}" \
		llvm-cov --no-report --branch --features "$(strjoin , "${features[@]}")" \
		nextest "$@"

	if [ -v CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER ]; then
		unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER
	fi
}

set -x

# Increase the maximum file descriptor limit from the default 1024 to whatever
# the hard limit is (which should be large enough) so that our racing
# remove_all tests won't fail with EMFILE. Ideally this workaround wouldn't be
# necessary, see <https://github.com/openSUSE/libpathrs/issues/149>.
ulimit -n "$(ulimit -Hn)"

# We need to run race and non-race tests separately because the racing tests
# can cause the non-race tests to error out spuriously. Hopefully in the future
# <https://github.com/nextest-rs/nextest/discussions/2054> will be resolved and
# nextest will make it easier to do this.
nextest_run --no-fail-fast -E "not test(#tests::test_race_*)"
nextest_run --no-fail-fast -E "test(#tests::test_race_*)"

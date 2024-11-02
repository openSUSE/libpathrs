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

CARGO ?= cargo
CARGO_NIGHTLY ?= cargo +nightly

RUSTC_FLAGS := --features=capi -- -C panic=abort
CARGO_FLAGS ?=

SRC_FILES = $(wildcard Cargo.*) $(shell find . -name '*.rs')

.DEFAULT: debug
.PHONY: debug
debug: target/debug

target/debug: $(SRC_FILES)
	# For some reason, --crate-types needs separate invocations. We can't use
	# #![crate_type] unfortunately, as using it with #![cfg_attr] has been
	# deprecated. <https://github.com/rust-lang/rust/issues/91632>
	$(CARGO) rustc $(CARGO_FLAGS) --crate-type=cdylib    $(RUSTC_FLAGS)
	$(CARGO) rustc $(CARGO_FLAGS) --crate-type=staticlib $(RUSTC_FLAGS)

.PHONY: release
release: target/release

target/release: $(SRC_FILES)
	# For some reason, --crate-types needs separate invocations. We can't use
	# #![crate_type] unfortunately, as using it with #![cfg_attr] has been
	# deprecated. <https://github.com/rust-lang/rust/issues/91632>
	$(CARGO) rustc $(CARGO_FLAGS) --release --crate-type=cdylib    $(RUSTC_FLAGS)
	$(CARGO) rustc $(CARGO_FLAGS) --release --crate-type=staticlib $(RUSTC_FLAGS)

.PHONY: smoke-test
smoke-test:
	make -C examples smoke-test

.PHONY: clean
clean:
	-rm -rf target/

.PHONY: lint
lint: lint-rust

.PHONY: lint-rust
lint-rust:
	$(CARGO_NIGHTLY) fmt --all -- --check
	$(CARGO) clippy --all-features --all-targets
	$(CARGO) check $(CARGO_FLAGS) --all-features --all-targets

.PHONY: test-rust-doctest
test-rust-doctest:
	$(CARGO_NIGHTLY) llvm-cov --no-report --branch --all-features --doc

.PHONY: test-rust-unpriv
test-rust-unpriv:
	$(CARGO_NIGHTLY) llvm-cov --no-report --branch --features capi nextest --no-fail-fast

.PHONY: test-rust-root
test-rust-root:
# Run Rust tests as root.
# NOTE: Ideally this would be configured in .cargo/config.toml so it
#       would also work locally, but unfortunately it seems cargo doesn't
#       support cfg(feature=...) for target runner configs.
#       See <https://github.com/rust-lang/cargo/issues/14306>.
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' \
		$(CARGO_NIGHTLY) llvm-cov --no-report --branch --features capi,_test_as_root nextest --no-fail-fast

.PHONY: test-rust
test-rust:
	-rm -rf target/llvm-cov*
	make test-rust-{doctest,unpriv,root}

.PHONY: test
test: test-rust
	$(CARGO_NIGHTLY) llvm-cov report
	$(CARGO_NIGHTLY) llvm-cov report --open

.PHONY: docs
docs:
	$(CARGO) doc --all-features --document-private-items --open

.PHONY: install
install: release
	@echo "If you want to configure the install paths, use ./install.sh directly."
	@echo "[Sleeping for 3 seconds.]"
	@sleep 3s
	./install.sh

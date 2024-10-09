# Changelog #
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] ##

## [0.1.3] - 2024-10-10 ##

> 自動化って物は試しとすればいい物だ

### Changed ###
- gha: our Rust crate and Python bindings are now uploaded automatically from a
  GitHub action when a tag is pushed.

### Fixes ###
- syscalls: the pretty-printing of `openat2` errors now gives a string
  description of the flags passed rather that just a hex value (to match other
  syscalls).
- python bindings: restrict how our methods and functions can be called using
  `/` and `*` to reduce the possibility of future breakages if we rename or
  re-order some of our arguments.

## [0.1.2] - 2024-10-09 ##

> 蛇のように賢く、鳩のように素直でありなさい

### Fixes ###
- python bindings: add a minimal README for PyPI.
- python bindings: actually export `PROC_ROOT`.
- python bindings: add type annotations and `py.typed` to allow for downstream
  users to get proper type annotations for the API.

## [0.1.1] - 2024-10-01 ##

> 頒布と聞いたら蛇に睨まれた蛙になるよ

### Added ###
- procfs: add support for operating on files in the `/proc` root (or other
  processes) with `ProcfsBase::ProcRoot`.

  While the cached file descriptor shouldn't leak into containers (container
  runtimes know to set `PR_SET_DUMPABLE`, and our cached file descriptor is
  `O_CLOEXEC`), I felt a little uncomfortable about having a global unmasked
  procfs handle sitting around in `libpathrs`. So, in order to avoid making a
  file descriptor leak by a `libpathrs` user catastrophic, `libpathrs` will
  always try to use a "limited" procfs handle as the global cached handle
  (which is much safer to leak into a container) and for operations on
  `ProcfsBase::ProcRoot`, a temporary new "unrestricted" procfs handle is
  created just for that operartion. This is more expensive, but it avoids a
  potential leak turning into a breakout or other nightmare scenario.

- python bindings: The `cffi` build script is now a little easier to use for
  distributions that want to build the python bindings at the same time as the
  main library. After compiling the library, set the `PATHRS_SRC_ROOT`
  environment variable to the root of the `libpathrs` source directory. This
  will instruct the `cffi` build script (when called from `setup.py` or
  `python3 -m build`) to link against the library built in the source directory
  rather than using system libraries. As long as you install the same library
  later, this should cause no issues.

  Standard wheel builds still work the same way, so users that want to link
  against the system libraries don't need to make any changes.

### Fixed ###
- `Root::mkdir_all` no longer does strict verification that directories created
  by `mkdir_all` "look right" after opening each component. These checks didn't
  protect against any practical attack (since an attacker could just get us to
  use a directory by creating it before `Root::mkdir_all` and we would happily
  use it) and just resulted in spurious errors when dealing with complicated
  filesystem configurations (POSIX ACLs, weird filesystem-specific mount
  options). (#71)

- capi: Passing invalid `pathrs_proc_base_t` values to `pathrs_proc_*` will now
  return an error rather than resulting in Undefined Behaviour™.

## [0.1.0] - 2024-09-14 ##

> 負けたくないことに理由って要る?

### Added ###
- libpathrs now has an official MSRV of 1.63, which is verified by our CI. The
  MSRV was chosen because it's the Rust version in Debian stable and it has
  `io_safety` which is one of the last bits we absolutely need.

- libpathrs now has a "safe procfs resolver" implementation that verifies all
  of our operations on `/proc` are done safely (including using `fsopen(2)` or
  `open_tree(2)` to create a private `/proc` to protect against race attacks).

  This is mainly motivated by issues like [CVE-2019-16884][] and
  [CVE-2019-19921][], where an attacker could configure a malicious mount table
  such that naively doing `/proc` operations could result in security issues.
  While there are limited things you can do in such a scenario, it is far more
  preferable to be able to detect these kinds of attacks and at least error out
  if there is a malicious `/proc`.

  This is based on similar work I did in [filepath-securejoin][].

  - This API is also exposed to users through the Rust and C FFI because this
    is something a fair number of system tools (such as container runtimes)
    need.

- root: new `Root` methods:
  - `readlink` and `resolve_nofollow` to allow users to operate on symlinks
    directly (though it is still unsafe to use the returned path for lookups!).
  - `remove_all` so that Go users can switch from `os.RemoveAll` (though [Go's
    `os.RemoveAll` is safe against races since Go 1.21.11 and Go
    1.22.4][go-52745]).
  - `mkdir_all` so that Go users can switch from `os.MkdirAll`. This is based
    on similar work done in [filepath-securejoin][].

- root: The method for configuring the resolver has changed to be more akin to
  a getter-setter style. This allows for more ergonomic usage (see the
  `RootRef::with_resolver_flags` examples) and also lets us avoid exposing
  internal types needlessly.

  As part of this change, the ability to choose the resolver backend was
  removed (because the C API also no longer supports it). This will probably be
  re-added in the future, but for now it seems best to not add extra APIs that
  aren't necessary until someone asks.

- opath resolver: We now emulate `fs.protected_symlinks` when resolving
  symlinks using the emulated opath resolver. This is only done if
  `fs.protected_symlinks` is enabled on the system (to mirror the behaviour of
  `openat2`).

- tests: Add a large number of integration tests, mainly based on the test
  suite in [filepath-securejoin][]. This test suite tests all of the Rust code
  and the C FFI code from within Rust, giving us ~89% test coverage.

- tests: Add some smoke tests using our bindings to ensure that you can
  actually build with them and run a basic `cat` program. In the future we will
  do proper e2e testing with all of the bindings.

- packaging: Add an autoconf-like `install.sh` script that generates a
  `pkg-config` specification for libpathrs. This should help distributions
  package libpathrs.

[CVE-2019-16884]: https://nvd.nist.gov/vuln/detail/CVE-2019-16884
[CVE-2019-19921]: https://nvd.nist.gov/vuln/detail/CVE-2019-19921
[filepath-securejoin]: https://github.com/cyphar/filepath-securejoin
[go-52745]: https://github.com/golang/go/issues/52745

### Fixed ###
- Handling of `//` and trailing slashes has been fixed to better match what
  users expect and what the kernel does.
- opath resolver: Use reference counting to avoid needlessly cloning files
  internally when doing lookups.
- Remove the `try_clone_hotfix` workaround, since the Rust stdlib patch was
  merged several years ago.
- cffi: Building the C API is now optional, so Rust crates won't contain any of
  the C FFI code and we only build the C FFI crate types manually in the
  makefile. This also lets us remove some dependencies and other annoying
  things in the Rust crate (since those things are only needed for the C API).
- python bindings: Switch to setuptools to allow for a proper Python package
  install. This also includes some reworking of the layout to avoid leaking
  stuff to users that just do `import pathrs`.

### Changed ###
- cffi: Redesign the entire API to be file descriptor based, removing the need
  for complicated freeing logic and matching what most kernel APIs actually
  look like. While there is a risk that users would operate on file descriptors
  themselves, the benefits of a pure-fd-based API outweigh those issues (and
  languages with bindings like Python and Go can easily wrap the file
  descriptor to provide helper methods and avoid this mistake by users).

  Aside from making C users happier, this makes writing bindings much simpler
  because every language has native support for handling the freeing of file
  objects (Go in particular has `*os.File` which would be too difficult to
  emulate outside of the stdlib because of it's unique `Close` handling).

  - Unfortunately, this API change also removed some information from the C API
    because it was too difficult to deal with:
    - Backtraces are no longer provided to the C API. There is no plan to
      re-add them because they complicate the C API a fair bit and it turns out
      that it's basically impossible to graft backtraces to languages that have
      native backtrace support (Go and Python) so providing this information
      has no real benefit to anyone.
    - The configuration API has been removed for now. In the future we will
      probably want to re-add it, but figuring out a nice API for this is left
      for a future (pre-1.0) release. In practice, the default settings are the
      best settings to use for most people anyway.

- bindings: All of the bindings were rewritten to use the new API.

- rust: Rework libpathrs to use the (stabilised in Rust 1.63) `io_safety`
  features. This lets us avoid possible "use after free" issues with file
  descriptors that were closed by accident.

  This required the addition of `HandleRef` and `RootRef` to wrap `BorrowedFd`
  (this is needed for the C API, but is almost certainly useful to other
  folks). Unfortunately we can't implement `Deref` so all of the methods need
  to be duplicated for the new types.

- Split `Root::remove` into `Root::remove_file` (`unlink`) and
  `Root::remove_dir` (`rmdir`) so we don't need to do the retry loop anymore.
  Some users care about what kind of inode they're removing, and if a user
  really wants to nuke a path they would want to use `Root::remove_all` anyway
  because the old `Root::remove` would not remove non-empty directories.

- Switch from `snafu` to `thiserror` for generating our error impls. One upshot
  of this change is that our errors are more opaque to Rust users. However,
  this change resulted in us removing backtraces from our errors (because
  `thiserror` only supports `std::backtrace::Backtrace` which was stabilised
  after our MSRV, and even then it is somewhat limited until some more bits of
  `std::backtrace::Backtrace` are stabilised). We do plan to re-add backtraces
  but they probably aren't strictly *needed* by most library users.

  In the worst case we could write our own handling of backtraces using the
  `backtrace` crate, but I'd like to see a user actually ask for that before
  sitting down to work on it.

## [0.0.2] - 2020-02-15 ##

### Added ###
- bindings: Go bindings (thanks to Maxim Zhiburt for the initial version!).
- bindings: Add support for converting to/from file descriptors.

### Fixed ###
- Update to the newest `openat2` API (which now uses extensible structs).

### Changed ###
- cffi: Make all objects thread-safe so multi-threaded programs don't hit data
  races.
- cffi: Major rework of the CPointer locking design to split the single Mutex
  (used for both the inner type and errors) into two separate locks. As the
  inner value is almost always read, this should massively reduce lock
  contention in multi-threaded programs.
- cffi: `pathrs_from_fd` now clones the passed file descriptor. Some GC'd
  languages are annoying to deal with when a file descriptor's ownership is
  meant to be transferred outside of the program.

## [0.0.1] - 2020-01-05 ##

### Fixed ###
- docs: Fix rustdoc build errors.

## [0.0.0] - 2020-01-05 `[YANKED]` ##

Initial release.

(This release was yanked because the rust docs were broken.)

### Added ###
- Initial implementation of libpathrs, with most of the major functionality
  we need implemented:
  - `Root`:
    - `openat2`- and `O_PATH`-based resolvers.
    - `resolve`
    - `create` and `create_file`
    - `remove`
    - `rename`
  - `Handle`:
    - `reopen`
  - C FFI.
  - Python bindings.

[Unreleased]: https://github.com/openSUSE/libpathrs/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/openSUSE/libpathrs/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/openSUSE/libpathrs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/openSUSE/libpathrs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/openSUSE/libpathrs/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/openSUSE/libpathrs/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/openSUSE/libpathrs/compare/v0.0.0...v0.0.1
[0.0.0]: https://github.com/openSUSE/libpathrs/commits/v0.0.0/

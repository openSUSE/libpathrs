# Changelog #
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] ##

### Fixed ###
- Fixed build failures on s390x with musl libc. The type of `struct statfs`'s
  `f_type` field is not always the same as `rustix::fs::FsWord` (on
  s390x-musl, `f_type` is a `u32` while `FsWord` is a `u64`), so comparing the
  two would not compile. We now always compare filesystem magic numbers as
  `u64`s. (#425)

## [0.2.6] - 2026-09-05 ##

> "If only, if only," the woodpecker sighs,
> "The bark on the tree was as soft as the skies."

### Fixed ###
- The new `--{enable,disable}-*` arguments for `install.sh` to control shared
  library installation were incorrectly called `--disable-dynamic` rather than
  autoconf's `--disable-shared`. We have added new `--{enable,disable}-shared`
  flags and the old ones are kept for compatibility.
- go-pathrs: Fix build failures when building the Go bindings with Clang. CGo's
  handling of numerical C constants is somewhat compiler-dependent and some of
  our sanity checking code would previously fail to compile under `CC=clang`.
  (#401)
- Previously, if a downstream regenerated our `include/pathrs.h` header with
  using `cbindgen >= v0.29.3`, the header would use C23 features that would
  cause go-pathrs to fail to build. We now have worked around the issue for
  go-pathrs but we still have not updated our headers because our Python
  bindings have other issues with the new headers. See the discussion in
  mozilla/cbindgen#1156 for more details.

### Changed ###
- runc closes all open file descriptors before executing user code in order to
  avoid some particularly hairy security bugs. Unfortunately, this also
  invalidates the cached `ProcfsHandle` in libpathrs, which could cause runc to
  later crash if a subsequent procfs operation was attempted (which happened in
  the error path of runc). Most downstream users will never run into this
  issue, but we now handle the problem a bit more gracefully -- if libpathrs
  detects this problematic condition, the cached handle is locked out of use
  and all `ProcfsHandleBuilder::build` invocations will produce a new handle.
  (#413, opencontainers/runc#5438)

## [0.2.5] - 2026-06-17 ##

> Or, to save on postage, I'll just poison him with this!

> [!IMPORTANT]
> Due to the rising tide of supply chain attacks, we have stopped using
> "Trusted" Publishing for our crates.io and PyPi releases. Their
> UIs imply that such releases are "more trusted" but as the recent attacks
> have shown, they actually grant your code forge's *entire infrastructure* the
> right to release things on your behalf.
>
> It would be nice if `crates.io` and PyPI supported a proper signing model
> where developers control their keys, but that is sadly not the case today.
> For PyPI, [detached PGP keys in PyPI are basically security
> theatre][pypi-sigs-2023] and [PEP 480][PEP-480] has stalled; for `crates.io`
> there appears to be *no* mechanism for signing your releases with a key you
> control directly!

[pypi-sigs-2023]: https://blog.yossarian.net/2023/05/21/PGP-signatures-on-PyPI-worse-than-useless
[PEP-480]: https://peps.python.org/pep-0480/

### Breaking ###
* `pathrs_inroot_hardlink` and `pathrs_inroot_symlink` have been switched to
  using the standard argument order from their respective system calls
  (previously the order was swapped, which lead to possible confusion).
  - Previously compiled programs will continue to work (thanks to symbol
    versioning) but rebuilt programs will need to adjust their argument order.
  - Rust users are not affected by this change.
  - For the Go and Python bindings, the wrappers have also had their argument
    orders swapped to match the C API and so will also need to be updated when
    rebuilding. **This is a very important point!** Users must ensure that they
    use pre-`0.2.5` bindings with pre-`0.2.5` libpathrs library installs, and
    post-`0.2.5` bindings with post-`0.2.5` library installs. Mixing and
    matching them will cause bugs (most likely spurious `ENOENT` errors).
  - For the sake of future extensions (and to ease the migration),
    `pathrs_inroot_hardlink` now accepts both an `old_root_fd` and
    `new_root_fd`. At the moment, callers must pass *the same value* to both
    arguments (this means the same numeric file descriptor value, not just a
    reference to the same underlying file).
    - The Go and Python bindings for `pathrs_inroot_hardlink` have not had
      their APIs changed, and so they still only permit operating within a
      single root.
* `pathrs_inroot_rename` also now accepts both an `old_root_fd` and
  `new_root_fd`, with the same caveats as `pathrs_inroot_hardlink` above.
   - The Go and Python bindings for `pathrs_inroot_rename` have not had their
     APIs changed, and so they still only permit operating within a single
     root.
* `RenameFlags` is now backed by a `u64` (instead of `libc::c_uint`) so that we
  can accommodate future extension bits beyond the kernel's current 32-bit ABI.
  Rust callers using `RenameFlags::bits()` or storing the raw value will need
  to adjust their types.
  - As part of this, `pathrs_inroot_rename` now also takes a `uint64_t`, and
    thus the the Go `(*Root).Rename` wrapper takes a `uint64` as well.
- `OpenFlags` is now bkaced by a `u64` (instead of `libc::c_int`), as recent
  kernel changes such as `OPENAT2_REGULAR` will likely start to use some of the
  upper flag bits available from `openat2(2)`. This has an impact on all C APIs
  (and thus Go bindings) that accept `OpenFlags` arguments (we do provide old
  symbol versions to ease the transition):
  - `pathrs_reopen`
  - `pathrs_inroot_open`
  - `pathrs_inroot_creat`
  - `pathrs_proc_open`
  - `pathrs_proc_openat`

### Added ###
- capi: We now have a new `pathrs_version` API that provides runtime version
  information, which loosely matches other libraries like `libseccomp`. The API
  is based on extensible structs, so we can add more information here in the
  future.
- `install.sh` now supports `--disable-static` and `--disable-dynamic` to limit
  what files are installed (their `--enable-*` inverses are also available for
  completeness, but they both are enabled by default).

### Fixed ###
- Containers often have `/proc/sys` overmounted with a read-only mount to avoid
  container escapes, this caused the `O_PATH` resolver to panic because the
  hardened procfs lookup for `/proc/sys/fs/protected_symlinks` would fail. We
  now conservatively assume that `fs.protected_symlinks` is enabled if we
  cannot access the file for any reason.

  This also causes attempts to access `/proc/sys` files using `ProcfsHandle` to
  also fail (by design). In the future we plan to provide some quality-of-life
  improvements to permit access in those cases, but at the moment users need to
  be aware that those kinds of accesses can fail.

- `Root::readlink` and `ProcfsHandle::readlink` would previously return
  `ENOENT` if the target path existed but was not a symlink. This occurred
  because of a peculiar asymmetry in the kernel APIs for `readlinkat(2)`, but
  users found it confusing and so we now remap the error in that case to
  `EINVAL` (as you would get from `readlink(2)` with a path). This will make it
  easier to distinguish the "target path does not exist" and "target path is
  not a symlink" cases.

## [0.2.4] - 2026-03-03 ##

> そう。神を生贄に捧げる！

### Added ###
- New `EXTRA_RUSTC_FLAGS` and `EXTRA_CARGO_FLAGS` variables have been added to
  our `Makefile`, making it easier for packaging tools to adjust builds while
  still using `make release`.
- `install.sh` now accepts `--rust-target` and `--rust-buildmode` as parameters
  to make cross-compilation workflows easier to write (in particular, this is
  needed for runc's release scripts).
- We now produce signed release artefacts for our releases (though currently
  only in the form of signed source and `cargo vendor` tarballs). The accepted
  set of signing keys are available in [`libpathrs.keyring`](./libpathrs.keyring).

### Changed ###
- The `O_PATH` resolver for `procfs` now has an additional bit of hardening
  (each component must be on a procfs -- previously we would check that it is
  on the same mount, which is an even stronger requirement but on older kernels
  it is possible to not have a mount ID to check against).

### Fixed ###
- Previously, `staticlib` builds of libpathrs (i.e., `libpathrs.a`)
  inadvertently included symbol versioned symbols (`@@LIBPATHRS_X.Y`), which
  would cause linker errors when trying to compile programs statically against
  libpathrs.

  This has been resolved, but downstream users who build runc without using
  `make release` will need to take care to ensure they correctly set the
  `LIBPATHRS_CAPI_BUILDMODE` environment variable when building and build
  `libpathrs.a` and `libpathrs.so` in **separate** `cargo build` (or `cargo
  rustc`) invocations. This is mostly necessary due to [the lack of support for
  `#[cfg(crate_type)]`][rust-issue20267].
- `go-pathrs` now correctly builds on 32-bit architectures.
- When doing `procfs` operations, previously libpathrs would internally keep a
  handle to `ProcfsBase` open during the entire operation (due to `Drop`
  semantics in Rust) rather than closing the file descriptor as quickly as
  possible. The file descriptor would be closed soon afterwards (and thus was
  not a leak) but tools that search for file descriptor leaks (such as runc's
  test suite) could incorrectly classify this as a leak. We now close this
  `ProcfsBase` handle far more aggressively.
- RHEL 8 kernels have backports of the fd-based mount API (`fsopen(2)`,
  `open_tree(2)`, et al.) but some `runc` testing found that they have very bad
  (and very difficult to debug) performance issues. Thus, to avoid broken
  backports libpathrs will now explicitly refuse to use the fd-based mount API
  if the reported kernel version is pre-5.2 and will instead fallback to the
  less-secure `open("/proc")`.
- libpathrs [0.2.0][] added some `fdinfo`-based hardening to the procfs
  resolver when `openat2` is not available. Unfortunately, one aspect of this
  hardening had a hard requirement on [a kernel feature only added in Linux
  5.14][kcommit-3845f256a8b52] (namely the `ino` field in `fdinfo`) and thus
  inadvertently increased our minimum kernel version requirement quite
  significantly. This additional hardening is now only treated as mandatory if
  the host kernel version is Linux 5.14 or newer.
- Some of the same `fdinfo`-based hardening had a separate issue when running
  in the context of a non-dumpable process on pre-5.14 kernels -- causing
  spurious `EACCES` errors. We now permit `fdinfo` to be inaccessible in this
  *very specific* situation.

[rust-issue20267]: https://github.com/rust-lang/rust/issues/20267
[kcommit-3845f256a8b52]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3845f256a8b527127bfbd4ced21e93d9e89aa6d7

## [0.2.3] - 2026-01-29 ##

> この閃きを俺は信じる！

### Fixed ###
- While our MSRV is Rust 1.63 (to allow libpathrs to be packaged for Debian
  12), we inadvertently depended on a Rust 1.64 feature in our build scripts
  (`cargo rustc --crate-type`). We have added a temporary workaround for Rust
  1.63, which will be removed after we update our MSRV.
- A bug in our system for generating symbol versions actually resulted in no
  versioned symbols for `libpathrs.so` when compiled with Rust 1.72 or newer.
  This bug has been present since libpathrs 0.2, meaning that this has been
  broken for all versions with versioned symbols. This has been fixed, and now
  our symbols are properly versioned.
  - In addition, building `libpathrs.so` with pre-1.90 Rust was broken because
    of unfortunate interactions with GNU ld and our version scripts. This has
    been resolved, but means that **libpathrs now requires `lld` to compile,
    even on older Rust versions**. Rust 1.90 switched to `lld` by default for
    x86 platforms.

## [0.2.2] - 2025-11-25 ##

> 貴様ら全員刀の錆にしてやるぜ。

### Changed ###
- Add `_test_race` feature to allow you to opt-out of the race tests when
  testing with `cargo test` (which resolves the spurious `EAGAIN` failures you
  get with naive `cargo test` and `cargo nextest` runs, along with making the
  whole test run ~50x faster).

### Fixed ###
- Previously, `cargo test` runs would fail with errors due to the unique
  execution environment that `cargo nextest` provides. We have resolved those
  differences and now have smoke tests in our CI to make sure that a naive
  `cargo test` run will succeed.
- libpathrs will now apply the same `openat2` retry logic for any usage of
  `openat2` (for scoped lookups), to further improve resiliency on busy
  systems.
- Our logic for deciding whether to use `openat2(2)` or fallback to an `O_PATH`
  resolver would cache the result to avoid doing needless test runs of
  `openat2(2)`. However, this causes issues when libpathrs is being used by a
  program that applies new seccomp-bpf filters onto itself -- if the filter
  denies `openat2(2)` then we would return that error rather than falling back
  to the `O_PATH` resolver. To resolve this issue, we have introduced more
  flexible fallback mechanisms and no longer cache the result if `openat2(2)`
  was successful (only if there was an error).

## [0.2.1] - 2025-11-03 ##

> やられたらやり返す。倍返しだ！

### Security ###
- When using `ProcfsHandle::open_follow` on **non**-magic-link symlinks,
  libpathrs could fall victim to an overmount attack because we had incorrectly
  assumed that opening a symlink as a final component would be "atomic" (this
  is only true for magic-links, which was the primary usecase we had in mind
  for this API).

  We now try to use the safe procfs resolver even on symlinks to handle the
  "regular symlink case". Note that (due to a separate bug in
  `ProcfsHandle::open_follow` that has also been fixed), privileged users would
  likely still get an error in this case.

### Added ###
- `Error` and `ErrorKind` now have a `can_retry` helper that can be used to
  make retry loops easier for callers.
- libpathrs now has fairly comprehensive end-to-end tests for all our bindings
  (written in a language-agnostic way), to ensure correctness and uniformty
  when you use libpathrs, no matter which language you use.

### Fixed ###
- python bindings: fix `pathrs.procfs` examples in README.
- go bindings: fix the internal `os.FileMode` to `S_IF*` conversion to not
  auto-include `S_IFREG` for non-`Mknod` operations (previously this would
  cause `MkdirAll` to error out).
- `Root::create_file` now supports `O_TMPFILE`.
- Previously, trying to use `ProcfsHandle::open_follow` with a path whose
  penultimate component was a symlink (i.e.,
  `ProcfsHandle::open_follow(ProcfsBase::ProcRoot, "self/status")`) would
  result in an error due to a mistake in how we handled looking up parent
  directories. This has been fixed, and this will now work the way you expect
  (though you should still use `ProcfsBase::ProcSelf` instead in the above
  example).
- `ProcfsHandle::open_follow` was missing the logic to temporarily allocate a
  non-`subset=pid` if the target does not exit. This ended up accidentally
  mitigating the `ProcfsHandle::open_follow` security issue mentioned above
  (for `fsopen(2)` users trying to open symlinks in `ProcfsBase::ProcRoot` --
  note that only `ProcfsBase::ProcRoot` contains such symlinks in the first
  place).
- Quite a few `Root` operations that required resolving the parent directory of
  the user-provided path could crash if passed `/` or return an unhelpful error
  when passed `.`. We now return a proper error in these cases.

### Changed ###
- The `openat2` resolver will now return `-EAGAIN` if the number of `openat2`
  retries is exceeded -- this allows higher-level users easily detect if an
  error is an indication they should retry (based on their own retry policy).

  In addition, the number of retries done has been bumped from `32` to `128`
  based on some benchmarking which showed that `32` could fail up to 3% of the
  time but `128` would only fail ~0.1% of the time in the worst case scenario
  of an attacker that can saturate all cores with `rename(2)` operations.

  Users that need stronger resiliency guarantees can do their own additional
  retry loop on top of `libpathrs` by checking the return value for `EAGAIN`.
  Please note that we would strongly recommend having some restriction to avoid
  denial-of-service attacks (such as a deadline -- for reference, our testing
  showed that even with >50k trials containing >200k operations a deadline of
  1ms was never exceeded even in the most pessimistic attack scenario).
- The `O_PATH` resolver for `ProcfsHandle` will now return `ELOOP` for
  magic-links that look like `foo:[bar]` in order to better match `openat2(2)`
  (examples include `anon_inode`, `nsfs`, `pipe`, and other such special
  inodes). Previously we would just return `ENOENT`.

## [0.2.0] - 2025-10-17 ##

> You're gonna need a bigger boat.

> [!NOTE]
> As of this release, the libpathrs repository has been moved to
> https://github.com/cyphar/libpathrs. Please update any references you have
> (though GitHub will redirect the old repository name to the new one).
>
> In addition, the `go-pathrs` package has been moved to a vanity URL of
> `cyphar.com/go-pathrs`. Please update your Go import paths accordingly.

> [!IMPORTANT]
> The license of this project has changed. Now, the entire project (including
> all language bindings and examples) is licensed under the terms of the
> Mozilla Public License version 2.0. Additionally, the Rust crate (and
> `cdylib`) may also be used (at your option) under the terms of the GNU Lesser
> General Public License version 3 (or later).
>
> For more information, see [`COPYING.md`](./COPYING.md) and the "License"
> section of the [README](./README.md).
>
> The long-term plan is to restructure the project so that `src/capi` is a
> separate crate that is only licensed as GNU LGPLv3+ and the Rust crate is
> only licensed under as MPLv2, but for technical reasons this is difficult to
> achieve at the moment. The primary purpose for dual-licensing is to try to
> assuage possible concerns around the GNU LGPLv3 requirements to be able to
> "recombine or relink the Application with a modified version of the Linked
> Version to produce a modified Combined Work" in the context of the Rust build
> system, while also allowing us to license the `cdylib` portion under the GNU
> LGPLv3+.

### Breaking ###
- python bindings: `Root.creat` has had its `filemode` and `flags` arguments
  swapped to match the argument order of `openat2` (and `Root.creat_raw`). This
  also now makes `filemode` have a default value of `0o644` if unspecified.
- Most of the C FFI functions have been renamed:
  - Operations on a `Root` have been renamed to have a `pathrs_inroot_` prefix.
  - `pathrs_root_open` has been renamed to `pathrs_open_root`, to avoid
    confusion with `pathrs_inroot_*` functions and clarify what it is opening.
  - However, `libpathrs.so` now uses symbol versioning and so (mostly as a
    proof-of-concept) programs compiled against libpathrs 0.1 will continue to
    function with libpathrs 0.2.
- python bindings: `Root.open` has been changed to be a wrapper of
  `pathrs_inroot_open` instead of being a wrapper around the `Root`
  constructor.
- All C FFI functions that return a file descriptor now set `O_CLOEXEC` by
  default. Previously some functions that took `O_*` flags would only set
  `O_CLOEXEC` if the user explicitly requested it, but `O_CLOEXEC` is easy to
  unset on file descriptors and having it enabled is a more sane default.
- The C API values of the `pathrs_proc_base_t` enum (`PATHRS_PROC_BASE_*`) have
  different values, in order to support `ProcfsBase::ProcPid` passing from C
  callers. Any binaries compiled with the old headers will need to be
  recompiled to avoid spurious behaviour.
  - This required a breaking change in the Go bindings for libpathrs.
    `ProcfsBase` is now an opaque `struct` type rather than a simple `int`
    wrapper -- this was necessary in order to add support for
    `ProcfsBase::ProcPid` in the form of the `ProcBasePid` helper function.
- go bindings: the Go module name for the libpathrs Go bindings has been
  renamed to `cyphar.com/go-pathrs`. This will cause build errors for existing
  users which used the old repository path, but can easily be fixed by updating
  `go.mod` and `go.sum` to use the new name.
- go bindings: the procfs APIs have been moved to a `procfs` subpackage, and
  several of the exported types and functions have changed names. We have not
  provided any compatibility aliases.
- python bindings: the procfs APIs have been moved to a `procfs` submodule. We
  have not provided any compatibility aliases.

### Added ###
- python bindings: add `Root.creat_raw` to create a new file and wrap it in a
  raw `WrappedFd` (os opposed to `Root.creat` which returns an `os.fdopen`).
- Root: it is now possible to open a file in one shot without having to do an
  intermediate `resolve` step with `Root::open_subpath`. This can be more
  efficient in some scenarios (especially with the openat2-based resolver or
  for C FFI users where function calls are expensive) as it saves one file
  descriptor allocation and extra function calls.
- Error: `ErrorKind` is now exported, allowing you to programmatically handle
  errors returned by libpathrs. This interface may change in the future (in
  particular, `ErrorKind::OsError` might change its representation of `errno`
  values).
- capi: errors that are returned by libpathrs itself (such as invalid arguments
  being passed by users) will now contain a `saved_errno` value that makes
  sense for the error type (so `ErrorKind::InvalidArgument` will result in an
  `EINVAL` value for `saved_errno`). This will allow C users to have a nicer
  time handling errors programmatically.
- tests: we now have a large array of tests for verifying that the core lookup
  logic of libpathrs is race-safe against various attacks. This is no big
  surprise, given libpathrs's design, but we now have more extensive tests than
  `github.com/cyphar/filepath-securejoin`.
- procfs: added `ProcfsBase::ProcPid(n)` which is just shorthand when operating
  on a operating on a different process. This is also now supported by the C
  API (by just passing the `pid_t` instead of a special `pathrs_proc_base_t`
  value).
- procfs: we now make use of `/proc/thread-self/fdinfo`'s `mnt_id` field to try
  to thwart bind-mount attacks on systems without `STATX_MNT_ID` support.

  On systems with `openat2(2)`, this protection is effectively just as safe as
  `STATX_MNT_ID` (which lets us lower the minimum recommended kernel version
  from Linux 5.8 to Linux 5.6). For older systems, this protection is not
  perfect, but is designed to be difficult for an attacker to bypass as
  consistently and easily as it would be without these protections.

  Note that it is still the case that post-6.8 kernels (`STATX_MNT_ID_UNIQUE`)
  are still the most strongly recommended kernels to use.
- procfs: `ProcfsHandle` is now `ProcfsHandleRef<'static>`, and it is now
  possible to construct borrowed versions of `ProcfsHandleRef<'fd>` and still
  use them. This is primarily intended for our C API, but Rust users can make
  use of it if you wish. It is possible we will move away from a type alias for
  `ProcfsHandle` in the future.
- capi: All of that `pathrs_proc_*` methods now have a `pathrs_proc_*at`
  variant which allows users to pass a file descriptor to use as the `/proc`
  handle (effectively acting as a C version of `ProcfsHandleRef<'fd>`). Only
  users that operate heavily on global procfs files are expected to make use of
  this API -- the regular API still lets you operate on global procfs files.
  Users can pass `PATHRS_PROC_DEFAULT_ROOTFD` (`-EBADF`) as a file descriptor
  to use the cached API (the old API methods just do this internally).
- procfs: a new `ProcfsHandleBuilder` builder has been added to the API, which
  allows users to construct an unmasked (i.e., no-`subset=pid`) `ProcfsHandle`.

  This should only be used sparingly and with great care to avoid leaks, but it
  allows some programs to amortise the cost of constructing a `procfs` handle
  when doing a series of operations on global procfs files (such as configuring
  a large number of sysctls).

  We plan to add a few more configuration options to `ProcfsHandleBuilder` in
  the future, but `ProcfsHandleBuilder::unmasked` will always give you an
  unmasked version of `/proc` regardless of any new features.
- procfs: `ProcfsHandleRef` can now be converted to `OwnedFd` with
  `.into_owned_fd()` (if it is internally an `OwnedFd`) and borrowed as
  `BorrowedFd` with `AsFd::as_fd`. Users should take great care when using the
  underlying file descriptor directly, as using it opens you up to all of the
  attacks that libpathrs protects you against.
- capi: add `pathrs_procfs_open` method to create a new `ProcfsHandle` with a
  custom configuration (a-la `ProcfsHandleBuilder`). As with
  `ProcfsHandleBuilder`, most users do not need to use this.
  - python bindings: `ProcfsHandle` wraps this new API, and you can construct
    custom `ProcfsHandle`s with `ProcfsHandle.new(...)`.
    `ProcfsHandle.cached()` returns the cached global `ProcfsHandle`. The
    top-level `proc_*` functions (which may be removed in future versions) are
    now just bound methods of `ProcfsHandle.cached()` and have been renamed to
    remove the `proc_` prefix (now that the procfs API lives in a separate
    `pathrs.procfs` module).
  - go bindings: `ProcfsHandle` wraps this new API, and you can construct a
    custom `ProcfsHandle`s with `OpenProcRoot` (calling this with no arguments
    will produce the global cached handle if the handle is being cached). The
    old `Proc*` functions have been removed entirely.
- capi: We now use symbol versioning for `libpathrs.so`, which should avoid
  concerns about future API breakages. I have tested all of the key aspects of
  this new symbol versioning setup and it seems Rust provides everything
  necessary (when testing this last year, I was unable to get
  backward-compatibity working).

### Changed ###
- procfs: the caching strategy for the internal procfs handle has been
  adjusted, and the public `GLOBAL_PROCFS_HANDLE` has been removed.

  The initial plan was to remove caching entirely, as there is a risk of leaked
  long-lived file descriptors leading to attacks like [CVE-2024-21626][].
  However, we found that the performance impact could be quite noticeable
  (`fsconfig(2)` in particular is somewhat heavy in practice if you do it for
  every VFS operation very frequently). (#203)

  The current approach is for `ProcfsHandle::new` to opportunistically cache
  the underlying file descriptor if it is considered relatively safe to cache
  (i.e., it is `subset=pid` and is a detached mount object, which should stop
  host breakouts even if a privileged container attacker snoops on the file
  descriptor). Programs need not be aware of the caching behaviour, though
  programs which need to change security contexts should still use common-sense
  protections like `PR_SET_DUMPABLE`. (#249)
- api: many of the generic type parameters have been replaced with `impl Trait`
  arguments, in order to make using libpathrs a bit more ergonomic. Unless you
  were specifically setting the generic types with `::<>` syntax, this change
  should not affect you.
- syscalls: switch to rustix for most of our syscall wrappers to simplify how
  much code we have for wrapper raw syscalls. This also lets us build on
  musl-based targets because musl doesn't support some of the syscalls we need.

  There are some outstanding issues with rustix that make this switch a little
  uglier than necessary ([rustix#1186][], [rustix#1187][]), but this is a net
  improvement overall.

### Fixes ###
- multiarch: we now build correctly on 32-bit architectures as well as
  architectures that have unsigned char. We also have CI jobs that verify that
  builds work on a fairly large number of architectures (all relevant tier-1
  and tier-2-with-host-tools architectures). If there is an architecture you
  would like us to add to the build matrix and it is well-supported by `rustc`,
  feel free to open an issue or PR!
- `Handle::reopen` will now return an error if you attempt to reopen a handle
  to a symlink (such as one created with `Root::resolve_nofollow`). Previously,
  you would get various errors and unexpected behaviour. If you wish to make an
  `O_PATH|O_NOFOLLOW` copy of a symlink handle, you can simply use `try_clone`
  (i.e. `dup(2)` the file descriptor).
- `Handle::reopen(O_NOFOLLOW)` will now return reasonable results. Previously,
  it would return `-ELOOP` in most cases and in other cases it would return
  unexpected results because the `O_NOFOLLOW` would have an effect on the
  magic-link used internally by `Handle::reopen`.
- `Root::mkdir_all` will no longer return `-EEXIST` if another process tried to
  do `Root::mkdir_all` at the same time, instead the race winner's directory
  will be used by both processes. See [opencontainers/runc#4543][] for more
  details.
- `Root::remove_all` will now handle missing paths that disappear from
  underneath it more gracefully, ensuring that multiple `Root::remove_all`
  operations run on the same directory tree will all succeed without errors.
  The need for this is similar to the need for `Root::mkdir_all` to handle such
  cases.
- opath resolver: in some cases with trailing symlinks in the symlink stack
  (i.e. for partial lookups caused by `Root::mkdir_all`) we would not correctly
  handle leading `..` components, leading to safety errors when libpathrs
  thought that the symlink stack had been corrupted.
- openat2 resolver: always return a hard `SafetyViolation` if we encounter one
  during partial lookups to match the opath resolver behaviour and to avoid
  confusion by users (it is theoretically safe to fall back from a
  `SafetyViolation` during a partial lookup, but it's better to be safe here).
- The error handling for `Root::*` operations that require splitting paths into
  a parent directory and single basename component (such as `Root::create`) has
  now been unified and cases like trailing `/.` and `/..` will now always
  result in `ErrorKind::InvalidArgument`.
- Trailing slash behaviour (i.e. where a user specifies a trailing slash in a
  path passed to libpathrs) throughout libpathrs has been improved to better
  match the kernel APIs (where possible) or otherwise has been made consistent
  and intentional:
  - `Root::create` will always error out with an `InvalidArgument` for the
    target path unless the inode being created is an `InodeType::Directory`, in
    which case the trailing slash will be ignored (to match the behaviour of
    `mkdir(2)` on Linux). Hard links with a trailing slash will also produce an
    error, as hard-links to directories are also forbidden on Unix.
  - `Root::create_file` will always error out with an `InvalidArgument`.
  - `Root::remove_all` and `Root::remove_dir` will ignore trailing slashes,
    while `Root::remove_file` will always fail with `ENOTDIR`. The reason for
    `Root::remove_all` always succeeding is that it matches the behaviour of
    Go's `os.RemoveAll` and `rm -rf`, as well as being impractical for us to
    determine if the target to be deleted is a directory in a race-free way.
  - `Root::rename` matches `renameat2(2)`'s behaviour to the best of our
    ability.
    * Trailing slashes on the source path are only allowed if the source is
      actually a directory (otherwise you get `ENOTDIR`).
    * For `RENAME_EXCHANGE`, the target path may only have trailing slashes if
      it is actually a directory (same as the source path). Otherwise, if the
      *target* path has a trailing slash then the *source* path must be a
      directory (otherwise you get `ENOTDIR`).
- opath resolver: we now return `ELOOP` when we run into a symlink that came
  from mount with the `MS_NOSYMFOLLOW` set, to match the behaviour of `openat2`.
- openat2: we now set `O_NOCTTY` and `O_NOFOLLOW` more aggressively when doing
  `openat2` operations, to avoid theoretical DoS attacks (these were set for
  `openat` but we missed including them for `openat2`).

[CVE-2024-21626]: https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
[rustix#1186]: https://github.com/bytecodealliance/rustix/issues/1186
[rustix#1187]: https://github.com/bytecodealliance/rustix/issues/1187
[opencontainers/runc#4543]: https://github.com/opencontainers/runc/issues/4543

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

[Unreleased]: https://github.com/cyphar/libpathrs/compare/v0.2.6...HEAD
[0.2.6]: https://github.com/cyphar/libpathrs/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/cyphar/libpathrs/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/cyphar/libpathrs/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/cyphar/libpathrs/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/cyphar/libpathrs/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/cyphar/libpathrs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/cyphar/libpathrs/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/cyphar/libpathrs/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cyphar/libpathrs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cyphar/libpathrs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cyphar/libpathrs/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/cyphar/libpathrs/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/cyphar/libpathrs/compare/v0.0.0...v0.0.1
[0.0.0]: https://github.com/cyphar/libpathrs/commits/v0.0.0/

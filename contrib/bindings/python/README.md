## python-pathrs ##

This is a basic Python wrapper around [libpathrs][libpathrs], a safe path
resolution library for Linux. For more details about the security protections
provided by [libpathrs][libpathrs], [see the main README][libpathrs-readme].

In order to use this library, you need to have `libpathrs.so` installed on your
system. Your distribution might already have a libpathrs package. If not, you
can [install libpathrs from source][libpathrs].

### Examples ###

libpathrs allows you to operate on a container root filesystem safely, without
worrying about an attacker swapping components and tricking you into operating
on host files.

```python
import pathrs

# Get a handle to the root filesystem.
with pathrs.Root("/path/to/rootfs") as root:
    # Get an O_PATH handle to a path we want to operate on.
    with root.resolve("/etc/passwd") as passwd:
        # Upgrade the handle to one you can do regular IO on.
        with root.reopen("r") as f:
            for line in f:
                print(line.rstrip("\n"))
```

Aside from just opening files, libpathrs also allows you to do most common
filesystem operations:

```python
import pathrs

# <fcntl.h>
RENAME_EXCHANGE = 0x2

with pathrs.Root("/path/to/rootfs") as root:
    # symlink
    root.symlink("foo", "bar") # foo -> bar
    # link
    root.hardlink("a", "b") # a -> b
    # rename(at2)
    root.rename("foo", "b", flags=RENAME_EXCHANGE) # foo <-> b
    # open(O_CREAT)
    with root.creat("newfile", "w+") as f:
        f.write("Some contents.")
```

It also supports operations like `mkdir -p` and `rm -f`, which are a little
tricky to implement safely.

```python
import pathrs

with pathrs.Root("/path/to/rootfs") as root:
    # rm -r
    root.remove_all("/tmp/foo")
    # mkdir -p
    root.mkdir_all("/tmp/foo/bar/baz/bing/boop", 0o755)
```

In addition, libpathrs provides a safe `procfs` API, to allow for privileged
programs to operate on `/proc` in a way that detects a maliciously-configured
mount table. This is a somewhat esoteric requirement, but privileged processes
that have to operate in untrusted mount namespaces need to handle this
properly or risk serious security issues.

```python
import pathrs

# readlink("/proc/thread-self/fd/0")
stdin_path = pathrs.proc_readlink(pathrs.PROC_THREAD_SELF, "fd/0")

# readlink("/proc/self/exe")
exe_path = pathrs.proc_readlink(pathrs.PROC_SELF, "exe")

# Read data from /proc/cpuinfo.
with pathrs.proc_open(pathrs.PROC_ROOT, "cpuinfo", "r") as cpuinfo:
    for line in cpuinfo:
        print(line.rstrip("\n"))
```

For more information about the libpathrs API and considerations you should have
when using libpathrs, please see [the Rust documentation][libpathrs-rustdoc].

[libpathrs]: https://github.com/openSUSE/libpathrs
[libpathrs-readme]: https://github.com/openSUSE/libpathrs/blob/main/README.md
[libpathrs-rustdoc]: https://docs.rs/pathrs

## `libpathrs` ##

This library implements a set of C-friendly APIs (written in Rust) to make path
resolution within a potentially-untrusted directory safe on GNU/Linux. There
are countless examples of security vulnerabilities caused by bad handling of
paths (symlinks make the issue significantly worse).

I have been working on [kernel patches to make this trivial to do safely][lwn],
but in order to safely use the new kernel API you need to restructure how you
handle paths quite significantly. Since a restructure is necessary anyway,
having a new library is not too much of a downside. In addition, this gives us
the ability to implement the core safety features through userspace emulation
on older kernels.

[lwn]: https://lwn.net/Articles/767547/

### License ###

`libpathrs` is licensed under the GNU LGPLv3 (or any later version).

```
libpathrs: safe path resolution on Linux
Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
Copyright (C) 2019 SUSE LLC

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.
```

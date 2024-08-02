#!/usr/bin/env python3
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

# File: examples/python/static_web.py
#
# An example program which provides a static webserver which will serve files
# from a directory, safely resolving paths with libpathrs.

import os
import sys
import stat
import errno

import flask
import flask.json

sys.path.append(os.path.dirname(__file__) + "/../contrib/bindings/python")
import pathrs

app = flask.Flask(__name__)

def json_dentry(dentry):
	st = dentry.stat(follow_symlinks=False)
	return {
		"ino": st.st_ino,
		"mode": stat.S_IMODE(st.st_mode),
		"type": {
			stat.S_IFREG: "regular file",
			stat.S_IFDIR: "directory",
			stat.S_IFLNK: "symlink",
			stat.S_IFBLK: "block device",
			stat.S_IFCHR: "character device",
			stat.S_IFIFO: "named pipe",
			stat.S_IFSOCK: "socket",
		}.get(stat.S_IFMT(st.st_mode)),
	}

@app.route("/<path:path>")
def get(path):
	try:
		handle = root.resolve(path)
	except pathrs.Error as e:
		e.pprint()
		status_code = {
			# No such file or directory => 404 Not Found.
			errno.ENOENT: 404,
			# Operation not permitted => 403 Forbidden.
			errno.EPERM:  403,
			# Permission denied => 403 Forbidden.
			errno.EACCES: 403,
		}.get(e.errno, 500)
		flask.abort(status_code, "Could not resolve path: %s." % (e,))

	with handle:
		try:
			f = handle.reopen("rb")
			return flask.Response(f, mimetype="application/octet-stream", direct_passthrough=True)
		except IsADirectoryError:
			with handle.reopen_raw(os.O_RDONLY) as dirf:
				with os.scandir(dirf.fileno()) as s:
					return flask.json.jsonify({
						dentry.name: json_dentry(dentry)
						for dentry in s
					})


def main(root_path=None):
	if root_path is None:
		root_path = os.getcwd()

	# Open a root handle. This is long-lived.
	global root
	root = pathrs.Root(root_path)

	# Now serve our dumb HTTP server.
	app.run(debug=True, port=8080)

if __name__ == "__main__":
	main(*sys.argv[1:])

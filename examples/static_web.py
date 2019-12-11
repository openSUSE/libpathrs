#!/usr/bin/python3
# libpathrs: safe path resolution on Linux
# Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
# Copyright (C) 2019 SUSE LLC
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

# File: examples/static_web.py
#
# An example program which provides a static webserver which will serve files
# from a directory, safely resolving paths with libpathrs.

import os
import sys
import errno

import flask
import pathrs

app = flask.Flask(__name__)

@app.route("/<path:path>")
def get(path):
	try:
		handle = root.resolve(path)
	except pathrs.Error as e:
		status_code = {
			# No such file or directory => 404 Not Found.
			errno.ENOENT: 404,
			# Operation not permitted => 403 Forbidden.
			errno.EPERM:  403,
			# Permission denied => 403 Forbidden.
			errno.EACCES: 403,
		}.get(e.errno, 500)
		flask.abort(status_code, "Could not resolve path.")

	f = handle.reopen("rb")
	return flask.Response(f, mimetype="application/octet-stream", direct_passthrough=True)

def main(root_path=None):
	if root_path is None:
		root_path = os.getcwd()

	# Open a root handle. This is long-lived.
	global root
	root = pathrs.Root(root_path)

	# Now server our dumb HTTP server.
	app.run(debug=True, port=8080)

if __name__ == "__main__":
	main(*sys.argv[1:])

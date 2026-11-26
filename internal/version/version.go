// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package version exposes the build version shared by the roughtime binaries.
package version

// Version is the current release of the roughtime module.
const Version = "v1.28.4"

// Commit is the source commit the binary was built from, set via -ldflags -X.
var Commit = ""

// Date is the RFC 3339 timestamp set via -ldflags -X. Make defaults to the
// source commit date.
var Date = ""

// Copyright is the copyright notice displayed by all roughtime binaries.
const Copyright = `Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
is governed by a BSD-style license that can be found in the LICENSE file.`

// Full returns the version string with optional commit and date metadata.
func Full() string {
	out := Version
	if Commit != "" {
		out += " (" + Commit
		if Date != "" {
			out += ", " + Date
		}
		out += ")"
	} else if Date != "" {
		out += " (" + Date + ")"
	}
	return out
}

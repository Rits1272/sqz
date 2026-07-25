// Package web embeds the sqz frontend into the binary, so deployment is a
// single artifact with no static-file path to configure or get wrong.
package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html assets
var files embed.FS

// FS returns the embedded web assets.
func FS() fs.FS { return files }

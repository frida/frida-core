package patterns

import _ "embed"

//go:embed runtime.js
var runtimeSource string

//go:embed target.js
var targetSource string

//go:embed endianness.js
var endiannessSource string

const RuntimeScheme = "frida-patterns://"

var RuntimeModules = map[string]*string{
	"/runtime.js":    &runtimeSource,
	"/target.js":     &targetSource,
	"/endianness.js": &endiannessSource,
}

var constantModules = map[string]string{
	"$target":       "/target.js",
	"$littleEndian": "/endianness.js",
}

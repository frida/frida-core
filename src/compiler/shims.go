package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

var nodeGlobals = `
export { Blob, Buffer } from 'node:buffer';
export { default as process } from 'node:process';
export { ReadableStream } from 'node:stream/web';
export { Response } from '@frida/fetch';
`

const requireWrapper = `
import * as ns from %q;

const exported = ns.default;
if (exported === undefined) {
  module.exports = ns;
} else {
  for (const key of Object.keys(ns)) {
    if (key !== 'default' && !(key in exported))
      exported[key] = ns[key];
  }
  module.exports = exported;
}
`

//go:embed node_modules/@frida/*/package.json
//go:embed node_modules/@frida/*/*.js
//go:embed node_modules/@frida/*/*/*.js
//go:embed node_modules/@frida/*/*/*/*.js
//go:embed node_modules/frida-fs/package.json
//go:embed node_modules/frida-fs/*/*.js
var embeddedShims embed.FS

func makeFridaShimsPlugin() esbuild.Plugin {
	const (
		nsBuiltins = "frida-builtins"
		nsShim     = "frida-shim"
		nsStub     = "frida-stub"
		nsRequire  = "frida-shim-require"
	)

	const (
		builtinFilter        = `^frida-builtins://(.+)$`
		shimFilter           = `^(assert|base64-js|buffer|crypto|depd|diagnostics_channel|events|fs|http|https|http-parser-js|ieee754|net|os|path|process|punycode|querystring|readable-stream|stream|stream/web|string_decoder|timers|tty|url|util|vm|@frida/fetch)$`
		stubFilter           = `^(node:)?(async_hooks|child_process|cluster|constants|dgram|dns|domain|http2|inspector|module|perf_hooks|readline|repl|tls|v8|worker_threads|zlib)$`
		shimNodePrefixFilter = `^node:(assert|buffer|crypto|diagnostics_channel|events|fs|http|https|net|os|path|process|punycode|querystring|stream|stream/web|string_decoder|timers|tty|url|util|vm)$`
	)

	return esbuild.Plugin{
		Name: "frida-custom-shims",
		Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: builtinFilter},
				func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
					return esbuild.OnResolveResult{
						Path:        strings.TrimPrefix(args.Path, "frida-builtins://"),
						Namespace:   nsBuiltins,
						SideEffects: esbuild.SideEffectsFalse,
					}, nil
				})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: nsBuiltins},
				func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
					if args.Path != "/node-globals.js" {
						return esbuild.OnLoadResult{
							Errors: []esbuild.Message{{Text: "Unexpected path: " + args.Path}},
						}, nil
					}
					return esbuild.OnLoadResult{
						Contents: &nodeGlobals,
						Loader:   esbuild.LoaderJS,
					}, nil
				})

			registerShimResolve := func(pattern string) {
				build.OnResolve(esbuild.OnResolveOptions{Filter: pattern},
					func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
						if args.Kind == esbuild.ResolveJSRequireCall {
							return makeResolveResult(nsRequire, args.Path)
						}
						return makeResolveResult(nsShim, args.Path)
					})
			}
			registerShimResolve(shimFilter)
			registerShimResolve(shimNodePrefixFilter)

			build.OnResolve(esbuild.OnResolveOptions{Filter: stubFilter},
				func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
					return esbuild.OnResolveResult{
						Path:        strings.TrimPrefix(args.Path, "node:"),
						Namespace:   nsStub,
						SideEffects: esbuild.SideEffectsFalse,
					}, nil
				})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: nsStub},
				func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
					contents := "module.exports = {};"
					return esbuild.OnLoadResult{
						Contents: &contents,
						Loader:   esbuild.LoaderJS,
					}, nil
				})

			build.OnResolve(esbuild.OnResolveOptions{Filter: ".*", Namespace: nsShim},
				func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
					if strings.HasPrefix(args.Path, ".") {
						abs := filepath.ToSlash(filepath.Join(filepath.Dir(args.Importer), args.Path))
						return esbuild.OnResolveResult{
							Path:        abs,
							Namespace:   nsShim,
							SideEffects: esbuild.SideEffectsFalse,
						}, nil
					}
					return makeResolveResult(nsShim, args.Path)
				})

			build.OnResolve(esbuild.OnResolveOptions{Filter: ".*", Namespace: nsRequire},
				func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
					return esbuild.OnResolveResult{
						Path:        args.Path,
						Namespace:   nsShim,
						SideEffects: esbuild.SideEffectsFalse,
					}, nil
				})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: nsRequire},
				func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
					contents := fmt.Sprintf(requireWrapper, args.Path)
					return esbuild.OnLoadResult{
						Contents: &contents,
						Loader:   esbuild.LoaderJS,
					}, nil
				})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: nsShim},
				func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
					data, err := embeddedShims.ReadFile(filepath.ToSlash(args.Path))
					if err != nil {
						return esbuild.OnLoadResult{
							Errors: []esbuild.Message{{
								Text: fmt.Sprintf("Error reading shim file %q: %v", args.Path, err),
							}},
						}, nil
					}

					content := string(data)
					return esbuild.OnLoadResult{
						Contents: &content,
						Loader:   loaderFor(args.Path),
					}, nil
				})
		},
	}
}

func makeResolveResult(ns string, module string) (esbuild.OnResolveResult, error) {
	path, errs := resolveShim(module)
	if len(errs) > 0 {
		return esbuild.OnResolveResult{Errors: errs}, nil
	}
	return esbuild.OnResolveResult{
		Path:        path,
		Namespace:   ns,
		SideEffects: esbuild.SideEffectsFalse,
	}, nil
}

func loaderFor(path string) esbuild.Loader {
	switch ext := filepath.Ext(path); ext {
	case ".js", ".mjs", ".cjs":
		return esbuild.LoaderJS
	case ".json":
		return esbuild.LoaderJSON
	default:
		panic(fmt.Sprintf("frida-shims: unsupported file type %q", ext))
	}
}

var shimMap = map[string]string{
	"assert":              "@frida/assert",
	"base64-js":           "@frida/base64-js",
	"buffer":              "@frida/buffer",
	"crypto":              "@frida/crypto",
	"depd":                "@frida/depd",
	"diagnostics_channel": "@frida/diagnostics_channel",
	"events":              "@frida/events",
	"fs":                  "frida-fs",
	"http":                "@frida/http",
	"https":               "@frida/https",
	"http-parser-js":      "@frida/http-parser-js",
	"ieee754":             "@frida/ieee754",
	"net":                 "@frida/net",
	"os":                  "@frida/os",
	"path":                "@frida/path",
	"process":             "@frida/process",
	"punycode":            "@frida/punycode",
	"querystring":         "@frida/querystring",
	"readable-stream":     "@frida/readable-stream",
	"stream":              "@frida/stream",
	"stream/web":          "@frida/web-streams",
	"string_decoder":      "@frida/string_decoder",
	"timers":              "@frida/timers",
	"tty":                 "@frida/tty",
	"url":                 "@frida/url",
	"util":                "@frida/util",
	"vm":                  "@frida/vm",
}

type PackageJSON struct {
	Main   string `json:"main"`
	Module string `json:"module"`
}

func resolveShim(shimName string) (string, []esbuild.Message) {
	var subDir string
	if strings.HasPrefix(shimName, "@frida/") {
		subDir = shimName
	} else {
		actualShimName := strings.TrimPrefix(shimName, "node:")

		var ok bool
		subDir, ok = shimMap[actualShimName]
		if !ok {
			return "", []esbuild.Message{{Text: "Unknown shim: " + actualShimName}}
		}
	}

	shimPackageDir := filepath.Join("node_modules", subDir)
	packageJSONPath := filepath.Join(shimPackageDir, "package.json")

	pkgJSONBytes, _ := embeddedShims.ReadFile(filepath.ToSlash(packageJSONPath))

	var pkg PackageJSON
	json.Unmarshal(pkgJSONBytes, &pkg)

	entryFile := ""
	if pkg.Module != "" {
		entryFile = pkg.Module
	} else if pkg.Main != "" {
		entryFile = pkg.Main
	} else {
		entryFile = "index.js"
	}

	resolvedEntryPath := filepath.Join(shimPackageDir, entryFile)

	return filepath.ToSlash(resolvedEntryPath), nil
}

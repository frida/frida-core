package main

import "C"

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

//export frida_compiler_backend_bundle_js
func frida_compiler_backend_bundle_js(cProjectRoot, cEntrypoint *C.char, source_map, compress uint, js_code, error_message **C.char) C.int {
	*js_code = nil
	*error_message = nil

	projectRoot, err := filepath.EvalSymlinks(C.GoString(cProjectRoot))
	if err != nil {
		*error_message = C.CString(fmt.Sprintf("Failed to resolve project root: %w", err))
		return -1
	}
	entrypoint, err := filepath.EvalSymlinks(C.GoString(cEntrypoint))
	if err != nil {
		*error_message = C.CString(fmt.Sprintf("Failed to resolve entrypoint: %w", err))
		return -1
	}

	tsconfigPath := filepath.Join(projectRoot, "tsconfig.json")
	tsconfigData, err := os.ReadFile(tsconfigPath)
	var tsconfigText string
	if err == nil {
		if !utf8.Valid(tsconfigData) {
			*error_message = C.CString(fmt.Sprintf("%q is not valid UTF-8", tsconfigPath))
			return -1
		}
		tsconfigText = string(tsconfigData)
	} else {
		tsconfigText = "{ \"compilerOptions\": { \"target\": \"ES2022\", \"module\": \"Node16\", \"skipLibCheck\": true } }"
	}

	tsCompiler, err := NewTSCompiler(entrypoint, tsconfigPath, tsconfigText, projectRoot)
	if err != nil {
		*error_message = C.CString(fmt.Sprintf("Error initializing TypeScript compiler: %s", err.Error()))
		return -1
	}

	sourcemapOption := esbuild.SourceMapNone
	if source_map != 0 {
		sourcemapOption = esbuild.SourceMapInline
	}

	minifyWhitespace := false
	minifyIdentifiers := false
	minifySyntax := false
	if compress != 0 {
		minifyWhitespace = true
		minifyIdentifiers = true
		minifySyntax = true
	}

	result := esbuild.Build(esbuild.BuildOptions{
		AbsWorkingDir:     projectRoot,
		EntryPoints:       []string{entrypoint},
		Bundle:            true,
		Write:             false,
		Platform:          esbuild.PlatformNeutral,
		Target:            esbuild.ES2022,
		TsconfigRaw:       tsconfigText,
		Sourcemap:         sourcemapOption,
		SourcesContent:    esbuild.SourcesContentExclude,
		MinifyWhitespace:  minifyWhitespace,
		MinifyIdentifiers: minifyIdentifiers,
		MinifySyntax:      minifySyntax,
		Inject:            []string{"frida-builtins:///node-globals.js"},
		Plugins: []esbuild.Plugin{
			makeTypeScriptPlugin(tsCompiler),
			makeFridaShimsPlugin(),
		},
	})

	if len(result.Errors) > 0 {
		var errorMessages []string
		for _, e := range result.Errors {
			errorMessages = append(errorMessages, e.Text)
			if e.Location != nil {
				errorMessages[len(errorMessages)-1] = fmt.Sprintf("%s (%s:%d:%d)", e.Text, e.Location.File, e.Location.Line, e.Location.Column)
			}
		}
		*error_message = C.CString(strings.Join(errorMessages, "\n"))
		return -1
	}

	*js_code = C.CString(string(result.OutputFiles[0].Contents))
	return 0
}

func makeTypeScriptPlugin(compiler *TSCompiler) esbuild.Plugin {
	return esbuild.Plugin{
		Name: "frida-custom-ts",
		Setup: func(build esbuild.PluginBuild) {
			build.OnLoad(esbuild.OnLoadOptions{Filter: "\\.ts$"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				compiledJS, tsDiagnosticStrings, err := compiler.Compile(args.Path)

				var esbuildMessages []esbuild.Message
				for _, dText := range tsDiagnosticStrings {
					// TODO: Parse dText for file, line, col to create richer esbuild.Message.Location
					esbuildMessages = append(esbuildMessages, esbuild.Message{Text: dText})
				}

				if err != nil {
					mainError := esbuild.Message{Text: err.Error()}
					esbuildMessages = append([]esbuild.Message{mainError}, esbuildMessages...)
					return esbuild.OnLoadResult{Errors: esbuildMessages}, nil
				}

				if len(esbuildMessages) > 0 {
					return esbuild.OnLoadResult{Errors: esbuildMessages}, nil
				}

				return esbuild.OnLoadResult{
					Contents: &compiledJS,
					Loader:   esbuild.LoaderJS,
					Errors:   esbuildMessages,
				}, nil
			})
		},
	}
}

var nodeGlobals = `
export { Buffer } from 'node:buffer';
export { default as process } from 'node:process';
`

//go:embed node_modules/@frida/*/package.json
//go:embed node_modules/@frida/*/*.js
//go:embed node_modules/@frida/*/*/*.js
//go:embed node_modules/frida-fs/package.json
//go:embed node_modules/frida-fs/*/*.js
var embeddedShims embed.FS

func makeFridaShimsPlugin() esbuild.Plugin {
	return esbuild.Plugin{
		Name: "frida-custom-shims",
		Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: "^frida-builtins://(.+)$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				return esbuild.OnResolveResult{Path: strings.TrimPrefix(args.Path, "frida-builtins://"), Namespace: "frida-builtins"}, nil
			})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "frida-builtins"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				if args.Path == "/node-globals.js" {
					return esbuild.OnLoadResult{
						Contents: &nodeGlobals,
						Loader:   esbuild.LoaderJS,
					}, nil
				}

				panic("Unexpected frida-builtins:// path: " + args.Path)
			})

			build.OnResolve(esbuild.OnResolveOptions{Filter: "^(assert|base64-js|buffer|crypto|diagnostics_channel|events|fs|http|https|http-parser-js|ieee754|net|os|path|process|punycode|querystring|readable-stream|stream|string_decoder|timers|tty|url|util|vm)$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				path, errs := resolveShim(args.Path)
				if len(errs) > 0 {
					return esbuild.OnResolveResult{Errors: errs}, nil
				}
				return esbuild.OnResolveResult{Path: path, Namespace: "frida-shim"}, nil
			})

			build.OnResolve(esbuild.OnResolveOptions{Filter: "^node:(assert|buffer|crypto|diagnostics_channel|events|fs|http|https|net|os|path|process|punycode|querystring|stream|string_decoder|timers|tty|url|util|vm)$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				path, errs := resolveShim(args.Path)
				if len(errs) > 0 {
					return esbuild.OnResolveResult{Errors: errs}, nil
				}
				return esbuild.OnResolveResult{Path: path, Namespace: "frida-shim"}, nil
			})

			build.OnResolve(esbuild.OnResolveOptions{Filter: ".*", Namespace: "frida-shim"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				req := args.Path
				if strings.HasPrefix(req, ".") {
					resolvedPath := filepath.Join(filepath.Dir(args.Importer), req)
					return esbuild.OnResolveResult{Path: filepath.ToSlash(resolvedPath), Namespace: "frida-shim"}, nil
				}
				path, errs := resolveShim(req)
				if len(errs) > 0 {
					return esbuild.OnResolveResult{Errors: errs}, nil
				}
				return esbuild.OnResolveResult{Path: path, Namespace: "frida-shim"}, nil
			})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "frida-shim"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				data, err := embeddedShims.ReadFile(filepath.ToSlash(args.Path))
				if err != nil {
					return esbuild.OnLoadResult{Errors: []esbuild.Message{{Text: fmt.Sprintf("Error reading shim file '%s': %s", args.Path, err.Error())}}}, nil
				}

				var loader esbuild.Loader
				ext := filepath.Ext(args.Path)
				switch ext {
				case ".js", ".mjs", ".cjs":
					loader = esbuild.LoaderJS
				case ".json":
					loader = esbuild.LoaderJSON
				default:
					return esbuild.OnLoadResult{Errors: []esbuild.Message{{Text: fmt.Sprintf("Unsupported file type '%s' in frida-shim namespace: %s", ext, args.Path)}}}, nil
				}

				content := string(data)
				return esbuild.OnLoadResult{Contents: &content, Loader: loader}, nil
			})
		},
	}
}

var shimMap = map[string]string{
	"assert":              "@frida/assert",
	"base64-js":           "@frida/base64-js",
	"buffer":              "@frida/buffer",
	"crypto":              "@frida/crypto",
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
	actualShimName := strings.TrimPrefix(shimName, "node:")

	subDir, ok := shimMap[actualShimName]
	if !ok {
		return "", []esbuild.Message{{Text: "Unknown shim: " + actualShimName}}
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

func main() {}

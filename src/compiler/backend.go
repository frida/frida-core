package main

/*
typedef void (* FridaDiagnosticFunc) (char * category, int code, char * path, int line, int character, char * text,
    void * user_data);
typedef void (* FridaBundleCompleteFunc) (char * js_code, char * error_message, void * user_data);
typedef void (* FridaDestroyFunc) (void * user_data);

static inline void
invoke_diagnostic_func (FridaDiagnosticFunc fn,
                        char * category,
                        int code,
                        char * path,
                        int line,
                        int character,
                        char * text,
                        void * user_data)
{
  fn (category, code, path, line, character, text, user_data);
}

static inline void
invoke_bundle_complete_func (FridaBundleCompleteFunc fn,
                             char * js_code,
                             char * error_message,
                             void * user_data)
{
  fn (js_code, error_message, user_data);
}

static inline void
invoke_destroy_func (FridaDestroyFunc fn,
                     void * user_data)
{
  fn (user_data);
}
*/
import "C"

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
	"unsafe"

	esbuild "github.com/evanw/esbuild/pkg/api"
	"github.com/frida/typescript-go/scanner"
)

type Diagnostic struct {
	category        string
	code            int
	path            string
	line, character int
	text            string
}

type DiagnosticHandler func(d Diagnostic)

//export frida_compiler_backend_bundle_js
func frida_compiler_backend_bundle_js(cProjectRoot, cEntrypoint *C.char, sourceMap, compress uint,
	onDiagnostic C.FridaDiagnosticFunc, onDiagnosticData unsafe.Pointer, onDiagnosticDestroy C.FridaDestroyFunc,
	onComplete C.FridaBundleCompleteFunc, onCompleteData unsafe.Pointer, onCompleteDestroy C.FridaDestroyFunc) {
	projectRoot := C.GoString(cProjectRoot)
	entrypoint := C.GoString(cEntrypoint)

	go func() {
		var onDiagnostic DiagnosticHandler = func(d Diagnostic) {
			C.invoke_diagnostic_func(onDiagnostic, C.CString(d.category), C.int(d.code), C.CString(d.path), C.int(d.line),
				C.int(d.character), C.CString(d.text), onDiagnosticData)
		}

		jsCode, err := bundleJs(projectRoot, entrypoint, sourceMap != 0, compress != 0, onDiagnostic)

		var cJsCode, cErrorMessage *C.char
		if err == nil {
			cJsCode = C.CString(jsCode)
		} else {
			cErrorMessage = C.CString(err.Error())
		}

		C.invoke_bundle_complete_func(onComplete, cJsCode, cErrorMessage, onCompleteData)

		C.invoke_destroy_func(onDiagnosticDestroy, onDiagnosticData)
		C.invoke_destroy_func(onCompleteDestroy, onCompleteData)
	}()
}

func bundleJs(projectRoot, entrypoint string, sourceMap, compress bool, onDiagnostic DiagnosticHandler) (jsCode string, err error) {
	var e error

	var normalizedProjectRoot, normalizedEntrypoint string
	if normalizedProjectRoot, e = filepath.EvalSymlinks(projectRoot); e != nil {
		err = fmt.Errorf("Failed to resolve project root: %w", e)
		return
	}
	if normalizedEntrypoint, e = filepath.EvalSymlinks(entrypoint); e != nil {
		err = fmt.Errorf("Failed to resolve entrypoint: %w", e)
		return
	}

	tsconfigPath := filepath.Join(normalizedProjectRoot, "tsconfig.json")
	var tsconfigText string
	if tsconfigData, e := os.ReadFile(tsconfigPath); e == nil {
		if !utf8.Valid(tsconfigData) {
			err = fmt.Errorf("%q is not valid UTF-8", tsconfigPath)
			return
		}
		tsconfigText = string(tsconfigData)
	} else {
		tsconfigText = "{ \"compilerOptions\": { \"target\": \"ES2022\", \"module\": \"Node16\", \"skipLibCheck\": true } }"
	}

	var tsCompiler *TSCompiler
	if tsCompiler, e = NewTSCompiler(normalizedEntrypoint, tsconfigPath, tsconfigText, normalizedProjectRoot); e != nil {
		err = fmt.Errorf("Failed to initialize TypeScript compiler: %w", e)
		return
	}

	sourcemapOption := esbuild.SourceMapNone
	if sourceMap {
		sourcemapOption = esbuild.SourceMapInline
	}

	minifyWhitespace := false
	minifyIdentifiers := false
	minifySyntax := false
	if compress {
		minifyWhitespace = true
		minifyIdentifiers = true
		minifySyntax = true
	}

	result := esbuild.Build(esbuild.BuildOptions{
		AbsWorkingDir:     normalizedProjectRoot,
		EntryPoints:       []string{normalizedEntrypoint},
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
		for _, e := range result.Errors {
			emitDiagnostic("error", e, onDiagnostic)
		}
		for _, e := range result.Warnings {
			emitDiagnostic("warning", e, onDiagnostic)
		}
		err = fmt.Errorf("Compilation failed")
		return
	}

	jsCode = string(result.OutputFiles[0].Contents)
	return
}

func emitDiagnostic(category string, message esbuild.Message, onDiagnostic DiagnosticHandler) {
	d := Diagnostic{
		category: category,
		code:     -1,
		text:     message.Text,
	}

	l := message.Location
	if l != nil {
		d.path = l.File
		d.line = l.Line
		d.character = l.Column
	}

	if message.PluginName == "frida-custom-ts" {
		d.category = message.Notes[0].Text
		fmt.Sscan(message.Notes[1].Text, &d.code)
	}

	onDiagnostic(d)
}

func makeTypeScriptPlugin(compiler *TSCompiler) esbuild.Plugin {
	return esbuild.Plugin{
		Name: "frida-custom-ts",
		Setup: func(build esbuild.PluginBuild) {
			build.OnLoad(esbuild.OnLoadOptions{Filter: "\\.ts$"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				compiledJS, tsDiagnostics, err := compiler.Compile(args.Path)

				var esbuildMessages []esbuild.Message
				for _, d := range tsDiagnostics {
					f := d.File()

					pos := d.Pos()
					line, column := scanner.GetLineAndCharacterOfPosition(f, pos)

					esbuildMessages = append(esbuildMessages, esbuild.Message{
						Text: d.Message(),
						Location: &esbuild.Location{
							File:     f.FileName(),
							Line:     line,
							Column:   column,
							Length:   d.Len(),
							LineText: f.Text()[pos:d.End()],
						},
						Notes: []esbuild.Note{
							esbuild.Note{Text: d.Category().Name()},
							esbuild.Note{Text: fmt.Sprintf("%d", d.Code())},
						},
					})
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

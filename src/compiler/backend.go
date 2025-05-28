package main

import "C"

import (
	"fmt"
	"path/filepath"
	"strings"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

//export frida_compiler_backend_bundle_js
func frida_compiler_backend_bundle_js(cProjectRoot, cEntrypoint *C.char, js_code, error_message **C.char) C.int {
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

	tsCompiler, err := NewTSCompiler(entrypoint, tsconfigPath, projectRoot)
	if err != nil {
		*error_message = C.CString(fmt.Sprintf("Error initializing TypeScript compiler: %s", err.Error()))
		return -1
	}

	fridaPlugin := esbuild.Plugin{
		Name: "frida-custom-ts-and-shims",
		Setup: func(build esbuild.PluginBuild) {
			build.OnLoad(esbuild.OnLoadOptions{Filter: "\\.ts$"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				compiledJS, tsDiagnosticStrings, err := tsCompiler.Compile(args.Path)

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

	result := esbuild.Build(esbuild.BuildOptions{
		EntryPoints:   []string{entrypoint},
		Bundle:        true,
		Write:         false,
		Platform:      esbuild.PlatformNode,
		AbsWorkingDir: projectRoot,
		Plugins:       []esbuild.Plugin{fridaPlugin},
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

func main() {}

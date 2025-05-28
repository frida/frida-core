package main

import (
	"context"
	"embed"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/frida/typescript-go/ast"
	"github.com/frida/typescript-go/bundled"
	"github.com/frida/typescript-go/compiler"
	"github.com/frida/typescript-go/tsoptions"
	"github.com/frida/typescript-go/tspath"
	"github.com/frida/typescript-go/vfs"
	"github.com/frida/typescript-go/vfs/iovfs"
	"github.com/frida/typescript-go/vfs/osvfs"
)

//go:embed node_modules/@types/*/package.json
//go:embed node_modules/@types/*/*.d.ts
//go:embed node_modules/@types/*/*/*.d.ts
var embeddedTypes embed.FS

type TSCompiler struct {
	program            *compiler.Program
	fs                 vfs.FS
	captureFs          *captureFS
	defaultLibraryPath string
	cwd                string
	newLine            string
}

func NewTSCompiler(entrypoint, tsconfigFileName, projectRoot string) (*TSCompiler, error) {
	captureFs := newCaptureFS(osvfs.FS())
	fs := newTypesFS(bundled.WrapFS(captureFs), projectRoot)
	basePath := projectRoot
	defaultLibraryPath := bundled.LibPath()

	c := &TSCompiler{
		fs:                 fs,
		captureFs:          captureFs,
		defaultLibraryPath: defaultLibraryPath,
		cwd:                projectRoot,
		newLine:            "\n",
	}

	tsconfigText, ok := c.fs.ReadFile(tsconfigFileName)
	if !ok {
		tsconfigText = "{ \"compilerOptions\": { \"target\": \"ES2022\" \"module\": \"Node16\", \"skipLibCheck\": true } }"
	}

	tsconfigSourceFile := tsoptions.NewTsconfigSourceFileFromFilePath(tsconfigFileName, tspath.ToPath(tsconfigFileName, "", c.fs.UseCaseSensitiveFileNames()), tsconfigText)
	parsedCommandLine := tsoptions.ParseJsonSourceFileConfigFileContent(tsconfigSourceFile, c, basePath, nil, tsconfigFileName, nil, nil, nil)

	if len(parsedCommandLine.Errors) > 0 {
		var errorMessages []string
		for _, diag := range parsedCommandLine.Errors {
			errorMessages = append(errorMessages, diag.Message())
		}
		return nil, fmt.Errorf("failed to parse tsconfig.json at %s: %s", tsconfigFileName, strings.Join(errorMessages, "; "))
	}

	compilerHost := compiler.NewCachedFSCompilerHost(parsedCommandLine.CompilerOptions(), projectRoot, c.fs, c.defaultLibraryPath)

	c.program = compiler.NewProgram(compiler.ProgramOptions{
		RootFiles: []string{entrypoint},
		Host:      compilerHost,
		Options:   parsedCommandLine.CompilerOptions(),
	})

	return c, nil
}

func (c *TSCompiler) Compile(filePathToCompile string) (string, []string, error) {
	program := c.program

	var targetSourceFile *ast.SourceFile
	sourceFiles := program.GetSourceFiles()
	for _, sf := range sourceFiles {
		if sf.FileName() == filePathToCompile {
			targetSourceFile = sf
			break
		}
	}
	if targetSourceFile == nil {
		return "", nil, fmt.Errorf("TypeScript source file not found in program: %s", filePathToCompile)
	}

	c.captureFs.Outputs = make(map[string]string)

	res := program.Emit(compiler.EmitOptions{
		TargetSourceFile: targetSourceFile,
	})

	ctx := context.Background()

	diagnostics := program.GetSyntacticDiagnostics(ctx, targetSourceFile)
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, program.GetBindDiagnostics(ctx, targetSourceFile)...)
	}
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, program.GetOptionsDiagnostics(ctx)...)
	}
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, program.GetGlobalDiagnostics(ctx)...)
	}
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, program.GetSemanticDiagnostics(ctx, targetSourceFile)...)
	}

	var diagnosticMessages []string
	for _, diag := range diagnostics {
		msg := ""
		if diag.File() != nil {
			msg += fmt.Sprintf("%s(%d): ", diag.File().FileName(), diag.Pos())
		}
		msg += diag.Message()
		diagnosticMessages = append(diagnosticMessages, msg)
	}

	if res.EmitSkipped {
		errMsg := "TypeScript compilation failed and was skipped"
		if len(diagnosticMessages) == 0 {
			errMsg = fmt.Sprintf("TypeScript compilation failed and was skipped for %s, but no diagnostics reported", filePathToCompile)
		}
		return "", diagnosticMessages, fmt.Errorf(errMsg)
	}

	var compiledJS string
	var foundJSOutput bool
	for path, content := range c.captureFs.Outputs {
		ext := filepath.Ext(path)
		if ext == ".js" {
			compiledJS = content
			foundJSOutput = true
			break
		}
	}
	if !foundJSOutput {
		if len(diagnosticMessages) == 0 {
			return "", nil, fmt.Errorf("TypeScript compilation for %s seemed to succeed (emit not skipped, no diagnostics) but no .js output file was captured. Captured outputs: %v", filePathToCompile, c.captureFs.Outputs)
		}
		return "", diagnosticMessages, fmt.Errorf("no .js output file was captured for %s. Captured outputs: %v. Diagnostics: %s", filePathToCompile, c.captureFs.Outputs, strings.Join(diagnosticMessages, "; "))
	}

	return compiledJS, diagnosticMessages, nil
}

// FS implements ParseConfigHost.
func (c *TSCompiler) FS() vfs.FS {
	return c.fs
}

// GetCurrentDirectory implements ParseConfigHost.
func (c *TSCompiler) GetCurrentDirectory() string {
	return c.cwd
}

type captureFS struct {
	vfs.FS
	Outputs map[string]string
}

var _ vfs.FS = (*captureFS)(nil)

func newCaptureFS(inner vfs.FS) *captureFS {
	return &captureFS{
		FS:      inner,
		Outputs: make(map[string]string),
	}
}

func (c *captureFS) WriteFile(path string, data string, writeByteOrderMark bool) error {
	c.Outputs[path] = data
	return nil
}

func (c *captureFS) Remove(path string) error {
	delete(c.Outputs, path)
	return nil
}

type typesFS struct {
	vfs.FS
	projectRoot string
	types       vfs.FS
}

var _ vfs.FS = (*typesFS)(nil)

func newTypesFS(inner vfs.FS, projectRoot string) *typesFS {
	return &typesFS{
		FS:          inner,
		projectRoot: projectRoot,
		types:       iovfs.From(embeddedTypes, true),
	}
}

func (t *typesFS) DirectoryExists(path string) bool {
	embeddedPath := t.resolveEmbeddedPath(path)
	if embeddedPath != "" {
		if t.types.DirectoryExists(embeddedPath) {
			return true
		}
	}

	return t.FS.DirectoryExists(path)
}

func (t *typesFS) GetAccessibleEntries(path string) vfs.Entries {
	embeddedPath := t.resolveEmbeddedPath(path)

	var embeddedEntries vfs.Entries
	if embeddedPath != "" {
		embeddedEntries = t.types.GetAccessibleEntries(embeddedPath)
	}

	otherEntries := t.FS.GetAccessibleEntries(path)

	return vfs.Entries{
		Files:       mergeAndSort(embeddedEntries.Files, otherEntries.Files),
		Directories: mergeAndSort(embeddedEntries.Directories, otherEntries.Directories),
	}
}

func (t *typesFS) FileExists(path string) bool {
	embeddedPath := t.resolveEmbeddedPath(path)
	if embeddedPath != "" {
		if t.types.FileExists(embeddedPath) {
			return true
		}
	}

	return t.FS.FileExists(path)
}

func (t *typesFS) ReadFile(path string) (contents string, ok bool) {
	contents, ok = t.FS.ReadFile(path)
	if ok {
		return contents, ok
	}

	embeddedPath := t.resolveEmbeddedPath(path)
	if embeddedPath != "" {
		contents, ok = t.types.ReadFile(embeddedPath)
	}

	return contents, ok
}

func (c *typesFS) resolveEmbeddedPath(path string) string {
	rel, err := filepath.Rel(c.projectRoot, path)
	if err != nil {
		return ""
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return ""
	}

	return "/" + filepath.ToSlash(rel)
}

func mergeAndSort(a, b []string) []string {
	m := make(map[string]struct{}, len(a)+len(b))
	for _, v := range append(a, b...) {
		m[v] = struct{}{}
	}
	return slices.Sorted(maps.Keys(m))
}

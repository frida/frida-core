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
	"sync"
	"time"

	"github.com/frida/typescript-go/pkg/ast"
	"github.com/frida/typescript-go/pkg/bundled"
	"github.com/frida/typescript-go/pkg/compiler"
	"github.com/frida/typescript-go/pkg/core"
	"github.com/frida/typescript-go/pkg/tsoptions"
	"github.com/frida/typescript-go/pkg/tspath"
	"github.com/frida/typescript-go/pkg/vfs"
	"github.com/frida/typescript-go/pkg/vfs/iovfs"
	"github.com/frida/typescript-go/pkg/vfs/osvfs"
)

//go:embed node_modules/@types/*/package.json
//go:embed node_modules/@types/*/*.d.ts
//go:embed node_modules/@types/*/*/*.d.ts
var embeddedTypes embed.FS

type TSCompiler struct {
	projectRoot         string
	entrypoint          string
	loadCompilerOptions LoadCompilerOptionsHandler
	fs                  vfs.FS
	captureFs           *captureFS
	program             *compiler.Program
	mtimes              map[tspath.Path]time.Time
}

type LoadCompilerOptionsHandler func(host tsoptions.ParseConfigHost, fs vfs.FS) (*core.CompilerOptions, error)

func NewTSCompiler(projectRoot, entrypoint string, loadCompilerOptions LoadCompilerOptionsHandler) *TSCompiler {
	captureFs := newCaptureFS(osvfs.FS())
	fs := newTypesFS(bundled.WrapFS(captureFs), projectRoot)

	return &TSCompiler{
		projectRoot:         projectRoot,
		entrypoint:          entrypoint,
		loadCompilerOptions: loadCompilerOptions,
		fs:                  fs,
		captureFs:           captureFs,
	}
}

func (c *TSCompiler) Compile(filePathToCompile string) (string, []*ast.Diagnostic, error) {
	var program *compiler.Program
	var err error
	if c.program != nil {
		program, err = c.updateProgram(c.program)
	} else {
		program, err = c.createProgram()
	}
	c.program = program
	if err != nil {
		return "", nil, err
	}

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

	c.captureFs.ClearOutputs()

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

	if res.EmitSkipped {
		errMsg := "TypeScript compilation failed and was skipped"
		if len(diagnostics) == 0 {
			errMsg = fmt.Sprintf("TypeScript compilation failed and was skipped for %s, but no diagnostics reported", filePathToCompile)
		}
		return "", diagnostics, fmt.Errorf(errMsg)
	}

	var compiledJS string
	var foundJSOutput bool
	for path, content := range c.captureFs.GetOutputs() {
		ext := filepath.Ext(path)
		if ext == ".js" {
			compiledJS = content
			foundJSOutput = true
			break
		}
	}
	if !foundJSOutput {
		if len(diagnostics) == 0 {
			return "", nil, fmt.Errorf("TypeScript compilation for %s seemed to succeed (emit not skipped, no diagnostics) but no .js output file was captured. Captured outputs: %v", filePathToCompile, c.captureFs.GetOutputs())
		}
		return "", diagnostics, fmt.Errorf("No .js output file was captured for %s. Captured outputs: %v", filePathToCompile, c.captureFs.GetOutputs())
	}

	return compiledJS, diagnostics, nil
}

func (c *TSCompiler) createProgram() (*compiler.Program, error) {
	compilerOptions, err := c.loadCompilerOptions(c, c.fs)
	if err != nil {
		fmt.Printf("createProgram() unable to create new program: %w\n", err)
		return nil, err
	}

	host := compiler.NewCompilerHost(compilerOptions, c.projectRoot, c.fs, bundled.LibPath())

	fmt.Printf("createProgram() created new program!\n")

	program := compiler.NewProgram(compiler.ProgramOptions{
		RootFiles: []string{c.entrypoint},
		Host:      host,
		Options:   compilerOptions,
	})

	c.updateMtimes(program)

	return program, nil
}

func (c *TSCompiler) updateProgram(old *compiler.Program) (*compiler.Program, error) {
	newMtimes, err := c.collectMtimes(old)
	if err != nil {
		return c.createProgram()
	}

	newProg := old
	for path, mtime := range newMtimes {
		if !mtime.Equal(c.mtimes[path]) {
			var reused bool
			newProg, reused = newProg.UpdateProgram(path)
			if !reused {
				c.updateMtimes(newProg)
				return newProg, nil
			}
		}
	}
	c.mtimes = newMtimes
	return newProg, nil
}

func (c *TSCompiler) updateMtimes(p *compiler.Program) {
	mt, _ := c.collectMtimes(p)
	c.mtimes = mt
}

func (c *TSCompiler) collectMtimes(p *compiler.Program) (map[tspath.Path]time.Time, error) {
	mt := make(map[tspath.Path]time.Time, len(p.SourceFiles()))

	for _, sf := range p.SourceFiles() {
		name := sf.FileName()
		if isBundled(name) {
			continue
		}
		info := c.fs.Stat(name)
		if info == nil {
			return nil, fmt.Errorf("File %q disappeared", name)
		}
		mt[sf.Path()] = info.ModTime()
	}

	return mt, nil
}

func isBundled(name string) bool {
	return strings.HasPrefix(name, "bundled://")
}

// FS implements ParseConfigHost.
func (c *TSCompiler) FS() vfs.FS {
	return c.fs
}

// GetCurrentDirectory implements ParseConfigHost.
func (c *TSCompiler) GetCurrentDirectory() string {
	return c.projectRoot
}

type captureFS struct {
	vfs.FS
	outputs map[string]string
	mutex   sync.Mutex
}

var _ vfs.FS = (*captureFS)(nil)

func newCaptureFS(inner vfs.FS) *captureFS {
	return &captureFS{
		FS:      inner,
		outputs: make(map[string]string),
	}
}

func (c *captureFS) ClearOutputs() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.outputs = make(map[string]string)
}

func (c *captureFS) GetOutputs() map[string]string {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	snap := make(map[string]string, len(c.outputs))
	for k, v := range c.outputs {
		snap[k] = v
	}
	return snap
}

func (c *captureFS) WriteFile(path string, data string, writeByteOrderMark bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.outputs[path] = data
	return nil
}

func (c *captureFS) Remove(path string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.outputs, path)
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

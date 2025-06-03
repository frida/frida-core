package main

import (
	"context"
	"embed"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
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

	mu                        sync.Mutex
	options                   *core.CompilerOptions
	program                   *compiler.Program
	programErr                error
	forceFreshProgram         bool
	mtimes                    map[tspath.Path]time.Time
	inputDirs, inputFiles     []string
	pendingDirs, pendingFiles []string
}

type LoadCompilerOptionsHandler func(host tsoptions.ParseConfigHost) (*core.CompilerOptions, string, error)

func NewTSCompiler(projectRoot, entrypoint string, loadCompilerOptions LoadCompilerOptionsHandler) *TSCompiler {
	captureFs := newCaptureFS(osvfs.FS())
	fs := newTypesFS(bundled.WrapFS(captureFs), projectRoot)

	return &TSCompiler{
		projectRoot:         projectRoot,
		entrypoint:          tspath.NormalizePath(entrypoint),
		loadCompilerOptions: loadCompilerOptions,
		fs:                  fs,
		captureFs:           captureFs,
	}
}

func (c *TSCompiler) resetProgramState() {
	c.options = nil
	c.program = nil
	c.programErr = nil
	c.forceFreshProgram = false
	c.mtimes = nil
}

func (c *TSCompiler) EnsureProgramUpToDate() error {
	opts, _, err := c.loadCompilerOptions(c)
	if err != nil {
		c.resetProgramState()
		c.recomputeInputs()
		return err
	}

	var prog *compiler.Program
	var progErr error

	if c.forceFreshProgram || c.program == nil || opts != c.options {
		c.forceFreshProgram = false
		prog, progErr = c.createProgram(opts)
	} else {
		prog, progErr = c.updateProgram(c.program, opts)
	}

	c.program = prog
	c.programErr = progErr
	c.options = opts

	c.recomputeInputs()

	return progErr
}

func (c *TSCompiler) createProgram(options *core.CompilerOptions) (*compiler.Program, error) {
	host := compiler.NewCompilerHost(options, c.projectRoot, c.fs, bundled.LibPath())

	program := compiler.NewProgram(compiler.ProgramOptions{
		RootFiles: []string{c.entrypoint},
		Host:      host,
		Options:   options,
	})

	c.updateMtimes(program)

	return program, nil
}

func (c *TSCompiler) updateProgram(old *compiler.Program, options *core.CompilerOptions) (*compiler.Program, error) {
	newMtimes, err := c.collectMtimes(old)
	if err != nil {
		return c.createProgram(options)
	}

	updated := []tspath.Path{}
	newProg := old
	for path, mtime := range newMtimes {
		if !mtime.Equal(c.mtimes[path]) {
			var reused bool
			newProg, reused = newProg.UpdateProgram(path)
			updated = append(updated, path)
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

func (c *TSCompiler) WatchDirs() []string {
	if c.inputDirs != nil {
		return c.inputDirs
	}
	return c.pendingDirs
}

func (c *TSCompiler) WatchFiles() []string {
	if c.inputFiles != nil {
		return c.inputFiles
	}
	return c.pendingFiles
}

func (c *TSCompiler) CommitPendingInputs() {
	c.inputDirs, c.pendingDirs = c.pendingDirs, nil
	c.inputFiles, c.pendingFiles = c.pendingFiles, nil
}

func (c *TSCompiler) DropPendingInputs() {
	c.pendingDirs, c.pendingFiles = nil, nil
}

func (c *TSCompiler) recomputeInputs() {
	var capHint int
	if c.program != nil {
		capHint = 1 + len(c.program.GetSourceFiles())
	} else {
		capHint = 1
	}

	files := make([]string, 0, capHint)
	files = append(files, filepath.Join(c.projectRoot, "tsconfig.json"))
	if c.program != nil {
		for _, sf := range c.program.GetSourceFiles() {
			name := sf.FileName()
			if !isBundled(name) {
				files = append(files, name)
			}
		}
	}
	sort.Strings(files)

	c.pendingDirs = uniqueDirs(files)
	c.pendingFiles = files
}

func (c *TSCompiler) Compile(filePathToCompile string) (string, []*ast.Diagnostic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.programErr != nil {
		return "", nil, c.programErr
	}
	program := c.program

	var targetSourceFile *ast.SourceFile
	normalizedFilePathToCompile := tspath.NormalizePath(filePathToCompile)
	for _, sf := range program.GetSourceFiles() {
		if sf.FileName() == normalizedFilePathToCompile {
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
		semanticDiags := program.GetSemanticDiagnostics(ctx, targetSourceFile)
		for _, d := range semanticDiags {
			switch d.Code() {
			case
				2305, // Module '{0}' has no exported member '{1}'.
				2306, // File '{0}' is not a module.
				2307: // Cannot find module '{0}' or its corresponding type declarations.
				c.forceFreshProgram = true
			}
		}
		diagnostics = append(diagnostics, semanticDiags...)
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

func uniqueDirs(files []string) []string {
	m := make(map[string]struct{}, len(files))
	for _, f := range files {
		m[filepath.Dir(f)] = struct{}{}
	}

	out := make([]string, 0, len(m))
	for d := range m {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
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

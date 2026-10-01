package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	esbuild "github.com/evanw/esbuild/pkg/api"
	"github.com/frida/TypeScript/tsc/pkg/vfs"
	"github.com/frida/frida-core-compiler/patterns"
)

const (
	patternFileFilter    = `\.(hex)?pat$`
	patternRuntimeFilter = `^frida-patterns:///`
	patternNamespace     = "frida-patterns"
)

var patternFilePattern = regexp.MustCompile(patternFileFilter)

func makePatternPlugin(compiler *PatternCompiler) esbuild.Plugin {
	return esbuild.Plugin{
		Name: "frida-patterns",
		Setup: func(build esbuild.PluginBuild) {
			build.OnStart(func() (esbuild.OnStartResult, error) {
				compiler.ForgetReportedFailures()
				return esbuild.OnStartResult{}, nil
			})

			build.OnResolve(esbuild.OnResolveOptions{Filter: patternRuntimeFilter},
				func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
					return esbuild.OnResolveResult{
						Path:        strings.TrimPrefix(args.Path, patterns.RuntimeScheme),
						Namespace:   patternNamespace,
						SideEffects: esbuild.SideEffectsFalse,
					}, nil
				})

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: patternNamespace},
				func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
					contents, isRuntime := patterns.RuntimeModules[args.Path]
					if !isRuntime {
						contents = compiler.unitModule(args.Path)
					}
					return esbuild.OnLoadResult{
						Contents: contents,
						Loader:   esbuild.LoaderJS,
					}, nil
				})

			build.OnLoad(esbuild.OnLoadOptions{Filter: patternFileFilter, Namespace: "file"},
				func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
					result := esbuild.OnLoadResult{WatchFiles: []string{args.Path}}

					compiled, err := compiler.Compile(args.Path)
					if err != nil {
						result.Errors = []esbuild.Message{{Text: err.Error()}}
						return result, nil
					}
					result.WatchFiles = compiled.Files

					if len(compiled.Diagnostics) > 0 {
						result.Errors = compiled.failureMessages()
						compiler.MarkFailureReported(compiled)
						return result, nil
					}

					compiler.registerUnits(compiled)
					result.Contents = &compiled.JavaScript
					result.Loader = esbuild.LoaderJS
					return result, nil
				})
		},
	}
}

func (c *CompiledPattern) failureMessages() []esbuild.Message {
	var messages []esbuild.Message
	for _, d := range c.Diagnostics {
		path := d.Position.Path
		if path == "" {
			path = c.Path
		}
		messages = append(messages, esbuild.Message{
			Text: d.Message,
			Location: &esbuild.Location{
				File:     path,
				Line:     d.Position.Line + 1,
				Column:   d.Position.Character,
				LineText: lineOf(path, d.Position.Line),
			},
		})
	}
	return messages
}

func lineOf(path string, line int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if line >= len(lines) {
		return ""
	}
	return lines[line]
}

type patternDeclarationsFS struct {
	vfs.FS
	compiler *PatternCompiler
}

var _ vfs.FS = (*patternDeclarationsFS)(nil)

func newPatternDeclarationsFS(inner vfs.FS, compiler *PatternCompiler) *patternDeclarationsFS {
	return &patternDeclarationsFS{FS: inner, compiler: compiler}
}

func (p *patternDeclarationsFS) FileExists(path string) bool {
	if compiled := p.declarationsFor(path); compiled != nil {
		return true
	}
	return p.FS.FileExists(path)
}

func (p *patternDeclarationsFS) ReadFile(path string) (string, bool) {
	if compiled := p.declarationsFor(path); compiled != nil {
		return compiled.Declarations, true
	}
	return p.FS.ReadFile(path)
}

func (p *patternDeclarationsFS) Stat(path string) vfs.FileInfo {
	if compiled := p.declarationsFor(path); compiled != nil {
		return generatedFileInfo{name: filepath.Base(path), size: int64(len(compiled.Declarations)), modTime: compiled.ModTime}
	}
	return p.FS.Stat(path)
}

func (p *patternDeclarationsFS) GetAccessibleEntries(path string) vfs.Entries {
	entries := p.FS.GetAccessibleEntries(path)
	present := map[string]bool{}
	for _, file := range entries.Files {
		present[file] = true
	}
	for _, file := range entries.Files {
		if !patternFilePattern.MatchString(file) {
			continue
		}
		declarations := declarationsFileName(file)
		if !present[declarations] {
			entries.Files = append(entries.Files, declarations)
			present[declarations] = true
		}
	}
	return entries
}

func (p *patternDeclarationsFS) declarationsFor(path string) *CompiledPattern {
	patternPath, isDeclarations := patternFileForDeclarations(path)
	if !isDeclarations {
		return nil
	}
	compiled, err := p.compiler.Compile(patternPath)
	if err != nil || compiled.Declarations == "" {
		return nil
	}
	return compiled
}

type generatedFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (i generatedFileInfo) Name() string       { return i.name }
func (i generatedFileInfo) Size() int64        { return i.size }
func (i generatedFileInfo) Mode() fs.FileMode  { return 0644 }
func (i generatedFileInfo) ModTime() time.Time { return i.modTime }
func (i generatedFileInfo) IsDir() bool        { return false }
func (i generatedFileInfo) Sys() any           { return nil }

type PatternCompiler struct {
	mu       sync.Mutex
	entries  map[string]*CompiledPattern
	reported map[*CompiledPattern]bool
	units    map[string]string
}

type CompiledPattern struct {
	Path         string
	Files        []string
	JavaScript   string
	UnitModules  map[string]string
	Declarations string
	Diagnostics  []patterns.Diagnostic
	ModTime      time.Time
	modTimes     map[string]time.Time
}

func NewPatternCompiler() *PatternCompiler {
	return &PatternCompiler{entries: map[string]*CompiledPattern{}, reported: map[*CompiledPattern]bool{}, units: map[string]string{}}
}

func (c *PatternCompiler) ForgetReportedFailures() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reported = map[*CompiledPattern]bool{}
}

func (c *PatternCompiler) unitModule(path string) *string {
	c.mu.Lock()
	defer c.mu.Unlock()
	source := c.units[path]
	return &source
}

func (c *PatternCompiler) Compile(path string) (*CompiledPattern, error) {
	compiled, err := compiledPatterns.compile(path)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[path] = compiled
	return compiled, nil
}

type compiledPatternCache struct {
	mu      sync.Mutex
	entries map[string]*CompiledPattern
}

var compiledPatterns = &compiledPatternCache{entries: map[string]*CompiledPattern{}}

func (p *compiledPatternCache) compile(path string) (*CompiledPattern, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if cached, isCached := p.entries[path]; isCached && cached.isFresh() {
		return cached, nil
	}

	loader := &patternFileLoader{modTimes: map[string]time.Time{}}
	main, err := loader.read(path)
	if err != nil {
		return nil, err
	}

	compiled := &CompiledPattern{Path: path, Files: []string{path}, ModTime: loader.modTimes[path], modTimes: loader.modTimes}
	sourceName := filepath.Base(path)
	module, diagnostics := patterns.CompileSource(main, loader)
	if len(diagnostics) > 0 {
		compiled.Diagnostics = diagnostics
		if previous, wasCompiled := p.entries[path]; wasCompiled {
			compiled.Declarations = previous.Declarations
		}
	} else {
		compiled.Files = module.Files
		modules := patterns.EmitJavaScript(module, sourceName)
		compiled.JavaScript, compiled.UnitModules = modules.Main, modules.Units
		compiled.Declarations = patterns.EmitDeclarations(module, sourceName)
		writeDeclarationsFile(declarationsFileName(path), compiled.Declarations)
	}

	p.entries[path] = compiled
	return compiled, nil
}

func (c *CompiledPattern) isFresh() bool {
	for path, modTime := range c.modTimes {
		info, err := os.Stat(path)
		if err != nil || !info.ModTime().Equal(modTime) {
			return false
		}
	}
	return true
}

type patternFileLoader struct {
	modTimes map[string]time.Time
}

func (l *patternFileLoader) Resolve(importer string, path string) (patterns.Source, error) {
	for _, candidate := range patternFileCandidates(importer, path) {
		if candidate == importer {
			continue
		}
		source, err := l.read(candidate)
		if err == nil {
			return source, nil
		}
	}
	return patterns.Source{}, fmt.Errorf("cannot resolve %s", path)
}

func patternFileCandidates(importer string, path string) []string {
	var candidates []string
	appendIn := func(dir string) {
		base := filepath.Join(dir, filepath.FromSlash(path))
		candidates = append(candidates, base, base+".pat", base+".hexpat")
	}
	dir := filepath.Dir(importer)
	appendIn(dir)
	for {
		appendIn(filepath.Join(dir, "node_modules"))
		parent := filepath.Dir(dir)
		if parent == dir {
			return candidates
		}
		dir = parent
	}
}

func (l *patternFileLoader) read(path string) (patterns.Source, error) {
	info, err := os.Stat(path)
	if err != nil {
		return patterns.Source{}, err
	}
	if info.IsDir() {
		return patterns.Source{}, fmt.Errorf("%s is a directory", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return patterns.Source{}, err
	}
	l.modTimes[path] = info.ModTime()
	return patterns.Source{Path: path, Text: string(data)}, nil
}

func (c *PatternCompiler) MarkFailureReported(compiled *CompiledPattern) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reported[compiled] = true
}

func (c *PatternCompiler) registerUnits(compiled *CompiledPattern) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, source := range compiled.UnitModules {
		c.units[path] = source
	}
}

func (c *PatternCompiler) UnreportedFailureMessages() []esbuild.Message {
	c.mu.Lock()
	defer c.mu.Unlock()

	var messages []esbuild.Message
	for _, compiled := range c.entries {
		if len(compiled.Diagnostics) == 0 || c.reported[compiled] {
			continue
		}
		messages = append(messages, compiled.failureMessages()...)
		c.reported[compiled] = true
	}
	return messages
}

func writeDeclarationsFile(path string, declarations string) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == declarations {
		return
	}
	os.WriteFile(path, []byte(declarations), 0644)
}

func declarationsFileName(patternPath string) string {
	return patternPath + ".d.ts"
}

func patternFileForDeclarations(path string) (string, bool) {
	patternPath, hasSuffix := strings.CutSuffix(path, ".d.ts")
	if !hasSuffix || !patternFilePattern.MatchString(patternPath) {
		return "", false
	}
	return patternPath, true
}

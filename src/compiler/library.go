package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	esbuild "github.com/evanw/esbuild/pkg/api"
	"github.com/frida/TypeScript/tsc/pkg/ast"
	"github.com/frida/TypeScript/tsc/pkg/compiler"
	"github.com/frida/TypeScript/tsc/pkg/core"
	"github.com/frida/TypeScript/tsc/pkg/locale"
	"github.com/frida/TypeScript/tsc/pkg/tsoptions"
	"github.com/frida/TypeScript/tsc/pkg/tspath"
)

type LibraryOptions struct {
	ProjectRoot string
	Entrypoint  string
	OutputDir   string
	SourceMap   bool
}

type libraryBuilder struct {
	projectRoot     string
	outputDir       string
	sourceMap       bool
	configuredRoot  string
	tsCompiler      *TSCompiler
	patternCompiler *PatternCompiler
	patterns        []string
}

type libraryBuild struct {
	*libraryBuilder
	onDiagnostic BuildDiagnosticCallback
	failed       bool
	outputs      map[string]string
}

var errCompilationFailed = errors.New("Compilation failed")

func buildLibrary(options LibraryOptions, onDiagnostic BuildDiagnosticCallback) error {
	builder, err := newLibraryBuilder(options, nil)
	if err != nil {
		return err
	}
	defer builder.tsCompiler.Dispose()
	return builder.build(onDiagnostic)
}

func NewLibraryWatchSession(options LibraryOptions, onDispose SessionDisposeHandler, callbacks BuildEventCallbacks) (*WatchSession, error) {
	return newWatchSession(func(cbs BuildEventCallbacks) (*buildContext, error) {
		return makeLibraryContext(options, cbs)
	}, onDispose, callbacks)
}

func makeLibraryContext(options LibraryOptions, callbacks BuildEventCallbacks) (*buildContext, error) {
	builder, err := newLibraryBuilder(options, callbacks.OnConfigChange)
	if err != nil {
		return nil, err
	}

	ctx, ctxErr := esbuild.Context(esbuild.BuildOptions{
		Outdir:        filepath.FromSlash(builder.projectRoot),
		AbsWorkingDir: filepath.FromSlash(builder.projectRoot),
		EntryPoints:   []string{builder.tsCompiler.entrypoint},
		Write:         false,
		Plugins:       []esbuild.Plugin{makeLibraryPlugin(builder, callbacks)},
	})
	if ctxErr != nil {
		for _, e := range ctxErr.Errors {
			emitDiagnostic("error", e, callbacks.OnDiagnostic)
		}
		return nil, errors.New("Failed to create ESBuild context")
	}
	return &buildContext{ctx, builder.tsCompiler}, nil
}

func makeLibraryPlugin(builder *libraryBuilder, callbacks BuildEventCallbacks) esbuild.Plugin {
	return esbuild.Plugin{
		Name: "frida-library",
		Setup: func(build esbuild.PluginBuild) {
			if callbacks.OnStart != nil {
				build.OnStart(func() (esbuild.OnStartResult, error) {
					callbacks.OnStart()
					return esbuild.OnStartResult{}, nil
				})
			}

			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				err := builder.build(callbacks.OnDiagnostic)
				result := esbuild.OnLoadResult{
					WatchFiles: builder.inputs(),
					WatchDirs:  builder.tsCompiler.WatchDirs(),
				}
				if err != nil && err != errCompilationFailed {
					result.Errors = []esbuild.Message{{Text: err.Error()}}
					return result, nil
				}
				empty := ""
				result.Contents = &empty
				result.Loader = esbuild.LoaderJS
				return result, nil
			})

			build.OnEnd(func(result *esbuild.BuildResult) (esbuild.OnEndResult, error) {
				for _, e := range result.Errors {
					emitDiagnostic("error", e, callbacks.OnDiagnostic)
				}
				if callbacks.OnEnd != nil {
					callbacks.OnEnd()
				}
				return esbuild.OnEndResult{}, nil
			})
		},
	}
}

func newLibraryBuilder(options LibraryOptions, onConfigChange ConfigChangeCallback) (*libraryBuilder, error) {
	projectRoot, err := resolveProjectRoot(options.ProjectRoot)
	if err != nil {
		return nil, err
	}
	entrypoint, err := resolveEntrypoint(projectRoot, options.Entrypoint)
	if err != nil {
		return nil, err
	}
	outputDir := options.OutputDir
	if !filepath.IsAbs(outputDir) {
		outputDir = filepath.Join(projectRoot, outputDir)
	}

	b := &libraryBuilder{
		projectRoot:     tspath.NormalizePath(projectRoot),
		outputDir:       tspath.NormalizePath(outputDir),
		sourceMap:       options.SourceMap,
		patternCompiler: NewPatternCompiler(),
	}
	tsconfigCache := NewTSConfigCache(projectRoot, false, onConfigChange)
	b.tsCompiler = NewTSCompiler(projectRoot, entrypoint, b.patternCompiler, b.loadCompilerOptions(tsconfigCache, entrypoint))
	return b, nil
}

func (b *libraryBuilder) loadCompilerOptions(cache *TSConfigCache, entrypoint string) LoadCompilerOptionsHandler {
	return func(host tsoptions.ParseConfigHost) (*core.CompilerOptions, string, error) {
		configured, text, err := cache.GetCompilerOptions(host)
		if err != nil {
			return nil, "", err
		}
		b.configuredRoot = configured.RootDir
		options := configured.Clone()
		options.Declaration = core.TSTrue
		options.RootDir = b.projectRoot
		options.OutDir = b.outputDir
		options.SourceMap = boolToTristate(b.sourceMap)
		options.InlineSources = boolToTristate(b.sourceMap)
		if strings.HasSuffix(entrypoint, ".js") {
			options.AllowJs = core.TSTrue
		}
		return options, text, nil
	}
}

func (b *libraryBuilder) build(onDiagnostic BuildDiagnosticCallback) error {
	if err := b.tsCompiler.EnsureProgramUpToDate(); err != nil {
		return err
	}
	b.tsCompiler.CommitPendingInputs()
	return (&libraryBuild{libraryBuilder: b, onDiagnostic: onDiagnostic, outputs: map[string]string{}}).run()
}

func (b *libraryBuilder) inputs() []string {
	return append(b.tsCompiler.WatchFiles(), b.patterns...)
}

func (b *libraryBuild) run() error {
	program := b.tsCompiler.program
	sources := b.collectSources(program)
	imported := b.collectPatterns(program)
	for _, message := range b.patternCompiler.UnreportedFailureMessages() {
		b.reportFailure(message)
	}
	b.reportDiagnostics(program, sources)
	if b.failed {
		return errCompilationFailed
	}

	result := program.Emit(context.Background(), compiler.EmitOptions{TargetSourceFiles: sources, WriteFile: b.captureOutput})
	for _, d := range result.Diagnostics {
		b.report(d)
	}
	if b.failed {
		return errCompilationFailed
	}

	return b.write(b.commonRoot(sources), imported)
}

func (b *libraryBuild) collectSources(program *compiler.Program) []*ast.SourceFile {
	var sources []*ast.SourceFile
	for _, file := range program.GetSourceFiles() {
		if file.IsDeclarationFile || !b.owns(file.FileName()) {
			continue
		}
		sources = append(sources, file)
	}
	return sources
}

func (b *libraryBuild) collectPatterns(program *compiler.Program) []string {
	var imported []string
	b.patterns = nil
	seen := map[string]bool{}
	for _, file := range program.GetSourceFiles() {
		path, isPattern := patternFileForDeclarations(file.FileName())
		if !isPattern || !b.owns(path) {
			continue
		}
		imported = append(imported, path)
		compiled, _ := b.patternCompiler.Compile(path)
		for _, dependency := range compiled.Files {
			dependency = tspath.NormalizePath(dependency)
			if b.owns(dependency) && !seen[dependency] {
				seen[dependency] = true
				b.patterns = append(b.patterns, dependency)
			}
		}
	}
	return imported
}

func (b *libraryBuild) owns(path string) bool {
	return strings.HasPrefix(path, b.projectRoot+"/") && !strings.Contains(path, "/node_modules/")
}

func (b *libraryBuild) reportFailure(message esbuild.Message) {
	message.Location.File = b.display(message.Location.File)
	b.failed = true
	emitDiagnostic("error", message, b.onDiagnostic)
}

func (b *libraryBuild) reportDiagnostics(program *compiler.Program, sources []*ast.SourceFile) {
	ctx := context.Background()
	diagnostics := collectDiagnostics(sources, func(file *ast.SourceFile) []*ast.Diagnostic {
		return program.GetSyntacticDiagnostics(ctx, file)
	})
	if len(diagnostics) == 0 {
		diagnostics = collectDiagnostics(sources, func(file *ast.SourceFile) []*ast.Diagnostic {
			return program.GetBindDiagnostics(ctx, file)
		})
	}
	if len(diagnostics) == 0 {
		diagnostics = program.GetProgramDiagnostics()
	}
	if len(diagnostics) == 0 {
		diagnostics = program.GetGlobalDiagnostics(ctx)
	}
	if len(diagnostics) == 0 {
		diagnostics = collectDiagnostics(sources, func(file *ast.SourceFile) []*ast.Diagnostic {
			return program.GetSemanticDiagnostics(ctx, file)
		})
	}
	for _, d := range diagnostics {
		b.report(d)
	}
}

func collectDiagnostics(sources []*ast.SourceFile, query func(file *ast.SourceFile) []*ast.Diagnostic) []*ast.Diagnostic {
	var diagnostics []*ast.Diagnostic
	for _, file := range sources {
		diagnostics = append(diagnostics, query(file)...)
	}
	return diagnostics
}

func (b *libraryBuild) report(d *ast.Diagnostic) {
	diagnostic := Diagnostic{category: d.Category().Name(), code: int(d.Code()), text: d.Localize(locale.Default)}
	if location := diagnosticLocation(d); location != nil {
		diagnostic.path = b.display(location.File)
		diagnostic.line = location.Line
		diagnostic.character = location.Column
	}
	b.failed = true
	b.onDiagnostic(diagnostic)
}

func (b *libraryBuild) display(path string) string {
	rel, _ := filepath.Rel(filepath.FromSlash(b.projectRoot), filepath.FromSlash(path))
	return rel
}

func (b *libraryBuild) captureOutput(fileName string, text string, data *compiler.WriteFileData) error {
	b.outputs[fileName] = text
	return nil
}

func (b *libraryBuild) commonRoot(sources []*ast.SourceFile) string {
	if b.configuredRoot != "" {
		return b.configuredRoot
	}
	var paths []string
	for _, file := range sources {
		paths = append(paths, file.FileName())
	}
	return commonDirectory(append(paths, b.patterns...))
}

func commonDirectory(paths []string) string {
	common := strings.Split(tspath.GetDirectoryPath(paths[0]), "/")
	for _, path := range paths[1:] {
		parts := strings.Split(tspath.GetDirectoryPath(path), "/")
		n := 0
		for n < len(common) && n < len(parts) && common[n] == parts[n] {
			n++
		}
		common = common[:n]
	}
	return strings.Join(common, "/")
}

func (b *libraryBuild) write(root string, imported []string) error {
	for fileName, text := range b.outputs {
		source := b.projectRoot + strings.TrimPrefix(fileName, b.outputDir)
		if err := b.writeFile(root, source, text); err != nil {
			return err
		}
	}
	for _, path := range b.patterns {
		data, err := os.ReadFile(filepath.FromSlash(path))
		if err != nil {
			return err
		}
		if err := b.writeFile(root, path, string(data)); err != nil {
			return err
		}
	}
	for _, path := range imported {
		compiled, _ := b.patternCompiler.Compile(path)
		if err := b.writeFile(root, declarationsFileName(path), compiled.Declarations); err != nil {
			return err
		}
	}
	return nil
}

func (b *libraryBuild) writeFile(root string, source string, text string) error {
	target := filepath.FromSlash(b.outputDir + strings.TrimPrefix(source, root))
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	return os.WriteFile(target, []byte(text), 0644)
}

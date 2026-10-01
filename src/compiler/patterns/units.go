package patterns

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

type Source struct {
	Path string
	Text string
}

type Resolver interface {
	Resolve(importer string, path string) (Source, error)
}

type compilation struct {
	once        sync.Once
	module      *Module
	diagnostics []Diagnostic
}

var compilations = newCache[string, *compilation](16)

func Compile(source string) (*Module, []Diagnostic) {
	c := compilations.obtain(source, func() *compilation { return &compilation{} })
	c.once.Do(func() {
		c.module, c.diagnostics = CompileSource(Source{Text: source}, nil)
	})
	return c.module, c.diagnostics
}

func CompileSource(main Source, resolver Resolver) (*Module, []Diagnostic) {
	loader := &unitLoader{resolver: resolver, loaded: map[string]*File{}, paths: map[*File]string{}, merged: map[string]bool{}}
	loader.load(main, "", nil)
	if len(loader.diagnostics) > 0 {
		return nil, loader.diagnostics
	}
	return analyze(loader.units)
}

type unit struct {
	file  *File
	order ByteOrder
	abi   ABI
}

type unitLoader struct {
	resolver    Resolver
	loaded      map[string]*File
	paths       map[*File]string
	merged      map[string]bool
	units       []*unit
	diagnostics []Diagnostic
}

func (l *unitLoader) load(source Source, alias string, incoming macros) *File {
	key := source.Path + "|" + alias
	if source.Path != "" {
		if loaded, isLoaded := l.loaded[key]; isLoaded {
			return loaded
		}
	}
	file := l.parse(source, alias, incoming)
	if file != nil && source.Path != "" {
		l.loaded[key] = file
		l.paths[file] = source.Path
	}
	return file
}

func (l *unitLoader) parse(source Source, alias string, incoming macros) *File {
	parsed := parseShared(source, incoming, l.resolver)
	l.diagnostics = append(l.diagnostics, parsed.diagnostics...)
	if len(parsed.diagnostics) > 0 {
		return nil
	}
	copied := *parsed.file
	file := &copied

	for _, include := range file.Includes {
		if included := l.loadDependency(source.Path, include.Path, "", include.Position, include.macros); included != nil {
			l.mergeBody(file, included)
		}
	}
	for _, statement := range file.Imports {
		if statement.AsType {
			if imported := l.loadIsolated(source.Path, statement.Path, statement.Alias, statement.Position, statement.macros); imported != nil {
				importedType := &StructDecl{Name: statement.Alias, Global: true, Members: imported.Body, Position: statement.Position}
				file.Declarations = append([]Declaration{importedType}, file.Declarations...)
			}
			continue
		}
		if imported := l.loadDependency(source.Path, statement.Path, statement.Alias, statement.Position, statement.macros); imported != nil {
			l.mergeBody(file, imported)
		}
	}

	if alias != "" {
		aliasFile(file, alias)
	}

	u := &unit{file: file}
	u.order, u.abi = l.applyPragmas(file.Pragmas)
	l.units = append(l.units, u)
	return file
}

func (l *unitLoader) loadIsolated(importer string, path string, namespace string, position Position, incoming macros) *File {
	dependency, err := resolveDependency(importer, path, l.resolver)
	if err != nil {
		l.report(position, err.Error())
		return nil
	}
	file := l.parse(dependency, "", incoming)
	if file == nil {
		return nil
	}
	isolateFile(file, namespace)
	return file
}

func isolateFile(file *File, namespace string) {
	declarations := make([]Declaration, len(file.Declarations))
	for i, decl := range file.Declarations {
		declarations[i] = renamedDeclaration(decl, namespace+"::"+decl.declaredName(), nestScope(namespace, scopeOf(decl)))
	}
	file.Declarations = declarations
	file.Body = rescopedMembers(file.Body, func(scope string) string { return nestScope(namespace, scope) })
}

func nestScope(namespace string, scope string) string {
	if scope == "" {
		return namespace
	}
	return namespace + "::" + scope
}

func (l *unitLoader) mergeBody(into *File, dependency *File) {
	path := l.paths[dependency]
	if l.merged[path] || dependency == into {
		return
	}
	l.merged[path] = true
	into.Body = slices.Concat(dependency.Body, into.Body)
}

func (l *unitLoader) loadDependency(importer string, path string, alias string, position Position, incoming macros) *File {
	dependency, err := resolveDependency(importer, path, l.resolver)
	if err != nil {
		l.report(position, err.Error())
		return nil
	}
	if dependency.Path == standardLibraryPath {
		alias = ""
	}
	return l.load(dependency, alias, incoming)
}

func resolveDependency(importer string, path string, resolver Resolver) (Source, error) {
	if strings.HasPrefix(path, "std/") {
		return Source{Path: standardLibraryPath, Text: standardLibrarySource}, nil
	}
	if resolver == nil {
		return Source{}, errNoResolver
	}
	return resolver.Resolve(importer, path)
}

var errNoResolver = errors.New("includes and imports are only available when compiling a file")

func aliasFile(file *File, alias string) {
	declarations := make([]Declaration, len(file.Declarations))
	for i, decl := range file.Declarations {
		name := decl.declaredName()
		if namespace := autoNamespaceOf(file, name); namespace != "" {
			declarations[i] = renamedDeclaration(decl, alias+name[len(namespace):], renameScope(scopeOf(decl), namespace, alias))
		} else {
			declarations[i] = renamedDeclaration(decl, alias+"::"+name, nestScope(alias, scopeOf(decl)))
		}
	}
	file.Declarations = declarations
	file.Body = rescopedMembers(file.Body, func(scope string) string {
		if namespace := autoNamespaceOf(file, scope); namespace != "" {
			return renameScope(scope, namespace, alias)
		}
		return nestScope(alias, scope)
	})
}

func autoNamespaceOf(file *File, name string) string {
	for _, namespace := range file.AutoNamespaces {
		if name == namespace || strings.HasPrefix(name, namespace+"::") {
			return namespace
		}
	}
	return ""
}

func renameScope(scope string, namespace string, alias string) string {
	if scope == namespace {
		return alias
	}
	return alias + scope[len(namespace):]
}

func (l *unitLoader) applyPragmas(pragmas []Pragma) (ByteOrder, ABI) {
	order := NativeOrder
	abi := PackedABI
	for _, pragma := range pragmas {
		switch pragma.Name {
		case "endian":
			switch pragma.Value {
			case "native":
				order = NativeOrder
			case "little":
				order = LittleEndian
			case "big":
				order = BigEndian
			default:
				l.report(pragma.Position, fmt.Sprintf("unknown endianness %q; expected native, little or big", pragma.Value))
			}
		case "abi":
			switch pragma.Value {
			case "packed":
				abi = PackedABI
			case "native":
				abi = NativeABI
			default:
				l.report(pragma.Position, fmt.Sprintf("unknown ABI %q; expected packed or native", pragma.Value))
			}
		case "bitfield_order":
			if pragma.Value != "right_to_left" {
				l.report(pragma.Position, "only right_to_left bitfield order is supported")
			}
		}
	}
	return order, abi
}

func (l *unitLoader) report(position Position, message string) {
	l.diagnostics = append(l.diagnostics, Diagnostic{Position: position, Message: message})
}

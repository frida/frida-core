package patterns

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type FileResolver struct {
	overrides map[string]string
	stamps    map[string]fileStamp
}

type fileStamp struct {
	override bool
	text     string
	missing  bool
	modTime  time.Time
}

type fileCompilation struct {
	module      *Module
	diagnostics []Diagnostic
	resolver    *FileResolver
}

var fileCompilations = newCache[string, *fileCompilation](16)

func CompileFile(path string, overrides map[string]string, defines map[string]string) (*Module, []Diagnostic, error) {
	key := path + "\x00" + definedMacros(defines).signature()
	if cached, isCached := fileCompilations.get(key); isCached && cached.resolver.Fresh(overrides) {
		return cached.module, cached.diagnostics, nil
	}
	resolver := NewFileResolver(overrides)
	main, err := resolver.Read(path)
	if err != nil {
		return nil, nil, err
	}
	module, diagnostics := compileUnit(main, definedMacros(defines), newUnitRegistry(resolver))
	fileCompilations.put(key, &fileCompilation{module: module, diagnostics: diagnostics, resolver: resolver})
	return module, diagnostics, nil
}

func (r *FileResolver) Fresh(overrides map[string]string) bool {
	for path, stamp := range r.stamps {
		text, isOverridden := overrides[path]
		if stamp.override != isOverridden {
			return false
		}
		if stamp.override {
			if text != stamp.text {
				return false
			}
			continue
		}
		info, err := os.Stat(path)
		if stamp.missing {
			if err == nil {
				return false
			}
			continue
		}
		if err != nil || !info.ModTime().Equal(stamp.modTime) {
			return false
		}
	}
	return true
}

func NewFileResolver(overrides map[string]string) *FileResolver {
	return &FileResolver{overrides: overrides, stamps: map[string]fileStamp{}}
}

func (r *FileResolver) Resolve(importer string, path string) (Source, error) {
	for _, candidate := range fileCandidates(importer, path) {
		if candidate == importer {
			continue
		}
		source, err := r.Read(candidate)
		if err == nil {
			return source, nil
		}
	}
	return Source{}, fmt.Errorf("cannot resolve %s", path)
}

func fileCandidates(importer string, path string) []string {
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

func (r *FileResolver) Read(path string) (Source, error) {
	if text, isOverridden := r.overrides[path]; isOverridden {
		r.stamps[path] = fileStamp{override: true, text: text}
		return Source{Path: path, Text: text}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			r.stamps[path] = fileStamp{missing: true}
		}
		return Source{}, err
	}
	if info.IsDir() {
		return Source{}, fmt.Errorf("%s is a directory", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Source{}, err
	}
	r.stamps[path] = fileStamp{modTime: info.ModTime()}
	return Source{Path: path, Text: string(data)}, nil
}

func (r *FileResolver) ModTime(path string) time.Time {
	return r.stamps[path].modTime
}

package patterns

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type corpusResolver struct {
	root string
}

func (r corpusResolver) Resolve(importer string, path string) (Source, error) {
	for _, dir := range []string{filepath.Dir(importer), filepath.Join(r.root, "includes"), filepath.Join(r.root, "patterns")} {
		for _, candidate := range []string{path, path + ".pat", path + ".hexpat"} {
			full := filepath.Join(dir, candidate)
			if full == importer {
				continue
			}
			if data, err := os.ReadFile(full); err == nil {
				return Source{Path: full, Text: string(data)}, nil
			}
		}
	}
	return Source{}, fmt.Errorf("cannot resolve %s", path)
}

func TestCorpus(t *testing.T) {
	root := os.Getenv("IMHEX_PATTERNS")
	if root == "" {
		t.Skip("IMHEX_PATTERNS is not set")
	}
	var files []string
	filepath.WalkDir(filepath.Join(root, "patterns"), func(path string, entry os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".hexpat") {
			files = append(files, path)
		}
		return nil
	})
	node, _ := exec.LookPath("node")
	scratch := t.TempDir()
	writeModuleLoader(t, scratch)
	histogram := map[string]int{}
	fail := func(file string, message string, detail string) {
		words := strings.Fields(message)
		histogram[strings.Join(words[:min(3, len(words))], " ")]++
		if os.Getenv("IMHEX_PATTERNS_VERBOSE") != "" {
			t.Logf("%s: %s", strings.TrimPrefix(file, root+"/"), detail)
		}
	}
	passed := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		module, diagnostics := CompileSource(Source{Path: file, Text: string(data)}, corpusResolver{root})
		if len(diagnostics) > 0 {
			fail(file, diagnostics[0].Message, diagnostics[0].Error())
			continue
		}
		sourceName := filepath.Base(file)
		EmitDeclarations(module, sourceName)
		javaScript := EmitJavaScript(module, sourceName)
		if node != "" {
			if problem := loadProblem(node, scratch, javaScript); problem != "" {
				fail(file, problem, problem)
				continue
			}
		}
		passed++
	}
	type entry struct {
		key   string
		count int
	}
	var entries []entry
	for key, count := range histogram {
		entries = append(entries, entry{key, count})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].count > entries[j].count })
	t.Logf("%d of %d patterns compile", passed, len(files))
	for _, e := range entries[:min(40, len(entries))] {
		t.Logf("%4d  %s", e.count, e.key)
	}
}

func writeModuleLoader(t *testing.T, dir string) {
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	loader := `
import { install } from "./gum-shim.mjs";
install();
await import("./module.mjs");
`
	for name, contents := range map[string]string{"gum-shim.mjs": string(shim), "load.mjs": loader} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)
}

func loadProblem(node string, scratch string, javaScript string) string {
	if err := os.WriteFile(filepath.Join(scratch, "module.mjs"), []byte(nodeSource(javaScript)), 0644); err != nil {
		return err.Error()
	}
	output, err := exec.Command(node, filepath.Join(scratch, "load.mjs")).CombinedOutput()
	if err == nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Error") {
			return line
		}
	}
	return err.Error()
}

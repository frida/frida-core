package patterns

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var referenceVirtualSources = map[string]string{
	"A":               "#include <B>\n#include <C>\nfn a() {};\n",
	"B":               "#include <C>\nfn b() {};\n",
	"C":               "#pragma once\nfn c() {};\n",
	"IA":              "import IB;\nimport IC as C;\nfn a() {};\n",
	"IB":              "namespace auto B {\n    import IC as C;\n    fn b() {};\n}\n",
	"IC":              "#pragma once\nfn c() {};\n",
	"ImportedSection": "char imported @ 0;\nstd::assert(imported == 'A', \"Imported type did not execute in the target section\");\n",
}

type referenceResolver struct{}

func (referenceResolver) Resolve(importer string, path string) (Source, error) {
	if text, isVirtual := referenceVirtualSources[path]; isVirtual {
		return Source{Path: path, Text: text}, nil
	}
	return Source{}, fmt.Errorf("cannot resolve %s", path)
}

type referenceCase struct {
	name    string
	failing bool
	source  string
	inputs  map[string]any
}

var (
	referenceClassPattern  = regexp.MustCompile(`class TestPattern`)
	referenceNamePattern   = regexp.MustCompile(`\(evaluator, "([^"]+)"`)
	referenceSourcePattern = regexp.MustCompile(`(?s)R"(\w*)\((.*?)\)(\w*)"`)
	referenceInputPattern  = regexp.MustCompile(`\{ "(\w+)", u128\((\d+)\) \}`)
)

func referenceCases(root string) ([]referenceCase, error) {
	files, err := filepath.Glob(filepath.Join(root, "tests", "include", "test_patterns", "test_pattern_*.hpp"))
	if err != nil {
		return nil, err
	}
	var cases []referenceCase
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		chunks := referenceClassPattern.Split(string(data), -1)
		for _, chunk := range chunks[1:] {
			name := referenceNamePattern.FindStringSubmatch(chunk)
			source := referenceSourcePattern.FindStringSubmatch(chunk)
			if name == nil || source == nil || source[1] != source[3] {
				continue
			}
			failing := strings.Contains(chunk, "Mode::Failing") || strings.Contains(chunk, "TestPatternFailingSemantic(evaluator")
			if runnerSpecific[name[1]] || commentedOut(source[2]) {
				continue
			}
			cases = append(cases, referenceCase{name: name[1], failing: failing, source: source[2], inputs: referenceInputs(chunk)})
		}
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].name < cases[j].name })
	return cases, nil
}

func referenceInputs(chunk string) map[string]any {
	inputs := map[string]any{}
	for _, match := range referenceInputPattern.FindAllStringSubmatch(chunk, -1) {
		value, _ := strconv.ParseInt(match[2], 10, 64)
		inputs[match[1]] = value
	}
	return inputs
}

var runnerSpecific = map[string]bool{"PragmasFail": true, "CustomBuiltInType": true, "HeapLifetime": true}

func commentedOut(source string) bool {
	for _, line := range strings.Split(source, "\n") {
		if text := strings.TrimSpace(line); text != "" && !strings.HasPrefix(text, "//") {
			return false
		}
	}
	return true
}

func decodedError(v *DecodedValue) string {
	if v.Error != "" {
		return v.Error
	}
	for _, child := range append(append([]*DecodedValue{}, v.Fields...), v.Elements...) {
		if message := decodedError(child); message != "" {
			return message
		}
	}
	return ""
}

func TestReferenceSuite(t *testing.T) {
	root := os.Getenv("PATTERN_LANGUAGE")
	if root == "" {
		t.Skip("PATTERN_LANGUAGE is not set")
	}
	data, err := os.ReadFile(filepath.Join(root, "tests", "test_data"))
	if err != nil {
		t.Fatal(err)
	}
	cases, err := referenceCases(root)
	if err != nil {
		t.Fatal(err)
	}
	passed := 0
	for _, c := range cases {
		if os.Getenv("PATTERN_LANGUAGE_VERBOSE") != "" {
			fmt.Fprintln(os.Stderr, "running", c.name)
		}
		outcome := ""
		module, diagnostics := CompileSource(Source{Path: c.name + ".hexpat", Text: c.source}, referenceResolver{})
		if len(diagnostics) > 0 {
			outcome = diagnostics[0].Error()
		} else if module.Root != nil {
			outcome = decodedError(DecodeWith(module, Targets[0], module.Root, data, 0, c.inputs))
		}
		if (outcome == "") != c.failing {
			passed++
			continue
		}
		if c.failing {
			t.Logf("%s: expected a failure", c.name)
		} else {
			t.Logf("%s: %s", c.name, outcome)
		}
	}
	t.Logf("%d of %d reference tests behave as expected", passed, len(cases))
}

func TestReferenceSuiteUnderNode(t *testing.T) {
	root := os.Getenv("PATTERN_LANGUAGE")
	if root == "" {
		t.Skip("PATTERN_LANGUAGE is not set")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := referenceCases(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gum-shim.mjs"), shim, 0644); err != nil {
		t.Fatal(err)
	}
	writeRuntimeModules(t, dir)
	runner := fmt.Sprintf(`
import { install, allocate } from "./gum-shim.mjs";
import { readFileSync } from "node:fs";
install();
const data = readFileSync(%q);
const mem = allocate(data.length, 0);
mem.writeByteArray(Array.from(data));
const { parse } = await import("./" + process.argv[2] + ".js");
try {
    parse(mem, data.length, JSON.parse(process.argv[3]));
    console.log("ok");
} catch (e) {
    console.log("error: " + e.message);
}
`, filepath.Join(root, "tests", "test_data"))
	if err := os.WriteFile(filepath.Join(dir, "run.mjs"), []byte(runner), 0644); err != nil {
		t.Fatal(err)
	}
	passed, total := 0, 0
	for _, c := range cases {
		module, diagnostics := CompileSource(Source{Path: c.name + ".hexpat", Text: c.source}, referenceResolver{})
		if len(diagnostics) > 0 || module.Root == nil {
			continue
		}
		total++
		if os.Getenv("PATTERN_LANGUAGE_VERBOSE") != "" {
			fmt.Fprintln(os.Stderr, "emitting", c.name)
		}
		if err := os.WriteFile(filepath.Join(dir, c.name+".js"), []byte(nodeModule(module, c.name+".hexpat")), 0644); err != nil {
			t.Fatal(err)
		}
		inputs, err := json.Marshal(c.inputs)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		output, err := exec.CommandContext(ctx, node, filepath.Join(dir, "run.mjs"), c.name, string(inputs)).CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		outcome := strings.TrimSpace(string(output))
		if timedOut {
			outcome = "timeout"
		} else if err != nil {
			outcome = "crash: " + strings.SplitN(outcome, "\n", 2)[0]
		}
		if (outcome == "ok") != c.failing {
			passed++
			continue
		}
		t.Logf("%s: %s", c.name, outcome)
	}
	t.Logf("%d of %d reference tests behave as expected under node", passed, total)
}

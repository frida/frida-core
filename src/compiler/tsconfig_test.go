package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/frida/TypeScript/tsc/pkg/vfs"
	"github.com/frida/TypeScript/tsc/pkg/vfs/osvfs"
)

type testParseConfigHost struct {
	fs  vfs.FS
	cwd string
}

func (h testParseConfigHost) FS() vfs.FS {
	return h.fs
}

func (h testParseConfigHost) GetCurrentDirectory() string {
	return h.cwd
}

func TestTSConfigCacheSerializesPaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "tsconfig.json"), `{
  "compilerOptions": {
    "target": "ES2022",
    "paths": {
      "@agent/*": ["./agent/*"]
    }
  }
}
`)

	cache := NewTSConfigCache(dir, false, nil)
	opts, text, err := cache.GetCompilerOptions(testParseConfigHost{fs: osvfs.FS(), cwd: dir})
	if err != nil {
		t.Fatalf("GetCompilerOptions failed: %v", err)
	}

	if opts.Paths == nil || opts.Paths.Size() == 0 {
		t.Fatal("Parsed options lost their path aliases")
	}

	var serialized struct {
		CompilerOptions struct {
			Paths map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if err := json.Unmarshal([]byte(text), &serialized); err != nil {
		t.Fatalf("Serialized tsconfig is not valid JSON: %v", err)
	}
	substitutions, ok := serialized.CompilerOptions.Paths["@agent/*"]
	if !ok {
		t.Fatalf("Serialized tsconfig lost the path aliases: %s", text)
	}
	if len(substitutions) != 1 || substitutions[0] != "./agent/*" {
		t.Fatalf("Serialized tsconfig mangled the path aliases: %v", substitutions)
	}
}

func TestCompilerResolvesPathAliases(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "tsconfig.json"), `{
  "compilerOptions": {
    "target": "ES2022",
    "paths": {
      "@agent/*": ["./agent/*"]
    }
  },
  "include": ["agent/**/*.ts"]
}
`)
	writeFile(t, filepath.Join(dir, "agent", "logger.ts"), `
export function log(text: string): void {
    console.log(text);
}
`)
	writeFile(t, filepath.Join(dir, "agent", "index.ts"), `
import { log } from "@agent/logger.js";

log("hello");
`)

	var diagnostics []Diagnostic
	_, err := build(BuildOptions{
		ProjectRoot:  dir,
		Entrypoint:   "agent/index.ts",
		OutputFormat: OutputFormatUnescaped,
		BundleFormat: BundleFormatESM,
	}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err != nil {
		t.Fatalf("Build failed: %v\n%+v", err, diagnostics)
	}
}

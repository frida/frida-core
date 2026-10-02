package main

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/frida/frida-core-compiler/patterns"
)

type patternQuery struct {
	projectRoot string
	entrypoint  string
	platform    string
	arch        string
}

type patternCompilation struct {
	module      *patterns.Module
	diagnostics []patterns.Diagnostic
	target      patterns.Target
	projectRoot string
}

func describePatterns(query patternQuery) (string, error) {
	c, err := query.compile()
	if err != nil {
		return "", err
	}
	return patterns.DescribeModule(c.module, c.diagnostics, c.target, c.display), nil
}

func decodePattern(query patternQuery, typeName string, data []byte, address uint64, inputs map[string]any) (string, error) {
	c, err := query.compile()
	if err != nil {
		return "", err
	}
	result, err := patterns.DecodeType(c.module, c.diagnostics, typeName, data, address, c.target, inputs)
	return result, c.displayError(err)
}

func callPatternFunction(query patternQuery, typeName string, data []byte, address uint64, inputs map[string]any, patternID int,
	functionName string) (string, error) {
	c, err := query.compile()
	if err != nil {
		return "", err
	}
	result, err := patterns.CallTypeFunction(c.module, c.diagnostics, typeName, data, address, c.target, inputs, patternID, functionName)
	return result, c.displayError(err)
}

func (q patternQuery) compile() (*patternCompilation, error) {
	projectRoot, err := resolveProjectRoot(q.projectRoot)
	if err != nil {
		return nil, err
	}

	entrypoint := q.entrypoint
	if !filepath.IsAbs(entrypoint) {
		entrypoint = filepath.Join(projectRoot, entrypoint)
	}
	if entrypoint, err = filepath.EvalSymlinks(entrypoint); err != nil {
		return nil, fmt.Errorf("Failed to resolve entrypoint: %w", err)
	}

	module, diagnostics, err := patterns.CompileFile(entrypoint, nil)
	if err != nil {
		return nil, err
	}
	return &patternCompilation{module: module, diagnostics: diagnostics, target: targetFor(q.platform, q.arch), projectRoot: projectRoot}, nil
}

func targetFor(platform string, arch string) patterns.Target {
	if platform == "" {
		platform = hostPlatform()
	}
	if arch == "" {
		arch = hostArch()
	}
	switch arch {
	case "x64", "arm64":
		return patterns.Targets[0]
	case "ia32":
		if platform == "windows" {
			return patterns.Targets[1]
		}
		return patterns.Targets[2]
	}
	return patterns.Targets[1]
}

func hostPlatform() string {
	switch runtime.GOOS {
	case "ios":
		return "darwin"
	}
	return runtime.GOOS
}

func hostArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	}
	return runtime.GOARCH
}

func (c *patternCompilation) display(path string) string {
	if !filepath.IsAbs(path) {
		return path
	}
	rel, _ := filepath.Rel(c.projectRoot, path)
	return rel
}

func (c *patternCompilation) displayError(err error) error {
	if diagnostic, isDiagnostic := err.(patterns.Diagnostic); isDiagnostic {
		diagnostic.Position.Path = c.display(diagnostic.Position.Path)
		return diagnostic
	}
	return err
}

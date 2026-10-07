package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodePatternWithDefines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "layout.hexpat"), "#ifdef WIDE\nstruct Layout { u16 value; };\n#else\nstruct Layout { u8 value; };\n#endif\n")
	query := patternQuery{projectRoot: dir, entrypoint: "layout.hexpat", defines: map[string]any{"WIDE": ""}}
	result, err := decodePattern(query, "Layout", []byte{1, 2}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"size":2`) {
		t.Fatalf("the define should select the wide branch: %s", result)
	}
}

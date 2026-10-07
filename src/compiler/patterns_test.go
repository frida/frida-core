package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vec3Pattern = `
struct Vec3 {
	float x;
	float y;
	float z;
};
`

const playerPattern = `
#pragma abi native

struct Player {
	u32 hitpoints;
	u16 armor;
	Vec3 position;
	Player *next;
};
`

func TestBuildAgentWithPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "player.pat"), vec3Pattern+playerPattern)
	writeFile(t, filepath.Join(dir, "agent.ts"), `
import { Player } from "./player.pat";

const player = Player.at(Process.mainModule.base);
const hitpoints: number = player.hitpoints;
console.log(hitpoints, player.position.x, player.next);
`)

	var diagnostics []Diagnostic
	bundle, err := build(BuildOptions{ProjectRoot: dir, Entrypoint: "agent.ts"}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err != nil {
		t.Fatalf("build failed: %v\n%+v", err, diagnostics)
	}
	for _, expected := range []string{"Player", "hitpoints", "readU32()"} {
		if !strings.Contains(bundle, expected) {
			t.Errorf("bundle lacks %q:\n%s", expected, bundle)
		}
	}

	declarations, err := os.ReadFile(filepath.Join(dir, "player.pat.d.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(declarations), "export declare class Player") {
		t.Errorf("unexpected declarations:\n%s", declarations)
	}
}

func TestBuildReportsPatternErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "broken.pat"), "struct A {\n\tu32 a;\n\tauto b @ 4;\n};\n")
	writeFile(t, filepath.Join(dir, "agent.ts"), `import { A } from "./broken.pat";
console.log(A.size);
`)

	var diagnostics []Diagnostic
	_, err := build(BuildOptions{ProjectRoot: dir, Entrypoint: "agent.ts"}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err == nil {
		t.Fatal("expected the build to fail")
	}
	found := false
	for _, d := range diagnostics {
		if strings.Contains(d.text, "auto is not supported") && strings.HasSuffix(d.path, "broken.pat") && d.line == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func writeFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAgentWithImportedPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "node_modules", "geometry-types", "geometry.pat"), `
namespace auto geometry {
	struct Vec2 { float x; float y; };
};
`)
	writeFile(t, filepath.Join(dir, "colors.pat"), "enum Color : u8 { Red, Green };\n")
	writeFile(t, filepath.Join(dir, "sprite.pat"), `
#include "colors"
import "geometry-types/geometry" as geo;

struct Sprite {
	Color color;
	geo::Vec2 position;
};
`)
	writeFile(t, filepath.Join(dir, "agent.ts"), `
import { Sprite, Color, geo } from "./sprite.pat";

const sprite = Sprite.at(Process.mainModule.base);
const isRed: boolean = sprite.color === Color.Red;
const position: geo.Vec2 = sprite.position;
console.log(isRed, position.x);
`)

	var diagnostics []Diagnostic
	bundle, err := build(BuildOptions{ProjectRoot: dir, Entrypoint: "agent.ts"}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err != nil {
		t.Fatalf("build failed: %v\n%+v", err, diagnostics)
	}
	if !strings.Contains(bundle, "geometry.Vec2 = class Vec2") || !strings.Contains(bundle, "geo.Vec2 = geometry.Vec2") {
		t.Errorf("bundle lacks the imported type under its alias:\n%s", bundle)
	}
}

func TestBuildReportsErrorsInIncludedPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "colors.pat"), "enum Color : u8 { Red, Green };\nstruct Bad { auto x @ 0; };\n")
	writeFile(t, filepath.Join(dir, "sprite.pat"), "#include \"colors\"\nstruct Sprite { Color color; };\n")
	writeFile(t, filepath.Join(dir, "agent.ts"), `import { Sprite } from "./sprite.pat";
console.log(Sprite.size);
`)

	var diagnostics []Diagnostic
	_, err := build(BuildOptions{ProjectRoot: dir, Entrypoint: "agent.ts"}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err == nil {
		t.Fatal("expected the build to fail")
	}
	found := false
	for _, d := range diagnostics {
		if strings.Contains(d.text, "auto is not supported") && strings.HasSuffix(d.path, "colors.pat") && d.line == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("unexpected diagnostics: %+v", diagnostics)
	}
}

func TestMesonListsEveryGoSource(t *testing.T) {
	manifest, err := os.ReadFile("meson.build")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".", "patterns"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			listed := filepath.ToSlash(filepath.Join(dir, name))
			if dir == "." {
				listed = name
			}
			if !strings.Contains(string(manifest), "'"+listed+"'") {
				t.Errorf("%s is missing from meson.build", listed)
			}
		}
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildLibrary(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lib", "index.ts"), `
import { Player } from "./patterns/player.pat";
import { describe } from "./describe.js";

export function findPlayer(address: NativePointer): Player {
    return Player.at(address);
}

export function describePlayer(player: Player): string {
    return describe(player.hitpoints);
}
`)
	writeFile(t, filepath.Join(dir, "lib", "describe.ts"), `
export function describe(hitpoints: number): string {
    return hitpoints + " hp";
}
`)
	writeFile(t, filepath.Join(dir, "lib", "patterns", "player.pat"), "import geometry;\n"+playerPattern)
	writeFile(t, filepath.Join(dir, "lib", "patterns", "geometry.pat"), `
struct Vec3 {
	float x;
	float y;
	float z;
};
`)

	var diagnostics []Diagnostic
	err := buildLibrary(LibraryOptions{ProjectRoot: dir, Entrypoint: "lib/index.ts", OutputDir: "dist", SourceMap: true}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err != nil {
		t.Fatalf("build failed: %v\n%+v", err, diagnostics)
	}

	dist := filepath.Join(dir, "dist")
	declarations := readFile(t, filepath.Join(dist, "index.d.ts"))
	for _, expected := range []string{`import { Player } from "./patterns/player.pat";`, "export declare function findPlayer(address: NativePointer): Player;"} {
		if !strings.Contains(declarations, expected) {
			t.Errorf("declarations lack %q:\n%s", expected, declarations)
		}
	}
	if code := readFile(t, filepath.Join(dist, "index.js")); !strings.Contains(code, `from "./patterns/player.pat"`) {
		t.Errorf("unexpected code:\n%s", code)
	}
	for _, expected := range []string{"index.js.map", "describe.js", "describe.d.ts", "patterns/player.pat", "patterns/player.pat.d.ts", "patterns/geometry.pat"} {
		if _, err := os.Stat(filepath.Join(dist, filepath.FromSlash(expected))); err != nil {
			t.Errorf("missing %s", expected)
		}
	}
	if _, err := os.Stat(filepath.Join(dist, "patterns", "geometry.pat.d.ts")); err == nil {
		t.Error("declarations should only be emitted for imported patterns")
	}

	writeFile(t, filepath.Join(dir, "agent.ts"), `
import { findPlayer, describePlayer } from "./dist/index.js";

console.log(describePlayer(findPlayer(Process.mainModule.base)));
`)
	bundle, err := build(BuildOptions{ProjectRoot: dir, Entrypoint: "agent.ts"}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err != nil {
		t.Fatalf("consumer build failed: %v\n%+v", err, diagnostics)
	}
	for _, expected := range []string{"describePlayer", "readU32()"} {
		if !strings.Contains(bundle, expected) {
			t.Errorf("bundle lacks %q:\n%s", expected, bundle)
		}
	}
}

func TestBuildLibraryReportsErrors(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lib", "index.ts"), `export const answer: number = "nope";`)

	var diagnostics []Diagnostic
	err := buildLibrary(LibraryOptions{ProjectRoot: dir, Entrypoint: "lib/index.ts", OutputDir: "dist"}, func(d Diagnostic) {
		diagnostics = append(diagnostics, d)
	})
	if err == nil {
		t.Fatal("expected the build to fail")
	}
	if len(diagnostics) != 1 || diagnostics[0].path != filepath.Join("lib", "index.ts") || diagnostics[0].code != 2322 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist")); err == nil {
		t.Error("nothing should be written when the build fails")
	}
}

func TestWatchLibrary(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lib", "index.ts"), "export const answer = 42;\n")

	finished := make(chan struct{}, 1)
	var diagnostics []Diagnostic
	session, err := NewLibraryWatchSession(LibraryOptions{ProjectRoot: dir, Entrypoint: "lib/index.ts", OutputDir: "dist"}, func() {},
		BuildEventCallbacks{
			OnEnd: func() {
				finished <- struct{}{}
			},
			OnDiagnostic: func(d Diagnostic) {
				diagnostics = append(diagnostics, d)
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Dispose()

	<-finished
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	if declarations := readFile(t, filepath.Join(dir, "dist", "index.d.ts")); !strings.Contains(declarations, "export declare const answer = 42;") {
		t.Errorf("unexpected declarations:\n%s", declarations)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

package patterns

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const runtimeScript = `
import { install, allocate } from "./gum-shim.mjs";
install();
const { Player, Vec3, Class, Flags } = await import("./player.js");

const mem = allocate(256);
const p = Player.at(mem);
p.hitpoints = 94;
p.armor = 7;
p.stamina = 1337;
p.class = Class.Rogue;
p.flags.alive = 1;
p.flags.team = 9;
p.flags.boosted = true;
p.position.x = 1.5;
p.position.y = -2;
p.position.z = 3;
mem.add(24).writeByteArray([66, 111, 98, 0]);
p.next = null;
p.inventoryCount = 3;
mem.add(49).writeByteArray([10, 20, 30]);
p.checksum = 0xdeadbeef;

const lines = [];
lines.push(JSON.stringify(p));
lines.push("size=" + p.$size);
lines.push("stamina=" + mem.add(6).readU8() + "," + mem.add(7).readU8());
lines.push("flags=" + mem.add(10).readU16().toString(16));
p.next = p;
lines.push("next=" + p.next.hitpoints);
lines.push("pattern=" + Vec3.pattern({ x: 1.5, z: 3 }));
lines.push("sizes=" + Vec3.size + "," + Flags.size);
console.log(lines.join("\n"));
`

const expectedRuntimeOutput = `{"hitpoints":94,"armor":7,"stamina":1337,"class":6,"flags":{"alive":1,"team":9,"boosted":true},"position":{"x":1.5,"y":-2,"z":3},"name":"Bob","next":"0x0","inventoryCount":3,"inventory":[10,20,30],"checksum":3735928559}
size=56
stamina=5,57
flags=191
next=94
pattern=00 00 c0 3f ?? ?? ?? ?? 00 00 40 40
sizes=12,2`

func nodeModule(module *Module, sourceName string) string {
	return strings.ReplaceAll(EmitJavaScript(module, sourceName), `"`+RuntimeScheme+"/", `"./`)
}

func writeRuntimeModules(t *testing.T, dir string) {
	for path, source := range RuntimeModules {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(*source), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGeneratedModuleUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}

	module, diagnostics := Compile(playerSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}

	dir := t.TempDir()
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"gum-shim.mjs": string(shim),
		"player.js":    nodeModule(module, "player.pat"),
		"run.mjs":      runtimeScript,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)

	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, output)
	}
	if actual := strings.TrimSpace(string(output)); actual != expectedRuntimeOutput {
		t.Errorf("unexpected output:\n%s\nexpected:\n%s", actual, expectedRuntimeOutput)
	}
}

const shapeRuntimeScript = `
import { install, allocate } from "./gum-shim.mjs";
install();
const { Shape, Kind } = await import("./shape.js");

const mem = allocate(256);
mem.writeByteArray([2, 1, 0xaa, 0xbb, 0xcc, 2, 3, 40, 0, 50, 0, 0x10, 0x00, 0xde, 0xad, 0xbe, 0xef]);
mem.add(17).writeByteArray(new Array(12).fill(0x11));
mem.add(29).writeByteArray([2, 0, 7, 0, 8, 0, 9, 0]);
const shape = Shape.at(mem);
const lines = [];
lines.push("magic=" + shape.header.magic.toString(16) + " kind=" + Kind[shape.header.kind]);
lines.push("radius=" + shape.radius + " width=" + shape.width + " height=" + shape.height + " raw=" + shape.raw);
lines.push("legacy=" + shape.legacy + " modern=" + shape.modern + " future=" + shape.future);
lines.push("checksum=" + shape.checksum.toString(16) + " wide=" + shape.wide.toString(16));
lines.push("items=" + shape.payload.items + " size=" + shape.$size);
shape.header.kind = Kind.Circle;
lines.push("radius=" + shape.radius + " width=" + shape.width);
console.log(lines.join("\n"));
`

const expectedShapeOutput = `magic=ccbbaa kind=Rect
radius=undefined width=40 height=50 raw=undefined
legacy=undefined modern=16 future=undefined
checksum=deadbeef wide=111111111111111111111111efbeadde
items=7,8,9 size=37
radius=40 width=undefined`

func TestShapeUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}

	module, diagnostics := Compile(shapeSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}

	dir := t.TempDir()
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"gum-shim.mjs": string(shim),
		"shape.js":     nodeModule(module, "shape.pat"),
		"run.mjs":      shapeRuntimeScript,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)

	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, output)
	}
	if actual := strings.TrimSpace(string(output)); actual != expectedShapeOutput {
		t.Errorf("unexpected output:\n%s\nexpected:\n%s\n%s", actual, expectedShapeOutput, files["shape.js"])
	}
}

const iconRuntimeScript = `
import { install, allocate } from "./gum-shim.mjs";
install();
const { parse, Icon, IconDir, Entry } = await import("./icon.js");

const mem = allocate(256);
mem.writeByteArray([0, 0, 2, 0, 1, 0, 8, 8, 5, 0, 21, 0, 3, 0, 0x11, 0x22, 0xff, 0xde, 0xad, 0xbe, 0xef, 66, 77, 8, 0, 0, 0, 7, 9]);
const icon = parse(mem, 29);
const entry = icon.entries[0];
const lines = [];
lines.push("type=" + icon.dir.type + " count=" + icon.dir.count + " size=" + icon.$size);
lines.push("entry=" + entry.width + "x" + entry.height + " hotspot=" + entry.hotspot + " tail=" + entry.tail + " terminator=" + entry.terminator);
lines.push("image=" + entry.image.header.signature + " pixels=" + entry.image.pixels + " at=" + entry.$fields.image.address.sub(mem));
lines.push("magic=" + icon.magic.toString(16) + " entrySize=" + entry.$size + " typeof=" + typeof Entry.parse + " view=" + (IconDir.at(mem).count));
console.log(lines.join("\n"));
`

const expectedIconOutput = `type=2 count=1 size=12
entry=8x8 hotspot=3 tail=17,34 terminator=255
image=BM pixels=7,9 at=0x15
magic=150005 entrySize=11 typeof=function view=1`

func TestIconUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}

	module, diagnostics := CompileSource(Source{Path: iconSource, Text: iconFiles[iconSource]}, iconFiles)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}

	dir := t.TempDir()
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"gum-shim.mjs": string(shim),
		"icon.js":      nodeModule(module, "icon.hexpat"),
		"run.mjs":      iconRuntimeScript,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)

	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s\n%s", err, output, files["icon.js"])
	}
	if actual := strings.TrimSpace(string(output)); actual != expectedIconOutput {
		t.Errorf("unexpected output:\n%s\nexpected:\n%s\n%s", actual, expectedIconOutput, files["icon.js"])
	}
}

func TestDeclarationsForPlayer(t *testing.T) {
	module, diagnostics := Compile(playerSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	declarations := EmitDeclarations(module, "player.pat")
	for _, expected := range []string{
		"export declare enum Class {",
		"    Rogue = 6,",
		"export declare class Player {",
		"    hitpoints: number;",
		"    readonly position: Vec3;",
		"    get next(): Player | null;",
		"    readonly inventory: number[];",
		"    boosted: boolean;",
		"static pattern(fields: Vec3.Fields): string;",
		"export declare const PlayerRef: typeof Player;",
	} {
		if !strings.Contains(declarations, expected) {
			t.Errorf("missing %q in:\n%s", expected, declarations)
		}
	}
	if strings.Contains(declarations, "static pattern(fields: Player.Fields)") {
		t.Errorf("dynamically sized Player should not offer pattern()")
	}
}

const dynamicBitfieldScript = `
import { install, allocate } from "./gum-shim.mjs";
install();
const { parse } = await import("./record.js");
const mem = allocate(64);
mem.writeByteArray([0x13, 0x42, 0xf5, 1, 0x34, 0x12, 9, 8]);
const record = parse(mem, 8).record;
const h = record.header;
console.log(["version=" + h.version + " extended=" + h.extended + " extra=" + h.extra + " delta=" + h.delta + " kind=" + h.kind,
  "word=" + record.payload.word + " dword=" + record.payload.dword + " rest=" + record.rest + " size=" + record.$size].join("\n"));
`

const expectedDynamicBitfieldOutput = `version=3 extended=true extra=66 delta=5 kind=15
word=13313 dword=undefined rest=18,9,8 size=8`

func TestDynamicBitfieldsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	module, diagnostics := CompileSource(Source{Path: "record.hexpat", Text: dynamicBitfieldSource}, nil)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	dir := t.TempDir()
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"gum-shim.mjs": string(shim),
		"record.js":    nodeModule(module, "record.hexpat"),
		"run.mjs":      dynamicBitfieldScript,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)
	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s\n%s", err, output, files["record.js"])
	}
	if actual := strings.TrimSpace(string(output)); actual != expectedDynamicBitfieldOutput {
		t.Errorf("unexpected output:\n%s\nexpected:\n%s\n%s", actual, expectedDynamicBitfieldOutput, files["record.js"])
	}
}

func TestSectionsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	module, diagnostics := Compile(sectionsSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"gum-shim.mjs": string(shim),
		"sections.js":  nodeModule(module, "sections.hexpat"),
		"run.mjs": `
import { install, allocate } from "./gum-shim.mjs";
install();
const { parse } = await import("./sections.js");
const mem = allocate(64);
mem.writeByteArray([0x34, 0x12, 0x02, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x80, 0x3f]);
const root = parse(mem, 12).root;
console.log(JSON.stringify([root.blob.header, root.blob.peek, root.f, root.$fields.again.formatted]));
`,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)
	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, output)
	}
	expected := `[{"$address":"0x2","$size":4,"magic":4660,"len":2},4660,1,"1"]`
	if strings.TrimSpace(string(output)) != expected {
		t.Errorf("unexpected output:\n%s", output)
	}
}

func TestInputsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	module, diagnostics := Compile(inputsSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	shim, err := os.ReadFile("testdata/gum-shim.mjs")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"gum-shim.mjs": string(shim),
		"inputs.js":    nodeModule(module, "inputs.hexpat"),
		"run.mjs": `
import { install, allocate } from "./gum-shim.mjs";
install();
const { parse } = await import("./inputs.js");
const mem = allocate(16);
mem.writeU8(7);
const defaults = parse(mem, 1).sample;
const given = parse(mem, 1, { scale: 3, label: "given" }).sample;
console.log(JSON.stringify([defaults.scaled, defaults.name, given.scaled, given.name]));
`,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeModules(t, dir)
	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != `[7,"none",21,"given"]` {
		t.Errorf("unexpected output:\n%s", output)
	}
}

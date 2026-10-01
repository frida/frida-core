package patterns

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const functionsSource = `
fn describe(u8 kind) {
	if (kind == 1)
		return "circle";
	else if (kind == 2)
		return "square";
	return std::format("kind {:#x}", kind);
}

fn checksum(ref auto total, u8 count) {
	u32 i = 0;
	while (i < count) {
		total = total + std::mem::read_unsigned($ + i, 1);
		i = i + 1;
	}
	return total;
}

fn digits(u32 n) {
	str text = "";
	for (u32 i = 0, i < n, i = i + 1) {
		if (i == 3)
			break;
		text = text + std::string::to_string(i);
	}
	return text;
}

struct Record {
	u8 kind;
	u8 count;
	str label = describe(kind) [[export]];
	u32 sum = 0 [[export]];
	checksum(sum, count);
	u8 payload[count];
	try {
		u32 trailer;
		std::assert(trailer == 0xdeadbeef, "bad trailer");
	} catch {
		u8 fallback;
	}
	str name = digits(10) [[export]];
	bool big = sum > 5 [[export]];
};

Record record @ 0x00;
`

func TestFunctionsDecode(t *testing.T) {
	module, diagnostics := CompileSource(Source{Path: "records.hexpat", Text: functionsSource}, nil)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	record := findType(module, "Record").(*Struct)
	if record.Simple || len(module.Functions) != 3 {
		t.Fatalf("unexpected classification")
	}

	data := []byte{2, 3, 1, 2, 3, 0xef, 0xbe, 0xad, 0xde}
	root := Decode(module, Targets[0], module.Root, data, 0)
	rendered := root.String()
	for _, expected := range []string{
		"u8 kind @ 0x0 = 2",
		"auto label @ 0x0 = square",
		"u32 sum @ 0x0 = 6",
		"u8[...] payload @ 0x2",
		"u32 trailer @ 0x5 = 3735928559",
		"auto name @ 0x0 = 012",
		"bool big @ 0x0 = true",
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("missing %q in:\n%s", expected, rendered)
		}
	}
	if root.Error != "" || root.Truncated || *root.Size != 9 {
		t.Errorf("unexpected root: %+v\n%s", root, rendered)
	}

	short := Decode(module, Targets[0], module.Root, data[:6], 0)
	rendered = short.String()
	if !strings.Contains(rendered, "u8 fallback @ 0x5 = 239") || strings.Contains(rendered, "trailer") {
		t.Errorf("expected the catch branch to take over:\n%s", rendered)
	}

	encoded, err := DecodeSource(functionsSource, "Record", data, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	var value DecodedValue
	if err := json.Unmarshal([]byte(encoded), &value); err != nil {
		t.Fatal(err)
	}
	if value.Error != "" {
		t.Errorf("unexpected error: %s", value.Error)
	}
}

func TestFormat(t *testing.T) {
	cases := map[string]string{
		format("{} + {} = {}", []runtimeValue{int64(1), int64(2), int64(3)}):             "1 + 2 = 3",
		format("{:#x} {:08X} {:b}", []runtimeValue{uint64(255), int64(48879), int64(5)}): "0xff 0000BEEF 101",
		format("{1} {0} {{}}", []runtimeValue{"a", "b"}):                                 "b a {}",
		format("{:.2}", []runtimeValue{float64(3.14159)}):                                "3.14",
		format("{:>5}", []runtimeValue{"x"}):                                             "x",
	}
	for actual, expected := range cases {
		if actual != expected {
			t.Errorf("got %q, expected %q", actual, expected)
		}
	}
}

const functionsRuntimeScript = `
import { install, allocate } from "./gum-shim.mjs";
install();
const { parse } = await import("./records.js");

const mem = allocate(64);
mem.writeByteArray([2, 3, 1, 2, 3, 0xef, 0xbe, 0xad, 0xde]);
const full = parse(mem, 9);
const short = parse(mem, 6);
console.log([
  "label=" + full.record.label + " sum=" + full.record.sum + " name=" + full.record.name + " big=" + full.record.big,
  "trailer=" + full.record.trailer.toString(16) + " size=" + full.record.$size,
  "fallback=" + short.record.fallback + " trailer=" + short.record.trailer,
].join("\n"));
`

const expectedFunctionsOutput = `label=square sum=6 name=012 big=true
trailer=deadbeef size=9
fallback=239 trailer=undefined`

func TestFunctionsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	module, diagnostics := CompileSource(Source{Path: "records.hexpat", Text: functionsSource}, nil)
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
		"records.js":   EmitJavaScript(module, "records.hexpat"),
		"run.mjs":      functionsRuntimeScript,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s\n%s", err, output, files["records.js"])
	}
	if actual := strings.TrimSpace(string(output)); actual != expectedFunctionsOutput {
		t.Errorf("unexpected output:\n%s\nexpected:\n%s\n%s", actual, expectedFunctionsOutput, files["records.js"])
	}
}

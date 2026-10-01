package patterns

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const attributesSource = `
fn describe_kind(u8 kind) {
	return std::format("kind #{}", kind);
}

fn as_seconds(u32 raw) {
	return raw / 1000;
}

using Millis = u32 [[format("as_seconds")]];

struct Entry {
	u8 kind [[format("describe_kind"), color("FF0000")]];
	Millis elapsed;
	u16 raw [[transform("as_seconds")]];
	u8 secret [[hidden]];
	u8 tags[2] [[name(std::format("tags of {}", kind)), comment("two tags"), inline]];
} [[sealed]];

Entry entry @ 0x00;
`

func TestAttributesDecode(t *testing.T) {
	module, diagnostics := CompileSource(Source{Path: "entry.hexpat", Text: attributesSource}, nil)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	root := Decode(module, Targets[0], module.Root, []byte{7, 0xd0, 0x07, 0, 0, 0xe8, 0x03, 42, 1, 2}, 0)
	entry := root.Fields[0]
	if !entry.Sealed {
		t.Errorf("expected the struct attribute to seal the entry")
	}
	fields := map[string]*DecodedValue{}
	for _, field := range entry.Fields {
		fields[field.Name] = field
	}
	if fields["kind"].Formatted != "kind #7" || fields["kind"].Color != "FF0000" {
		t.Errorf("unexpected kind: %+v", fields["kind"])
	}
	if fields["elapsed"].Formatted != "2" {
		t.Errorf("alias format should apply: %+v", fields["elapsed"])
	}
	if fields["raw"].Value != int64(1) {
		t.Errorf("transform should replace the value: %+v", fields["raw"])
	}
	if !fields["secret"].Hidden {
		t.Errorf("hidden should be recorded")
	}
	tags := fields["tags"]
	if tags.DisplayName != "tags of 7" || tags.Comment != "two tags" || !tags.Inline {
		t.Errorf("unexpected tags: %+v", tags)
	}
}

const attributesScript = `
import { install, allocate } from "./gum-shim.mjs";
install();
const { parse } = await import("./entry.js");
const mem = allocate(64);
mem.writeByteArray([7, 0xd0, 0x07, 0, 0, 0xe8, 0x03, 42, 1, 2]);
const entry = parse(mem, 10).entry;
const f = entry.$fields;
console.log(["kind=" + f.kind.formatted + "/" + f.kind.color, "elapsed=" + f.elapsed.formatted, "raw=" + entry.raw,
  "secret=" + f.secret.hidden, "tags=" + f.tags.displayName + "/" + f.tags.comment + "/" + f.tags.inline, "sealed=" + entry.$sealed].join("\n"));
`

const expectedAttributesOutput = `kind=kind #7/FF0000
elapsed=2
raw=1
secret=true
tags=tags of 7/two tags/true
sealed=true`

func TestAttributesUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	module, diagnostics := CompileSource(Source{Path: "entry.hexpat", Text: attributesSource}, nil)
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
		"entry.js":     EmitJavaScript(module, "entry.hexpat"),
		"run.mjs":      attributesScript,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
	}
	output, err := exec.Command(node, filepath.Join(dir, "run.mjs")).CombinedOutput()
	if err != nil {
		t.Fatalf("node failed: %v\n%s\n%s", err, output, files["entry.js"])
	}
	if actual := strings.TrimSpace(string(output)); actual != expectedAttributesOutput {
		t.Errorf("unexpected output:\n%s\nexpected:\n%s\n%s", actual, expectedAttributesOutput, files["entry.js"])
	}
}

package patterns

import (
	"strings"
	"testing"
)

const serviceSource = `/** A three-byte colour. */
struct Rgb {
    u8 r [[color("FF0000")]];
    u8 g;
    u8 b;
};

namespace img {
    enum Kind : u8 {
        Raw = 0,
        Packed = 1,
    };

    bitfield Flags {
        dirty : 1;
        padding : 7;
    };
}

fn twice(u32 x) {
    return x * 2;
};

Rgb pixel @ 0x00;
`

func openService(t *testing.T) *LanguageService {
	t.Helper()
	service := NewLanguageService()
	service.Open("file:///test.hexpat", serviceSource)
	return service
}

func TestServiceHandlesPatternFiles(t *testing.T) {
	service := NewLanguageService()
	if !service.Handles("file:///a.hexpat") || !service.Handles("file:///lib.pat") || service.Handles("file:///agent.ts") {
		t.Fatal("wrong document routing")
	}
}

func TestServiceSymbols(t *testing.T) {
	symbols := openService(t).Symbols("file:///test.hexpat")
	if len(symbols) != 3 {
		t.Fatalf("expected Rgb, img and twice, got %+v", symbols)
	}
	rgb := symbols[0]
	if rgb.Name != "Rgb" || rgb.Kind != symbolStruct || rgb.Range.Start.Line != 1 || rgb.Range.End.Line != 5 || rgb.Range.End.Character != 2 {
		t.Errorf("unexpected Rgb symbol: %+v", rgb)
	}
	if rgb.SelectionRange.Start.Character != 7 || rgb.SelectionRange.End.Character != 10 {
		t.Errorf("Rgb name should be selected: %+v", rgb.SelectionRange)
	}
	if len(rgb.Children) != 3 || rgb.Children[0].Name != "r" || rgb.Children[0].Detail != "u8" {
		t.Errorf("unexpected Rgb fields: %+v", rgb.Children)
	}
	img := symbols[1]
	if img.Name != "img" || img.Kind != symbolNamespace || len(img.Children) != 2 {
		t.Fatalf("unexpected namespace: %+v", img)
	}
	if img.Children[0].Name != "Kind" || img.Children[0].Kind != symbolEnum || len(img.Children[0].Children) != 2 {
		t.Errorf("unexpected enum: %+v", img.Children[0])
	}
	if img.Children[1].Name != "Flags" || len(img.Children[1].Children) != 1 || img.Children[1].Children[0].Name != "dirty" {
		t.Errorf("unexpected bitfield: %+v", img.Children[1])
	}
	if symbols[2].Name != "twice" || symbols[2].Kind != symbolFunction {
		t.Errorf("unexpected function: %+v", symbols[2])
	}
}

func TestServiceFoldingRanges(t *testing.T) {
	ranges := openService(t).FoldingRanges("file:///test.hexpat")
	if len(ranges) != 5 {
		t.Fatalf("expected the struct, namespace, enum, bitfield and function to fold, got %+v", ranges)
	}
	first := ranges[0]
	if first.StartLine != 1 || first.StartCharacter != 11 || first.EndLine != 5 || first.EndCharacter != 1 {
		t.Errorf("unexpected struct fold: %+v", first)
	}
	if ranges[1].StartLine != 7 || ranges[1].EndLine != 17 {
		t.Errorf("unexpected namespace fold: %+v", ranges[1])
	}
}

func TestServiceColors(t *testing.T) {
	colors := openService(t).Colors("file:///test.hexpat")
	if len(colors) != 1 {
		t.Fatalf("expected one colour, got %+v", colors)
	}
	c := colors[0]
	if c.Range.Start.Line != 2 || c.Range.Start.Character != 17 || c.Range.End.Character != 25 {
		t.Errorf("unexpected colour range: %+v", c.Range)
	}
	if c.Color.Red != 1 || c.Color.Green != 0 || c.Color.Blue != 0 || c.Color.Alpha != 1 {
		t.Errorf("unexpected colour: %+v", c.Color)
	}
	presentations := NewLanguageService().ColorPresentations(Color{Red: 0, Green: 0.5, Blue: 1, Alpha: 1}, c.Range)
	if presentations[0].Label != "0080FF" || presentations[0].TextEdit.NewText != `"0080FF"` {
		t.Errorf("unexpected presentation: %+v", presentations[0])
	}
}

func TestServiceHoverAndDefinition(t *testing.T) {
	service := openService(t)
	hover := service.Hover("file:///test.hexpat", TextPosition{Line: 23, Character: 1})
	if hover == nil || hover.Contents.Value != "```hexpat\nstruct Rgb    // 3 bytes\n```\n\nA three-byte colour." {
		t.Fatalf("unexpected hover: %+v", hover)
	}
	definition := service.Definition("file:///test.hexpat", TextPosition{Line: 23, Character: 1})
	if definition == nil || definition.Range.Start.Line != 1 || definition.Range.Start.Character != 7 {
		t.Errorf("unexpected definition: %+v", definition)
	}
	if service.Hover("file:///test.hexpat", TextPosition{Line: 23, Character: 6}) != nil {
		t.Error("a variable name should not hover as a type")
	}
}

func TestServiceCompletionsAndDiagnostics(t *testing.T) {
	service := openService(t)
	items := service.Completions("file:///test.hexpat", TextPosition{Line: 23, Character: 0})
	labels := map[string]bool{}
	for _, item := range items {
		labels[item.Label] = true
	}
	for _, expected := range []string{"Rgb", "img::Kind", "twice", "u32", "struct", "std::mem::size"} {
		if !labels[expected] {
			t.Errorf("missing completion %q", expected)
		}
	}
	service.Change("file:///test.hexpat", "struct Broken {\n    u8 a\n};\n")
	diagnostics := service.Diagnostics("file:///test.hexpat")
	if len(diagnostics) != 1 || diagnostics[0].Range.Start.Line != 2 || diagnostics[0].Severity != SeverityError {
		t.Fatalf("unexpected diagnostics: %+v", diagnostics)
	}
	service.Change("file:///test.hexpat", "struct Typo {\n    u8 count;\n    u8 items[cuont];\n};\n")
	diagnostics = service.Diagnostics("file:///test.hexpat")
	if len(diagnostics) != 1 || diagnostics[0].Range.Start.Line != 2 || diagnostics[0].Severity != SeverityWarning {
		t.Fatalf("an unresolved name should be a warning: %+v", diagnostics)
	}
}

func TestServiceSemanticTokens(t *testing.T) {
	spans := openService(t).SemanticTokens("file:///test.hexpat")
	var declared, referenced bool
	for _, span := range spans {
		if span.Line == 1 && span.Character == 7 && span.Type == "struct" {
			declared = true
		}
		if span.Line == 23 && span.Character == 0 && span.Type == "type" && span.Length == 3 {
			referenced = true
		}
	}
	if !declared || !referenced {
		t.Errorf("expected the declaration and the reference of Rgb to be tokens: %+v", spans)
	}
}

func TestServiceCompletionsFollowContext(t *testing.T) {
	const declarations = "struct Header { u32 magic; };\nenum Kind : u8 { A, B };\nfn describe(Kind kind) { return \"\"; };\n"
	cases := []struct {
		source   string
		expected []string
		absent   []string
	}{
		{"|", []string{"struct", "Header", "u32", "describe"}, []string{"this", "hex::visualize"}},
		{"struct Pixel {\n    |", []string{"Header", "Kind", "u8", "if", "padding"}, []string{"struct", "describe", "this"}},
		{"struct Pixel {\n    u8 |", nil, []string{"Header", "u8", "if"}},
		{"struct Pixel {\n    u8 r;\n    u8 g [|", []string{"r", "this", "describe", "Kind::A", "while"}, []string{"Header", "u8", "g"}},
		{"struct Pixel {\n    u8 r [[|", []string{"color", "format", "hex::visualize"}, []string{"Header", "u8", "r"}},
		{"struct Pixel {\n    u8 r [[color(\"FF0000\"), |", []string{"name", "hidden"}, []string{"Header"}},
		{"struct Pixel {\n    u8 r [[hex::visualize(\"|", []string{"line_plot", "bitmap"}, []string{"color", "Header"}},
		{"struct Pixel {\n    u8 r [[hex::inline_visualize(\"|", []string{"color", "gauge"}, []string{"line_plot"}},
		{"struct Pixel {\n    u8 r [[format(\"|", []string{"describe"}, []string{"Header", "u8"}},
		{"struct Pixel {\n    u8 r [[hex::visualize(\"bitmap\", this, |", []string{"r", "this"}, []string{"line_plot", "Header"}},
		{"struct Pixel : |", []string{"Header"}, []string{"Kind", "u8"}},
		{"enum Flags : |", []string{"u8", "u32"}, []string{"Header", "float"}},
		{"enum Flags : u8 {\n    |", nil, []string{"u8", "Header"}},
		{"enum Flags : u8 {\n    A = |", []string{"Kind::B"}, []string{"u8"}},
		{"bitfield Bits {\n    |", []string{"Kind", "padding"}, []string{"struct"}},
		{"bitfield Bits {\n    flag : |", []string{"this"}, []string{"Kind"}},
		{"fn twice(u32 value) {\n    |", []string{"value", "return", "u32", "describe"}, []string{"struct", "padding"}},
		{"fn twice(|", []string{"u32", "ref", "Header"}, []string{"return", "describe"}},
		{"fn twice(u32 |", nil, []string{"u32"}},
		{"fn twice(u32 value) {\n    return |", []string{"value", "describe"}, []string{"u32"}},
		{"Header header @ |", []string{"describe", "sizeof"}, []string{"Header"}},
		{"struct Pixel {\n    u32 *pointer : |", []string{"u32"}, []string{"Header"}},
		{"std::mem::Bytes<|", []string{"u8"}, []string{"describe"}},
		{"// Head|", nil, []string{"Header"}},
		{"struct Pixel {\n    u8 r [[comment(\"Head|", nil, []string{"Header"}},
		{"struct |", nil, []string{"Header"}},
		{"struct Pixel {\n    std::mem::|", []string{"size"}, []string{"u8", "std::mem::size"}},
		{"struct Pixel {\n    u8 r [[hex::|", []string{"visualize", "inline_visualize"}, []string{"color", "hex::visualize"}},
		{"Header header @ std::mem::si|", []string{"size"}, []string{"describe"}},
	}
	for _, c := range cases {
		source := declarations + c.source
		cursor := strings.Index(source, "|")
		text := source[:cursor] + source[cursor+1:]
		service := NewLanguageService()
		service.Open("file:///c.hexpat", text)
		lines := strings.Split(source[:cursor], "\n")
		position := TextPosition{Line: len(lines) - 1, Character: len(lines[len(lines)-1])}
		labels := map[string]bool{}
		for _, item := range service.Completions("file:///c.hexpat", position) {
			labels[item.Label] = true
		}
		for _, label := range c.expected {
			if !labels[label] {
				t.Errorf("%q: missing %q", c.source, label)
			}
		}
		for _, label := range c.absent {
			if labels[label] {
				t.Errorf("%q: unexpected %q", c.source, label)
			}
		}
	}
}

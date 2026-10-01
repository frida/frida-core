package patterns

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeVisualizers(t *testing.T) {
	module, diagnostics := Compile(`
struct Image {
    u8 magic[4];
    u16 width;
    u8 visualizer[6] @ addressof(this) [[sealed, hex::visualize("image", this), no_unique_address]];
    u8 samples[2] [[hex::inline_visualize("line_plot", this, width, 1.5, "linear")]];
};
`)
	if len(diagnostics) != 0 {
		t.Fatal(diagnostics)
	}
	value := Decode(module, Targets[0], module.Types[0], []byte{0x89, 'P', 'N', 'G', 7, 0, 1, 2}, 0x1000)

	image := value.Fields[2].Visualizer
	if image == nil || image.Name != "image" || image.Presentation != "detached" || len(image.Arguments) != 1 {
		t.Fatalf("unexpected image visualizer: %+v", image)
	}
	pattern := image.Arguments[0]
	if pattern.Kind != "pattern" || pattern.Address != "0x1000" || pattern.Size == nil || *pattern.Size != 6 {
		t.Errorf("this should describe the visualizer field's bytes: %+v", pattern)
	}
	if pattern.Pattern != value.Fields[2].ID || !bytes.Equal(pattern.Data, []byte{0x89, 'P', 'N', 'G', 7, 0}) {
		t.Errorf("this should refer to the field and carry its bytes: %+v", pattern)
	}

	plot := value.Fields[3].Visualizer
	if plot == nil || plot.Name != "line_plot" || plot.Presentation != "inline" || len(plot.Arguments) != 4 {
		t.Fatalf("unexpected inline visualizer: %+v", plot)
	}
	if plot.Arguments[0].Kind != "pattern" || plot.Arguments[0].Address != "0x1006" || *plot.Arguments[0].Size != 2 {
		t.Errorf("this should describe the array's bytes: %+v", plot.Arguments[0])
	}
	if plot.Arguments[0].Pattern != value.Fields[3].ID || plot.Arguments[0].Pattern == value.Fields[2].ID {
		t.Errorf("this should refer to the array: %+v", plot.Arguments[0])
	}
	if plot.Arguments[1].Kind != "value" || fmt.Sprint(plot.Arguments[1].Value) != "7" {
		t.Errorf("a scalar field should pass its value: %+v", plot.Arguments[1])
	}
	if plot.Arguments[2].ValueKind != "float" || plot.Arguments[2].Value != 1.5 {
		t.Errorf("unexpected float argument: %+v", plot.Arguments[2])
	}
	if plot.Arguments[3].ValueKind != "string" || plot.Arguments[3].Value != "linear" {
		t.Errorf("unexpected string argument: %+v", plot.Arguments[3])
	}
}

func TestTypeVisualizersSeeOwnMembers(t *testing.T) {
	module, diagnostics := Compile(`
bitfield RGB<auto R, auto G, auto B> {
    r : R;
    g : G;
    b : B;
};
using Color = RGB<8, 8, 8> [[hex::inline_visualize("color", r, g, b, 0xff)]];
struct Picture {
    u8 kind;
    u8 data[2];
} [[hex::visualize("image", this.data)]];
struct File {
    Color background;
    Picture picture;
};
`)
	if len(diagnostics) != 0 {
		t.Fatal(diagnostics)
	}
	var file Type
	for _, candidate := range module.Types {
		if candidate.TypeName() == "File" {
			file = candidate
		}
	}
	value := Decode(module, Targets[0], file, []byte{0x10, 0x20, 0x30, 7, 0xAA, 0xBB}, 0x2000)

	color := value.Fields[0].Visualizer
	if color == nil || color.Name != "color" || len(color.Arguments) != 4 {
		t.Fatalf("unexpected color visualizer: %+v (error %q)", color, value.Fields[0].Error)
	}
	for i, expected := range []string{"16", "32", "48", "255"} {
		if fmt.Sprint(color.Arguments[i].Value) != expected {
			t.Errorf("argument %d: expected %s, got %+v", i, expected, color.Arguments[i])
		}
	}

	image := value.Fields[1].Visualizer
	if image == nil || len(image.Arguments) != 1 || image.Arguments[0].Address != "0x2004" || *image.Arguments[0].Size != 2 {
		t.Fatalf("this.data should describe the picture's own data: %+v (error %q)", image, value.Fields[1].Error)
	}
}

func TestVisualizerNeedsName(t *testing.T) {
	_, diagnostics := Compile(`struct A { u8 b [[hex::visualize()]]; };`)
	if len(diagnostics) != 1 || !strings.Contains(diagnostics[0].Message, "expects a visualizer name") {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}
}

func TestCallFunctionOnPattern(t *testing.T) {
	module, diagnostics := Compile(`
fn greet(ref auto pattern) {
    std::print("{} is {}", pattern.name, pattern.value);
};
struct Pair {
    u8 name;
    u8 value [[hex::inline_visualize("button", "greet")]];
};
`)
	if len(diagnostics) != 0 {
		t.Fatal(diagnostics)
	}
	pair := module.Types[0]
	for _, candidate := range module.Types {
		if candidate.TypeName() == "Pair" {
			pair = candidate
		}
	}
	data := []byte{1, 2}
	value := Decode(module, Targets[0], pair, data, 0)
	output, err := CallFunction(module, Targets[0], pair, data, 0, nil, value.ID, "greet")
	if err != nil {
		t.Fatal(err)
	}
	if output != "1 is 2" {
		t.Errorf("unexpected output %q", output)
	}
	if _, err := CallFunction(module, Targets[0], pair, data, 0, nil, 99, "greet"); err == nil {
		t.Error("an unknown pattern should fail")
	}
}

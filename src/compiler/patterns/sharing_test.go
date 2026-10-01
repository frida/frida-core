package patterns

import (
	"reflect"
	"sync"
	"testing"
)

func TestCompilingLeavesSharedParsesIntact(t *testing.T) {
	files := sourceMap{
		"shapes.pat": `
namespace auto shapes {
	struct Point { u8 x, y; };
}
u8 flags @ 0x00;
if (flags == 0) {
	u8 marker @ 0x02;
}
`,
		"palette.pat": `
enum Color : u8 { Red, Green };
Color background @ 0x03;
`,
		"main.hexpat": `
#include "palette"
import shapes as geo;
import * from palette as Palette;

struct Sprite {
	geo::Point position;
	Palette swatch;
};
Sprite sprite @ 0x04;
`,
	}
	if _, diagnostics := CompileSource(Source{Path: "main.hexpat", Text: files["main.hexpat"]}, files); len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	for path, text := range files {
		fresh, _ := ParseFile(path, text)
		if !reflect.DeepEqual(parseShared(Source{Path: path, Text: text}, nil, files).file, fresh) {
			t.Errorf("compiling altered the shared parse of %s", path)
		}
	}
}

func TestCompileSharesModules(t *testing.T) {
	first, _ := Compile(playerSource)
	second, _ := Compile(playerSource)
	if first != second {
		t.Errorf("compiling the same source twice should share the module")
	}
}

func TestSharedModuleServesConcurrentQueries(t *testing.T) {
	data := make([]byte, 64)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			DescribeSource(playerSource, Targets[0])
		})
		wg.Go(func() {
			if _, err := DecodeSource(playerSource, "Player", data, 0, Targets[0], nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

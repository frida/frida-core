package patterns

import (
	"fmt"
	"strings"
	"testing"
)

const playerSource = `
#pragma abi native

enum Class : u8 {
	Warrior,
	Mage = 5,
	Rogue,
};

bitfield Flags {
	alive : 1;
	padding : 3;
	team : 4;
	bool boosted : 1;
};

struct Vec3 {
	float x;
	float y;
	float z;
};

/** A player in the arena. */
struct Player {
	u32 hitpoints [[comment("Remaining health")]];
	u16 armor;
	be u16 stamina;
	Class class;
	Flags flags;
	Vec3 position;
	char name[16];
	Player *next;
	u8 inventoryCount;
	u8 inventory[inventoryCount];
	u32 checksum;
};

using PlayerRef = Player;
`

func TestCompilePlayer(t *testing.T) {
	module, diagnostics := Compile(playerSource)
	if len(diagnostics) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}

	layout := module.Layout(Targets[0])
	player := findType(module, "Player").(*Struct)
	composite := layout.Composite(player)

	offsets := map[string]int{}
	for _, f := range composite.Fields {
		if !f.Dynamic {
			offsets[f.Field.Name] = f.Offset
		}
	}
	expected := map[string]int{"hitpoints": 0, "armor": 4, "stamina": 6, "class": 8, "flags": 10, "position": 12, "name": 24, "next": 40, "inventoryCount": 48, "inventory": 49}
	for name, offset := range expected {
		if offsets[name] != offset {
			t.Errorf("%s: offset %d, expected %d", name, offsets[name], offset)
		}
	}
	if _, isStatic := offsets["checksum"]; isStatic {
		t.Errorf("checksum should have a dynamic offset")
	}

	class := findType(module, "Class").(*Enum)
	if class.Members[2].Value != 6 {
		t.Errorf("Rogue = %d, expected 6", class.Members[2].Value)
	}

	flags := findType(module, "Flags").(*Bitfield)
	if flags.TotalBits != 9 || flags.Members[2].Offset != 4 {
		t.Errorf("unexpected bitfield layout: %+v", flags)
	}
}

func TestCompileReportsUnsupported(t *testing.T) {
	cases := map[string]string{
		"struct A { auto a @ 0; };":                                   "auto is not supported",
		"struct A { A a; };":                                          "type contains itself by value",
		"struct A { u32 a; };\nstruct A { u32 b; };":                  "A is already declared at line 1",
		"struct C { u8 n; u8 d[n]; }; struct B { u8 x[sizeof(C)]; };": "sizeof a dynamically sized type",
	}
	for source, expected := range cases {
		_, diagnostics := Compile(source)
		if len(diagnostics) == 0 {
			t.Errorf("%q: expected a diagnostic", source)
			continue
		}
		if !strings.Contains(diagnostics[0].Message, expected) {
			t.Errorf("%q: got %q, expected %q", source, diagnostics[0].Message, expected)
		}
	}
}

func TestUnresolvedNamesFailWhenReached(t *testing.T) {
	cases := map[string]string{
		"fn foo(u32 a) { return a; }; struct A { u8 x[foo()]; };": "foo takes 1 arguments",
		"fn f() { return; }; struct A { u8 x[while(f(1))]; };":    "f takes 0 arguments",
		"struct A { u32 a; u32 b[c]; };":                          "unknown identifier c",
		"struct A { u32 a; u32 b[a.missing]; };":                  "a has no field missing",
	}
	for source, expected := range cases {
		module, diagnostics := Compile(source)
		if len(diagnostics) > 0 {
			t.Errorf("%q: unexpected diagnostics: %v", source, diagnostics)
			continue
		}
		if len(module.Warnings) == 0 || !strings.Contains(module.Warnings[0].Message, expected) {
			t.Errorf("%q: expected a warning %q, got %v", source, expected, module.Warnings)
		}
		decoded, err := DecodeSource(source, "A", make([]byte, 16), 0, Targets[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(decoded, expected) {
			t.Errorf("%q: decoding should fail with %q: %s", source, expected, decoded)
		}
	}
}

const shapeSource = `
enum Kind : u8 {
	Circle = 1,
	Rect = 2 ... 3,
	Other,
};

struct Header {
	u8 version, flags;
	u24 magic;
	Kind kind;
};

struct Payload {
	u16 count;
	u16 items[parent.limit];
};

struct Shape {
	Header header;
	u8 limit;
	if (header.kind == Kind::Circle) {
		u16 radius;
	} else if (header.kind == Kind::Rect) {
		u16 width, height;
	} else {
		u8 raw[limit];
	}
	match (header.version, header.flags) {
		(1, _): { u8 legacy; }
		(2 ... 3, 0 | 1): { u16 modern; }
		(_, _): { u32 future; }
	}
	be u32 checksum [[no_unique_address]];
	u128 wide;
	Payload payload;
};
`

func TestCompileShape(t *testing.T) {
	module, diagnostics := Compile(shapeSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}

	kind := findType(module, "Kind").(*Enum)
	if kind.Members[1].Value != 2 || kind.Members[1].Last != 3 || kind.Members[2].Value != 4 {
		t.Errorf("unexpected enum values: %+v", kind.Members)
	}

	shape := findType(module, "Shape").(*Struct)
	names := []string{}
	for _, field := range shape.Fields {
		names = append(names, field.Name)
	}
	expected := "header limit radius width height raw legacy modern future checksum wide payload"
	if strings.Join(names, " ") != expected {
		t.Errorf("unexpected fields: %v", names)
	}
	if shape.Fields[2].Guard == nil || shape.Fields[1].Guard != nil || !shape.Fields[9].NoUniqueAddress {
		t.Errorf("unexpected guards")
	}

	layout := module.Layout(Targets[0]).Composite(shape)
	if layout.Fields[2].Offset != 7 || layout.Fields[2].Dynamic || !layout.Fields[6].Dynamic {
		t.Errorf("unexpected layout: %+v", layout.Fields)
	}
	if layout.Fields[0].Type.Size != 6 {
		t.Errorf("Header should be 6 bytes, got %d", layout.Fields[0].Type.Size)
	}
}

const namespacedSource = `
namespace game {
	enum Team : u8 { Red, Blue };

	namespace math {
		struct Vec2 { float x; float y; };
	};

	struct Unit {
		Team team;
		math::Vec2 position;
		Unit *leader;
	};

	using Squad = Unit;
};

struct World {
	game::Unit units[2];
	game::Team winner;
};
`

func TestCompileNamespaces(t *testing.T) {
	module, diagnostics := Compile(namespacedSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	names := []string{}
	for _, t := range module.Types {
		names = append(names, t.TypeName())
	}
	if strings.Join(names, " ") != "game::Team game::math::Vec2 game::Unit game::Squad World" {
		t.Errorf("unexpected names: %v", names)
	}

	js := EmitJavaScript(module, "ns.pat")
	for _, expected := range []string{
		"export const game = {};",
		"game.math = {};",
		"game.math.Vec2 = class Vec2 {",
		"new game.math.Vec2(this.$address.add(1), this)",
		"game.Squad = game.Unit;",
		"export class World {",
	} {
		if !strings.Contains(js, expected) {
			t.Errorf("missing %q in:\n%s", expected, js)
		}
	}

	declarations := EmitDeclarations(module, "ns.pat")
	for _, expected := range []string{
		"export declare namespace game {\n",
		"    namespace math {\n",
		"        export class Vec2 {",
		"        readonly position: game.math.Vec2;",
		"        get leader(): game.Unit | null;",
		"    export const Squad: typeof game.Unit;",
		"\nexport declare class World {",
		"    readonly units: game.Unit[];",
	} {
		if !strings.Contains(declarations, expected) {
			t.Errorf("missing %q in:\n%s", expected, declarations)
		}
	}
}

func findType(module *Module, name string) NamedType {
	for _, t := range module.Types {
		if t.TypeName() == name {
			return t
		}
	}
	return nil
}

func TestSizeOfFieldInArrayLength(t *testing.T) {
	module, diagnostics := Compile("struct A { u8 header[4]; u8 body[sizeof(header) * 2]; u8 tail[sizeof(u32)]; };")
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	js := EmitJavaScript(module, "a.pat")
	if !strings.Contains(js, "$readArray(this.$address.add(4), 8, 1") || !strings.Contains(js, "$readArray(this.$address.add(12), 4, 1") {
		t.Errorf("unexpected output:\n%s", js)
	}
}

type sourceMap map[string]string

func (m sourceMap) Resolve(importer string, path string) (Source, error) {
	for _, candidate := range []string{path, path + ".pat", path + ".hexpat"} {
		if text, exists := m[candidate]; exists {
			return Source{Path: candidate, Text: text}, nil
		}
	}
	return Source{}, fmt.Errorf("cannot resolve %s from %s", path, importer)
}

func TestIncludesAndImports(t *testing.T) {
	files := sourceMap{
		"types/geometry.pat": `
#pragma abi native
namespace auto geometry {
	struct Vec2 { float x; float y; };
};
`,
		"types/colors.hexpat": `
#pragma endian big
enum Color : u16 { Red = 1, Green = 2 };
`,
		"main.hexpat": `
#include "types/colors"
import types.geometry as geo;

struct Sprite {
	Color color;
	geo::Vec2 position;
};
`,
	}
	module, diagnostics := CompileSource(Source{Path: "main.hexpat", Text: files["main.hexpat"]}, files)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	if strings.Join(module.Files, " ") != "types/colors.hexpat types/geometry.pat main.hexpat" {
		t.Errorf("unexpected files: %v", module.Files)
	}
	names := []string{}
	for _, t := range module.Types {
		names = append(names, t.TypeName())
	}
	if strings.Join(names, " ") != "Color geo::Vec2 Sprite" {
		t.Errorf("unexpected types: %v", names)
	}
	color := findType(module, "Color").(*Enum)
	if color.Underlying.Order != BigEndian {
		t.Errorf("Color should honour its own file's byte order")
	}
	sprite := findType(module, "Sprite").(*Struct)
	layout := module.Layout(Targets[0])
	if layout.Composite(sprite).Fields[1].Offset != 2 || layout.Of(findType(module, "geo::Vec2")).Align != 4 {
		t.Errorf("Sprite is packed while Vec2 keeps its own file's native alignment: %+v", layout.Composite(sprite).Fields)
	}

	_, diagnostics = CompileSource(Source{Path: "main.hexpat", Text: "import missing;\n"}, files)
	if len(diagnostics) != 1 || !strings.Contains(diagnostics[0].Message, "cannot resolve missing") {
		t.Errorf("unexpected diagnostics: %v", diagnostics)
	}

	_, diagnostics = Compile("#include \"x.pat\"\n")
	if len(diagnostics) != 1 || diagnostics[0].Message != "includes and imports are only available when compiling a file" {
		t.Errorf("unexpected diagnostics: %v", diagnostics)
	}

	_, diagnostics = CompileSource(Source{Path: "main.hexpat", Text: "import * from types.geometry;\n"}, files)
	if len(diagnostics) != 1 || diagnostics[0].Message != "import * requires an alias" {
		t.Errorf("unexpected diagnostics: %v", diagnostics)
	}
}

var iconFiles = sourceMap{
	"bmp.hexpat": `
struct BitmapHeader {
	char signature[2];
	u32 fileSize;
};

BitmapHeader header @ 0x00;
u8 pixels[header.fileSize - sizeof(header)] @ $;
`,
	"icon.hexpat": `
import * from bmp as Bitmap;

enum ImageType : u16 { Icon = 1, Cursor = 2 };

struct IconDir {
	u16 reserved [[hidden]];
	ImageType type;
	u16 count;
};

struct Entry {
	u8 width, height;
	u16 dataSize;
	u16 dataOffset;
	Bitmap image @ dataOffset;
	u128 span = $ - addressof(this);
	if (parent.dir.type == ImageType::Cursor) {
		u16 hotspot;
	}
	u8 tail[while(std::mem::read_unsigned($, 1) != 0xff)];
	u8 terminator;
};

IconDir dir @ 0x00;
Entry entries[dir.count] @ $;
u32 magic @ sizeof(dir) + 2;
`,
}

const iconSource = "icon.hexpat"

func TestCompileIcon(t *testing.T) {
	module, diagnostics := CompileSource(Source{Path: iconSource, Text: iconFiles[iconSource]}, iconFiles)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	names := []string{}
	for _, t := range module.Types {
		names = append(names, t.TypeName())
	}
	if strings.Join(names, " ") != "Bitmap::BitmapHeader Bitmap ImageType IconDir Entry Icon" || module.Root.Name != "Icon" {
		t.Errorf("unexpected types: %v", names)
	}
	if !findType(module, "IconDir").(*Struct).Simple || findType(module, "Entry").(*Struct).Simple || findType(module, "Bitmap").(*Struct).Simple {
		t.Errorf("unexpected classification")
	}
}

const templateSource = `
struct Vector<T, auto Count> {
	T items[Count];
};

struct Sized<T> {
	u8 length;
	T data[length];
};

using Bytes = Vector<u8, 4>;

struct Packet {
	u8 tag;
	Bytes header;
	Vector<u16, 2> pair;
	Sized<u16> body;
	u8 trailerCount;
	Vector<u8, trailerCount> trailer;
	u8 last[while(!std::mem::eof())];
};

Packet packet @ 0x00;
`

func TestTemplates(t *testing.T) {
	module, diagnostics := CompileSource(Source{Path: "packet.hexpat", Text: templateSource}, nil)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	names := []string{}
	for _, t := range module.Types {
		names = append(names, t.TypeName())
	}
	if strings.Join(names, " ") != "Bytes Packet Vector<u8, 4> Vector<u16, 2> Sized<u16> Vector<u8, ?field trailerCount> PacketRoot" {
		t.Errorf("unexpected types: %v", names)
	}
	if !findType(module, "Vector<u8, 4>").(*Struct).Simple || findType(module, "Vector<u8, ?field trailerCount>").(*Struct).Simple {
		t.Errorf("unexpected classification")
	}

	data := []byte{7, 1, 2, 3, 4, 0x34, 0x12, 0x78, 0x56, 2, 0xaa, 0xbb, 0xcc, 0xdd, 1, 9, 0x42}
	root := Decode(module, Targets[0], module.Root, data, 0)
	rendered := root.String()
	for _, expected := range []string{
		"Bytes header @ 0x1",
		"Vector<u16, 2> pair @ 0x5",
		"u16  @ 0x5 = 4660",
		"Sized<u16> body @ 0x9",
		"u16[...] data @ 0xa",
		"Vector<u8, 1> trailer @ 0xf",
		"u8  @ 0xf = 9",
		"u8[while] last @ 0x10",
		"u8  @ 0x10 = 66",
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("missing %q in:\n%s", expected, rendered)
		}
	}
	if root.Error != "" || root.Truncated || *root.Size != 17 {
		t.Errorf("unexpected root: %+v\n%s", root, rendered)
	}

	js := EmitJavaScript(module, "packet.hexpat")
	for _, expected := range []string{
		"export class Vector_u8_4 {",
		"export const Bytes = Vector_u8_4;",
		"Vector_u8_field_trailerCount.$parse($at, $env, $this, [$this.trailerCount])",
		"let $v_Count = $args[0];",
	} {
		if !strings.Contains(js, expected) {
			t.Errorf("missing %q in:\n%s", expected, js)
		}
	}
	declarations := EmitDeclarations(module, "packet.hexpat")
	if !strings.Contains(declarations, "header: Vector_u8_4.Parsed;") || !strings.Contains(declarations, "trailer: Vector_u8_field_trailerCount.Parsed;") {
		t.Errorf("unexpected declarations:\n%s", declarations)
	}
}

const dynamicBitfieldSource = `
bitfield Header<auto Wide> {
	version : 4;
	bool extended : 1;
	if (extended) {
		u8 extra;
		signed delta : 4;
	} else {
		padding : 3;
	}
	kind : Wide;
};

union Payload {
	u8 first;
	if (first == 1) {
		u16 word;
	} else {
		u32 dword;
	}
};

struct Record {
	Header<4> header;
	Payload payload;
	u8 rest[];
};

Record record @ 0x00;
`

func TestDynamicBitfieldsAndUnions(t *testing.T) {
	module, diagnostics := CompileSource(Source{Path: "record.hexpat", Text: dynamicBitfieldSource}, nil)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	header := findType(module, "Header<4>")
	if header == nil || header.(*Bitfield).Simple || findType(module, "Payload").(*Union).Simple {
		t.Fatalf("unexpected classification: %v", header)
	}

	data := []byte{0x13, 0x42, 0xf5, 1, 0x34, 0x12, 9, 8}
	root := Decode(module, Targets[0], module.Root, data, 0)
	rendered := root.String()
	for _, expected := range []string{
		": 4 version @ 0x0 = 3",
		"bool : 1 extended @ 0x0 = true",
		"u8 extra @ 0x1 = 66",
		"signed : 4 delta @ 0x2 = 5",
		": 4 kind @ 0x2 = 15",
		"u16 word @ 0x3 = 13313",
		"u8[while] rest @ 0x5",
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("missing %q in:\n%s", expected, rendered)
		}
	}
	if root.Error != "" || root.Truncated || *root.Size != 8 {
		t.Errorf("unexpected root: %+v\n%s", root, rendered)
	}
}

func TestIncludesShareMacros(t *testing.T) {
	files := sourceMap{
		"main.hexpat": "#define USE_LIB\n#include \"lib\"\nu8 tail @ LIB_SIZE;\n",
		"lib.pat":     "#define LIB_SIZE 4\nstruct Lib { u8 data[LIB_SIZE]; };\n#ifndef USE_LIB\nLib lib @ 0;\n#endif\n",
	}
	placements := func() string {
		module, diagnostics := CompileSource(Source{Path: "main.hexpat", Text: files["main.hexpat"]}, files)
		if len(diagnostics) > 0 {
			t.Fatal(diagnostics)
		}
		var names []string
		for _, field := range Decode(module, Targets[0], module.Root, make([]byte, 16), 0).Fields {
			names = append(names, fmt.Sprintf("%s@%d", field.Name, field.Offset))
		}
		return strings.Join(names, " ")
	}
	if got := placements(); got != "tail@4" {
		t.Errorf("the includer's macros should reach the included file and back: %s", got)
	}
	files["lib.pat"] = strings.Replace(files["lib.pat"], "LIB_SIZE 4", "LIB_SIZE 8", 1)
	if got := placements(); got != "tail@8" {
		t.Errorf("a change to an included file's macros should reach the includer: %s", got)
	}
}

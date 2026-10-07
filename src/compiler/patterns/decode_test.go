package patterns

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

const playerDeclarationLine = 23

func TestDescribeWithoutTypes(t *testing.T) {
	description := DescribeSource("namespace shared {\n}\n", Targets[0])
	if !strings.Contains(description, `"types":[]`) {
		t.Fatalf("types should be an empty array: %s", description)
	}
}

func TestDescribePlayer(t *testing.T) {
	description := DescribeSource(playerSource, Targets[0])
	var parsed Description
	if err := json.Unmarshal([]byte(description), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Diagnostics) != 0 || len(parsed.Types) != 5 {
		t.Fatalf("unexpected description: %s", description)
	}
	player := parsed.Types[3]
	if player.Name != "Player" || player.Size != nil || player.Align != 8 {
		t.Errorf("unexpected Player: %+v", player)
	}
	if player.File != "" || player.Line != playerDeclarationLine {
		t.Errorf("Player should be declared in the main source at line %d: %+v", playerDeclarationLine, player)
	}
	if *player.Fields[5].Offset != 12 || player.Fields[5].Type.Display != "Vec3" {
		t.Errorf("unexpected position field: %+v", player.Fields[5])
	}
	if player.Fields[10].Offset != nil {
		t.Errorf("checksum should have no static offset")
	}
	if parsed.Types[0].Values[2].Value != 6 || parsed.Types[1].Bits[2].Offset != 8 {
		t.Errorf("unexpected enum or bitfield: %+v %+v", parsed.Types[0], parsed.Types[1])
	}

	broken := DescribeSource("struct A { auto a @ 0; };", Targets[0])
	if !strings.Contains(broken, `"message":"auto is not supported"`) {
		t.Errorf("unexpected diagnostics: %s", broken)
	}
}

func TestDecodePlayer(t *testing.T) {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], 94)
	binary.LittleEndian.PutUint16(data[4:], 7)
	binary.BigEndian.PutUint16(data[6:], 1337)
	data[8] = 6
	binary.LittleEndian.PutUint16(data[10:], 0x191)
	binary.LittleEndian.PutUint32(data[12:], math.Float32bits(1.5))
	copy(data[24:], "Bob\x00")
	binary.LittleEndian.PutUint64(data[40:], 0x1000)
	data[48] = 3
	copy(data[49:], []byte{10, 20, 30})
	binary.LittleEndian.PutUint32(data[52:], 0xdeadbeef)

	encoded, err := DecodeSource(playerSource, "Player", data, 0x1000, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	var value DecodedValue
	if err := json.Unmarshal([]byte(encoded), &value); err != nil {
		t.Fatal(err)
	}

	expectations := map[string]any{
		"hitpoints":      float64(94),
		"stamina":        float64(1337),
		"class":          float64(6),
		"name":           "Bob",
		"next":           "0x1000",
		"inventoryCount": float64(3),
		"checksum":       float64(0xdeadbeef),
	}
	for _, field := range value.Fields {
		if expected, isExpected := expectations[field.Name]; isExpected && field.Value != expected {
			t.Errorf("%s = %v, expected %v", field.Name, field.Value, expected)
		}
	}
	if value.Fields[3].Label != "Rogue" || value.Fields[4].Fields[2].Value != true || value.Fields[5].Fields[0].Value != 1.5 {
		t.Errorf("unexpected nested values:\n%s", value.String())
	}
	if *value.Size != 56 || value.Fields[10].Offset != 52 || len(value.Fields[9].Elements) != 3 {
		t.Errorf("unexpected layout:\n%s", value.String())
	}

	short, err := DecodeSource(playerSource, "Player", data[:20], 0x1000, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(short, `"truncated":true`) {
		t.Errorf("expected truncation: %s", short)
	}

	if _, err := DecodeSource(playerSource, "Nope", data, 0, Targets[0], nil); err == nil || err.Error() != "unknown type Nope" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeMatch(t *testing.T) {
	const source = `
struct Tagged {
	u8 kind;
	match (kind) {
		(_): u8 fallback;
		(7): u8 seven;
		(9): u8 nine;
		(8 ... 9): u8 eightOrNine;
	}
};
`
	expectations := map[byte]string{7: `"name":"seven"`, 1: `"name":"fallback"`, 9: "ambiguous match"}
	for kind, expected := range expectations {
		decoded, err := DecodeSource(source, "Tagged", []byte{kind, 0}, 0, Targets[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(decoded, expected) {
			t.Errorf("kind %d should decode with %s: %s", kind, expected, decoded)
		}
	}
}

func TestDecodeShape(t *testing.T) {
	data := []byte{2, 1, 0xaa, 0xbb, 0xcc, 2, 3, 40, 0, 50, 0, 0x10, 0x00, 0xde, 0xad, 0xbe, 0xef}
	data = append(data, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11)
	data = append(data, 2, 0, 7, 0, 8, 0, 9, 0)

	encoded, err := DecodeSource(shapeSource, "Shape", data, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	var value DecodedValue
	if err := json.Unmarshal([]byte(encoded), &value); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, field := range value.Fields {
		names = append(names, field.Name)
	}
	if strings.Join(names, " ") != "header limit width height modern checksum wide payload" {
		t.Errorf("unexpected fields: %v\n%s", names, value.String())
	}
	if value.Fields[0].Fields[3].Label != "Rect" || value.Fields[4].Value != float64(16) || value.Fields[5].Value != float64(0xdeadbeef) {
		t.Errorf("unexpected values:\n%s", value.String())
	}
	if *value.Size != 37 || len(value.Fields[7].Fields[1].Elements) != 3 {
		t.Errorf("unexpected layout:\n%s", value.String())
	}
}

func iconData() []byte {
	data := []byte{0, 0, 2, 0, 1, 0}
	data = append(data, 8, 8, 5, 0, 21, 0)
	data = append(data, 3, 0)
	data = append(data, 0x11, 0x22, 0xff)
	data = append(data, 0xde, 0xad, 0xbe, 0xef)
	data = append(data, 'B', 'M', 8, 0, 0, 0, 7, 9)
	return data
}

func TestDecodeIcon(t *testing.T) {
	module, diagnostics := CompileSource(Source{Path: iconSource, Text: iconFiles[iconSource]}, iconFiles)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	value := Decode(module, Targets[0], module.Root, iconData(), 0x1000)
	rendered := value.String()
	for _, expected := range []string{
		"IconDir dir @ 0x1000",
		"ImageType type @ 0x1002 = 2 (Cursor)",
		"Entry[...] entries @ 0x1006",
		"Bitmap image @ 0x1015",
		"BitmapHeader header @ 0x1015",
		"u8[...] pixels @ 0x101b",
		"u32 fileSize @ 0x1017 = 8",
		"u16 hotspot @ 0x100c = 3",
		"u8[while] tail @ 0x100e",
		"u8 terminator @ 0x1010 = 255",
		"u32 magic @ 0x1008",
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("missing %q in:\n%s", expected, rendered)
		}
	}
	if *value.Size != 12 || value.Truncated {
		t.Errorf("unexpected root: size %v truncated %v\n%s", *value.Size, value.Truncated, rendered)
	}
}

const sectionsSource = `
import std.mem;
struct Header { u16 magic; u16 len; };
struct Blob {
    u8 raw[4];
    std::mem::Section sec = std::mem::create_section("copy");
    std::mem::set_section_size(sec, 8);
    std::mem::copy_value_to_section(raw, sec, 2);
    Header header @ 2 in sec;
    u16 peek = std::mem::read_unsigned(2, 2, std::mem::Endian::Native, sec) [[export]];
};
fn to_float(u32 bits) {
    std::mem::Reinterpreter<u32, float> converter;
    converter.from_value = bits;
    return converter.to_value;
};
struct Root {
    Blob blob;
    u32 bits;
    float f = to_float(bits) [[export]];
    u32 again [[format("to_float")]];
};
Root root @ 0;
`

var sectionsData = []byte{0x34, 0x12, 0x02, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x80, 0x3f}

func TestDecodeSections(t *testing.T) {
	module, diagnostics := Compile(sectionsSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	root := Decode(module, Targets[0], module.Root, sectionsData, 0x1000).Fields[0]
	blob := root.Fields[0]
	header := blob.Fields[1]
	if header.Section != 1 || header.Offset != 2 || header.Fields[0].Value != integerJSON(0x1234, false) || header.Fields[1].Value != integerJSON(2, false) {
		t.Errorf("unexpected header placed in a section: %s", header)
	}
	if blob.Fields[2].Value != integerJSON(0x1234, false) {
		t.Errorf("unexpected explicit section read: %s", blob.Fields[2])
	}
	if root.Fields[2].Value != 1.0 || root.Fields[3].Formatted != "1" {
		t.Errorf("unexpected reinterpreted values: %s %s", root.Fields[2], root.Fields[3])
	}
}

const inputsSource = `
u32 scale in = 1;
str label in = "none";
struct Sample {
    u8 raw;
    u32 scaled = raw * scale [[export]];
    str name = label [[export]];
};
Sample sample @ 0;
`

func TestDecodeInputs(t *testing.T) {
	module, diagnostics := Compile(inputsSource)
	if len(diagnostics) > 0 {
		t.Fatal(diagnostics)
	}
	description := DescribeSource(inputsSource, Targets[0])
	if !strings.Contains(description, `"inputs":[{"name":"scale","type":{"kind":"primitive","display":"u32"`) || !strings.Contains(description, `{"name":"label"}`) {
		t.Errorf("unexpected inputs: %s", description)
	}
	defaults := Decode(module, Targets[0], module.Root, []byte{7}, 0).Fields[0]
	if defaults.Fields[1].Value != integerJSON(7, true) || defaults.Fields[2].Value != "none" {
		t.Errorf("unexpected defaults: %s", defaults)
	}
	provided := DecodeWith(module, Targets[0], module.Root, []byte{7}, 0, map[string]any{"scale": 3.0, "label": "given"}).Fields[0]
	if provided.Fields[1].Value != integerJSON(21, true) || provided.Fields[2].Value != "given" {
		t.Errorf("unexpected inputs: %s", provided)
	}
}

func TestDecodeBitfieldMemberPositions(t *testing.T) {
	module, diagnostics := Compile(`
bitfield Flags {
    low : 4;
    wide : 8;
    high : 4;
};
`)
	if len(diagnostics) != 0 {
		t.Fatal(diagnostics)
	}
	value := Decode(module, Targets[0], module.Types[0], []byte{0x21, 0x43}, 0x1000)
	for i, expected := range []struct {
		bitOffset, bits, offset, size int
	}{{0, 4, 0, 1}, {4, 8, 0, 2}, {12, 4, 1, 1}} {
		field := value.Fields[i]
		if field.BitOffset == nil || *field.BitOffset != expected.bitOffset || field.Bits != expected.bits ||
			field.Offset != expected.offset || *field.Size != expected.size {
			t.Errorf("%s: unexpected placement %+v", field.Name, field)
		}
	}
}

func TestDecodeEnumOverEncodedValue(t *testing.T) {
	const source = `
fn varint_value(ref auto value) {
	return value.bytes[0] & 0x7f | (value.bytes[1] & 0x7f) << 7;
};

struct VarInt {
	u8 bytes[2];
} [[transform("varint_value")]];

enum Flag : VarInt {
	Small = 0x05,
	Large = 0x105,
};

struct Header {
	Flag flag;
	u8 after;
};
`
	decoded, err := DecodeSource(source, "Header", []byte{0x85, 0x02, 0x2a}, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decoded, `"label":"Large"`) || !strings.Contains(decoded, `"name":"after","type":"u8","address":"0x2","offset":2`) {
		t.Errorf("the enum should read through VarInt and take its size: %s", decoded)
	}
}

func TestDecodeTemplateFieldArgumentAcrossInstantiations(t *testing.T) {
	const source = `
struct Payload<auto Size> {
	u8 data[Size];
};
struct Record<Addr> {
	u8 size;
	u8 tag = std::mem::read_unsigned($, 1);
	Payload<size> payload;
};
struct File {
	u8 wide;
	if (wide == 1) {
		Record<u32> record;
	} else {
		Record<u64> record;
	}
};
`
	for _, wide := range []byte{1, 2} {
		decoded, err := DecodeSource(source, "File", []byte{wide, 2, 0xaa, 0xbb}, 0, Targets[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(decoded, "is not available") || !strings.Contains(decoded, `"count":2`) {
			t.Errorf("wide=%d: the template argument should bind in every instantiation: %s", wide, decoded)
		}
	}
}

func TestDecodeEnumsKeepTheirNames(t *testing.T) {
	const source = `
enum Kind : u8 {
	Circle = 1,
	Square = 2,
};
bitfield Packed {
	Kind kind : 4;
	padding : 4;
};
fn describe(ref auto shape) {
	return std::format("{} {}", shape.inner.kind, std::core::formatted_value(shape.packed.kind));
};
struct Inner {
	Kind kind;
};
struct Shape {
	Inner inner;
	Packed packed;
	str nested = std::format("{}", inner.kind) [[export]];
	str bits = std::format("{}", packed.kind) [[export]];
	str formatted = std::core::formatted_value(packed.kind) [[export]];
} [[format("describe")]];
struct Shapes {
	Shape shapes[1];
};
`
	decoded, err := DecodeSource(source, "Shapes", []byte{2, 1}, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	var value DecodedValue
	if err := json.Unmarshal([]byte(decoded), &value); err != nil {
		t.Fatal(err)
	}
	shape := value.Fields[0].Elements[0]
	if shape.Formatted != "Kind::Square Kind::Circle" {
		t.Errorf("a ref parameter should see enum names: %q", shape.Formatted)
	}
	if shape.Fields[2].Value != "Kind::Square" || shape.Fields[3].Value != "Kind::Circle" || shape.Fields[4].Value != "Kind::Circle" {
		t.Errorf("nested and bitfield members should keep their enum names: %s", shape)
	}
}

func TestDecodeFormattedValueOfScalar(t *testing.T) {
	const source = `
fn seconds(u32 millis) {
	return std::format("{}s", millis / 1000);
};
bitfield Prot {
	bool read : 1;
	bool write : 1;
	padding : 6;
} [[format("describeProt")]];
fn describeProt(ref auto prot) {
	return prot.read ? "r" : "-";
};
struct Timing {
	u32 elapsed [[format("seconds")]];
	Prot prot;
	str summary = std::format("{} {}", std::core::formatted_value(elapsed), std::core::formatted_value(prot)) [[export]];
};
`
	decoded, err := DecodeSource(source, "Timing", []byte{0xd0, 0x07, 0, 0, 1}, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decoded, `"value":"2s r"`) {
		t.Errorf("formatted_value should format scalar and bitfield fields: %s", decoded)
	}
}

func TestDecodeArrayIndexInsideElement(t *testing.T) {
	const source = `
struct Entry {
	u8 value;
	u32 index = std::core::array_index() [[export]];
};
struct Table {
	Entry entries[3];
};
`
	decoded, err := DecodeSource(source, "Table", []byte{10, 20, 30}, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	var value DecodedValue
	if err := json.Unmarshal([]byte(decoded), &value); err != nil {
		t.Fatal(err)
	}
	for i, element := range value.Fields[0].Elements {
		if element.Fields[1].Value != float64(i) {
			t.Errorf("element %d reports index %v", i, element.Fields[1].Value)
		}
	}
}

func TestDecodeTemplateLocalArgumentAcrossInstantiations(t *testing.T) {
	const source = `
struct Leaf<auto Kind> {
	u8 value;
	str summary = std::format("kind {}", Kind) [[export]];
};
struct First<auto Kind> {
	Leaf<Kind> leaf;
};
struct Second<auto Kind> {
	Leaf<Kind> leaf;
};
struct Top {
	u8 kind;
	First<kind> first;
	Second<kind + 1> second;
};
`
	decoded, err := DecodeSource(source, "Top", []byte{7, 1, 2}, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decoded, `"value":"kind 7"`) || !strings.Contains(decoded, `"value":"kind 8"`) {
		t.Errorf("each instantiation should see its own argument: %s", decoded)
	}
}

func TestDecodeRefParametersReceivePatterns(t *testing.T) {
	const source = `
bitfield Bits {
	bool read : 1;
	bool write : 1;
	padding : 6;
};
fn describeBits(ref auto bits) {
	return (bits.read ? "r" : "-") + (bits.write ? "w" : "-");
};
fn describePair(ref auto pair) {
	return std::format("{}/{}", pair.a, pair.b);
};
struct Pair {
	u8 a;
	u8 b;
};
struct Root {
	Bits bits;
	Pair pair;
	str viaBitfield = describeBits(bits) [[export]];
	str viaStruct = describePair(pair) [[export]];
};
`
	decoded, err := DecodeSource(source, "Root", []byte{3, 5, 6}, 0, Targets[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decoded, `"value":"rw"`) || !strings.Contains(decoded, `"value":"5/6"`) {
		t.Errorf("ref parameters should receive the pattern: %s", decoded)
	}
}

package patterns

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func EmitJavaScript(module *Module, sourceName string) string {
	e := &jsEmitter{
		module:  module,
		layouts: moduleLayouts(module),
		helpers: map[string]bool{},
	}
	var body strings.Builder
	for _, f := range module.Functions {
		e.emitFunction(&body, f)
	}
	if module.DynamicAttributes {
		e.emitNamedFunctions(&body, module)
	}
	for _, t := range module.TypesWithAliasesLast() {
		switch t := t.(type) {
		case *Struct:
			e.emitComposite(&body, t.Name, allFields(t), t)
		case *Union:
			e.emitComposite(&body, t.Name, t.Fields, t)
		case *Enum:
			e.emitEnum(&body, t)
		case *Bitfield:
			e.emitBitfield(&body, t)
		case *Alias:
			e.emitAlias(&body, t)
		}
	}
	if module.Root != nil {
		fmt.Fprintf(&body, "export function parse(address, size, inputs) { return %s.parse(address, size, inputs); }\n", jsRef(module.Root.Name))
	}

	var out strings.Builder
	fmt.Fprintf(&out, "// Generated from %s by frida-compile. Do not edit.\n", sourceName)
	if e.usesTarget {
		out.WriteString("const $target = Process.pointerSize === 8 ? 0 : (Process.arch === \"ia32\" && Process.platform !== \"windows\") ? 2 : 1;\n")
	}
	if e.helpers["$littleEndian"] {
		out.WriteString("const $littleEndian = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;\n")
	}
	for _, name := range e.sortedHelpers() {
		out.WriteString(helperSource(name))
	}
	emitNamespaceObjects(&out, module)
	out.WriteString(body.String())
	return out.String()
}

func (e *jsEmitter) emitNamedFunctions(out *strings.Builder, module *Module) {
	out.WriteString("const $named = {\n")
	for _, f := range module.Functions {
		fmt.Fprintf(out, "    %q: %s,\n", f.Name, functionName(f))
	}
	names := make([]string, 0, len(builtins))
	for name := range builtins {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(out, "    %q: ($env, $this, value) => %s($env, value),\n", name, e.helper(builtins[name].js))
	}
	out.WriteString("};\n")
}

func emitNamespaceObjects(out *strings.Builder, module *Module) {
	declared := map[string]bool{}
	for _, t := range module.Types {
		declared[t.TypeName()] = true
	}
	for _, t := range module.Types {
		segments := scopeSegments(t.TypeName())
		for depth := 1; depth < len(segments); depth++ {
			path := strings.Join(segments[:depth], "::")
			if declared[path] {
				continue
			}
			declared[path] = true
			if depth == 1 {
				fmt.Fprintf(out, "export const %s = {};\n", path)
			} else {
				fmt.Fprintf(out, "%s = {};\n", jsRef(path))
			}
		}
	}
}

func jsRef(name string) string {
	segments := scopeSegments(name)
	for i, segment := range segments {
		segments[i] = identifierName(segment)
	}
	return strings.Join(segments, ".")
}

func shortName(name string) string {
	segments := scopeSegments(name)
	return identifierName(segments[len(segments)-1])
}

func isNamespaced(name string) bool {
	return len(scopeSegments(name)) > 1
}

func scopeSegments(name string) []string {
	head, arguments := name, ""
	if open := strings.IndexByte(name, '<'); open != -1 {
		head, arguments = name[:open], name[open:]
	}
	segments := strings.Split(head, "::")
	segments[len(segments)-1] += arguments
	return segments
}

var nonIdentifierPattern = regexp.MustCompile(`[^A-Za-z0-9_]+`)

func identifierName(segment string) string {
	name := strings.TrimRight(nonIdentifierPattern.ReplaceAllString(segment, "_"), "_")
	if reservedNames[name] {
		return name + "$"
	}
	return name
}

var reservedNames = map[string]bool{
	"Object": true, "Array": true, "String": true, "Number": true, "Boolean": true, "BigInt": true, "Symbol": true, "Math": true,
	"JSON": true, "Date": true, "Map": true, "Set": true, "WeakMap": true, "WeakSet": true, "Promise": true, "Proxy": true,
	"Reflect": true, "Error": true, "RangeError": true, "TypeError": true, "Function": true, "Infinity": true, "NaN": true,
	"undefined": true, "globalThis": true, "Process": true, "Memory": true, "NativePointer": true, "ptr": true, "NULL": true,
	"Int64": true, "UInt64": true, "console": true, "parse": true,
	"break": true, "case": true, "catch": true, "class": true, "const": true, "continue": true, "debugger": true, "default": true,
	"delete": true, "do": true, "else": true, "enum": true, "export": true, "extends": true, "false": true, "finally": true,
	"for": true, "function": true, "if": true, "import": true, "in": true, "instanceof": true, "new": true, "null": true,
	"return": true, "super": true, "switch": true, "this": true, "throw": true, "true": true, "try": true, "typeof": true,
	"var": true, "void": true, "while": true, "with": true, "yield": true, "let": true, "static": true, "await": true,
}

func openClass(out *strings.Builder, name string) {
	if isNamespaced(name) {
		fmt.Fprintf(out, "%s = class %s {\n", jsRef(name), shortName(name))
	} else {
		fmt.Fprintf(out, "export class %s {\n", shortName(name))
	}
}

func closeClass(out *strings.Builder, name string) {
	if isNamespaced(name) {
		out.WriteString("};\n")
	} else {
		out.WriteString("}\n")
	}
}

func openConstant(out *strings.Builder, name string) {
	if isNamespaced(name) {
		fmt.Fprintf(out, "%s = ", jsRef(name))
	} else {
		fmt.Fprintf(out, "export const %s = ", shortName(name))
	}
}

func moduleLayouts(module *Module) []*ModuleLayout {
	layouts := make([]*ModuleLayout, len(Targets))
	for i, target := range Targets {
		layouts[i] = module.Layout(target)
	}
	return layouts
}

type jsEmitter struct {
	module     *Module
	layouts    []*ModuleLayout
	helpers    map[string]bool
	usesTarget bool
	parsing    bool
}

type variantTable struct {
	name   string
	keys   []string
	values map[string][]int
}

func (e *jsEmitter) emitComposite(out *strings.Builder, qualifiedName string, fields []*Field, t Type) {
	name := shortName(qualifiedName)
	table := &variantTable{name: "$" + typeKey(t), values: map[string][]int{}}

	var class strings.Builder
	openClass(&class, qualifiedName)
	if hasView(t) {
		c := &compositeEmitter{jsEmitter: e, name: name, t: t, fields: fields, table: table, expressionKeys: map[Value]string{}}
		c.compute()
		fmt.Fprintf(&class, "    static $align = %s;\n", c.table.value("align", c.alignsOfComposite()))
		fmt.Fprintf(&class, "    constructor(address, parent = null) { this.$address = ptr(address); this.$parent = parent; }\n")
		fmt.Fprintf(&class, "    static at(address) { return new %s(address); }\n", name)
		if !c.dynamic {
			fmt.Fprintf(&class, "    static size = %s;\n", c.size)
			fmt.Fprintf(&class, "    get $size() { return %s.size; }\n", name)
		} else {
			fmt.Fprintf(&class, "    get $size() { return %s; }\n", c.size)
		}
		for _, f := range c.entries {
			c.emitAccessors(&class, f)
		}
		c.emitToJSON(&class)
		if !c.dynamic {
			c.emitPattern(&class)
		}
	}
	if !hasView(t) {
		class.WriteString("    static $align = 1;\n")
	}
	e.emitParser(&class, t)
	closeClass(&class, qualifiedName)

	e.emitTable(out, table)
	out.WriteString(class.String())
}

func hasView(t Type) bool {
	switch t := t.(type) {
	case *Struct:
		return t.Simple
	case *Union:
		if !t.Simple {
			return false
		}
		for _, field := range t.Fields {
			if !hasView(field.Type) && !isPlainData(field.Type) {
				return false
			}
		}
		return true
	case *Bitfield:
		return t.Simple
	}
	return true
}

func isPlainData(t Type) bool {
	switch t := Unalias(t).(type) {
	case *Struct:
		return t.Simple
	case *Union:
		return hasView(t)
	case *Array:
		return t.While == nil && isPlainData(t.Element)
	}
	return true
}

func (e *jsEmitter) emitTable(out *strings.Builder, table *variantTable) {
	if len(table.keys) == 0 {
		return
	}
	e.usesTarget = true
	fmt.Fprintf(out, "const %s = [", table.name)
	for i := range Targets {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteString("{ ")
		for j, key := range table.keys {
			if j > 0 {
				out.WriteString(", ")
			}
			fmt.Fprintf(out, "%s: %d", key, table.values[key][i])
		}
		out.WriteString(" }")
	}
	out.WriteString("][$target];\n")
}

func (t *variantTable) value(key string, values []int) string {
	allEqual := true
	for _, v := range values[1:] {
		if v != values[0] {
			allEqual = false
		}
	}
	if allEqual {
		return fmt.Sprintf("%d", values[0])
	}
	if _, present := t.values[key]; !present {
		t.keys = append(t.keys, key)
		t.values[key] = values
	}
	return fmt.Sprintf("%s.%s", t.name, key)
}

type compositeEmitter struct {
	*jsEmitter
	name           string
	t              Type
	fields         []*Field
	table          *variantTable
	entries        []*fieldEntry
	expressionKeys map[Value]string
	dynamic        bool
	size           string
}

type fieldEntry struct {
	field     *Field
	layouts   []FieldLayout
	offset    string
	size      func() string
	guard     string
	dynamic   bool
	accessor  string
	staticOff bool
}

func (c *compositeEmitter) alignsOfComposite() []int {
	values := make([]int, len(c.layouts))
	for i, layout := range c.layouts {
		values[i] = layout.Composite(c.t).Align
	}
	return values
}

func (c *compositeEmitter) compute() {
	composites := make([]*CompositeLayout, len(c.layouts))
	for i, layout := range c.layouts {
		composites[i] = layout.Composite(c.t)
	}
	c.dynamic = c.layouts[0].Of(c.t).Dynamic

	var previous *fieldEntry
	for i, field := range c.fields {
		entry := &fieldEntry{field: field, accessor: field.Name}
		for _, composite := range composites {
			entry.layouts = append(entry.layouts, composite.Fields[i])
		}
		if field.Name == "" {
			entry.accessor = fmt.Sprintf("$field%d", i)
		}
		entry.dynamic = entry.layouts[0].Type.Dynamic
		entry.staticOff = !entry.layouts[0].Dynamic
		if entry.staticOff {
			entry.offset = c.table.value(entry.accessor, offsetsOf(entry.layouts))
		} else {
			entry.offset = fmt.Sprintf("this.$offsetOf_%s()", entry.accessor)
		}
		if !entry.dynamic {
			entry.size = func() string { return c.table.value(entry.accessor+"_size", sizesOf(entry.layouts)) }
		} else {
			entry.size = func() string { return c.dynamicSize(entry) }
		}
		if field.Guard != nil {
			entry.guard = c.expression(field.Guard)
		}
		c.entries = append(c.entries, entry)
		previous = entry
	}

	if !c.dynamic {
		c.size = c.table.value("size", compositeSizes(composites))
		return
	}
	c.size = c.aligned(c.endOf(previous), "align", compositeAligns(composites))
}

func (c *compositeEmitter) endOf(entry *fieldEntry) string {
	if entry == nil {
		return "0"
	}
	if entry.field.NoUniqueAddress {
		return c.endOf(c.previousEntry(entry))
	}
	if entry.guard != "" {
		return fmt.Sprintf("this.$endOf_%s()", entry.accessor)
	}
	return fmt.Sprintf("%s + %s", entry.offset, entry.size())
}

func offsetsOf(layouts []FieldLayout) []int {
	values := make([]int, len(layouts))
	for i, l := range layouts {
		values[i] = l.Offset
	}
	return values
}

func sizesOf(layouts []FieldLayout) []int {
	values := make([]int, len(layouts))
	for i, l := range layouts {
		values[i] = l.Type.Size
	}
	return values
}

func alignsOf(layouts []FieldLayout) []int {
	values := make([]int, len(layouts))
	for i, l := range layouts {
		values[i] = l.Align
	}
	return values
}

func compositeSizes(composites []*CompositeLayout) []int {
	values := make([]int, len(composites))
	for i, c := range composites {
		values[i] = c.Size
	}
	return values
}

func compositeAligns(composites []*CompositeLayout) []int {
	values := make([]int, len(composites))
	for i, c := range composites {
		values[i] = c.Align
	}
	return values
}

func (c *compositeEmitter) dynamicSize(entry *fieldEntry) string {
	address := c.address(entry.offset)
	switch t := Unalias(entry.field.Type).(type) {
	case *Array:
		if t.Length == nil {
			if characterKind(t.Element) == Char16 {
				return c.helper("$cString16Size") + "(" + address + ")"
			}
			return c.helper("$cStringSize") + "(" + address + ")"
		}
		elementSize := c.table.value(entry.accessor+"_stride", c.sizesOfType(t.Element))
		return fmt.Sprintf("(%s) * %s", c.expression(t.Length), elementSize)
	case *Padding:
		return fmt.Sprintf("(%s)", c.expression(t.Size))
	default:
		return fmt.Sprintf("%s.$size", c.viewOf(t, address))
	}
}

func (c *compositeEmitter) sizesOfType(t Type) []int {
	values := make([]int, len(c.layouts))
	for i, layout := range c.layouts {
		values[i] = layout.Of(t).Size
	}
	return values
}

func (c *compositeEmitter) aligned(value string, key string, aligns []int) string {
	allOne := true
	for _, a := range aligns {
		if a != 1 {
			allOne = false
		}
	}
	if allOne {
		return value
	}
	return fmt.Sprintf("%s(%s, %s)", c.helper("$align"), value, c.table.value(key, aligns))
}

func (c *compositeEmitter) address(offset string) string {
	if offset == "0" {
		return "this.$address"
	}
	return fmt.Sprintf("this.$address.add(%s)", offset)
}

func (c *compositeEmitter) emitAccessors(out *strings.Builder, entry *fieldEntry) {
	if !entry.staticOff {
		end := c.endOf(c.previousEntry(entry))
		fmt.Fprintf(out, "    $offsetOf_%s() { return %s; }\n", entry.accessor, c.aligned(end, entry.accessor+"_align", alignsOf(entry.layouts)))
	}
	if entry.guard != "" {
		fmt.Fprintf(out, "    $has_%s() { return (%s) !== 0; }\n", entry.accessor, entry.guard)
		if !entry.field.NoUniqueAddress {
			fmt.Fprintf(out, "    $endOf_%s() { return this.$has_%s() ? %s + %s : %s; }\n", entry.accessor, entry.accessor,
				entry.offset, entry.size(), c.endOf(c.previousEntry(entry)))
		}
	}
	if _, isPadding := entry.field.Type.(*Padding); isPadding || entry.field.Name == "" {
		return
	}
	address := c.address(entry.offset)
	reader := c.reader(entry.field.Type, address, entry)
	writer := c.writer(entry.field.Type, address, "value")
	if entry.guard != "" {
		fmt.Fprintf(out, "    get %s() { return this.$has_%s() ? %s : undefined; }\n", entry.accessor, entry.accessor, reader)
		if writer != "" {
			fmt.Fprintf(out, "    set %s(value) { if (this.$has_%s()) %s; }\n", entry.accessor, entry.accessor, writer)
		}
		return
	}
	fmt.Fprintf(out, "    get %s() { return %s; }\n", entry.accessor, reader)
	if writer != "" {
		fmt.Fprintf(out, "    set %s(value) { %s; }\n", entry.accessor, writer)
	}
}

func (c *compositeEmitter) previousEntry(entry *fieldEntry) *fieldEntry {
	for i, e := range c.entries {
		if e == entry {
			if i == 0 {
				return nil
			}
			return c.entries[i-1]
		}
	}
	panic("unreachable")
}

func (c *compositeEmitter) reader(t Type, address string, entry *fieldEntry) string {
	switch t := t.(type) {
	case *Primitive:
		return c.primitiveReader(t, address)
	case *Enum:
		return c.primitiveReader(t.Underlying, address)
	case *Struct, *Union, *Bitfield:
		return c.viewOf(t, address)
	case *Pointer:
		pointer := c.pointerReader(t, address)
		if isView(t.Target) {
			return fmt.Sprintf("%s(%s, %s)", c.helper("$deref"), pointer, jsRef(Unalias(t.Target).(NamedType).TypeName()))
		}
		return pointer
	case *Array:
		return c.arrayReader(t, address, entry)
	case *Alias:
		return c.reader(t.Target, address, entry)
	}
	panic("unreachable")
}

func (c *compositeEmitter) viewOf(t Type, address string) string {
	return fmt.Sprintf("new %s(%s, this)", jsRef(Unalias(t).(NamedType).TypeName()), address)
}

func isView(t Type) bool {
	switch Unalias(t).(type) {
	case *Struct, *Union, *Bitfield:
		return true
	}
	return false
}

func (e *jsEmitter) primitiveReader(t *Primitive, address string) string {
	switch t.Kind {
	case Bool:
		return fmt.Sprintf("(%s.readU8() !== 0)", address)
	case Char:
		return fmt.Sprintf("String.fromCharCode(%s.readU8())", address)
	case Char16:
		return fmt.Sprintf("String.fromCharCode(%s)", e.scalarReader(&Primitive{Kind: U16, Order: t.Order}, address))
	}
	return e.scalarReader(t, address)
}

func (e *jsEmitter) scalarReader(t *Primitive, address string) string {
	if isOddWidth(t.Kind) {
		return fmt.Sprintf("%s(%s, %d, %s)", e.helper(oddWidthHelperName("$read", t.Kind)), address, t.Kind.Size(), e.orderLiteral(t.Order))
	}
	if t.Order == NativeOrder && e.module.DynamicEndian && t.Kind.Size() > 1 && e.parsing {
		return fmt.Sprintf("%s(%s, %d, %q, $env.littleEndian)", e.helper("$readScalar"), address, t.Kind.Size(), viewMethod(t.Kind, "get"))
	}
	if t.Order == NativeOrder || t.Kind.Size() == 1 {
		return fmt.Sprintf("%s.read%s()", address, nativeAccessorName(t.Kind))
	}
	return fmt.Sprintf("%s(%s)", e.helper(orderedHelperName("$read", t)), address)
}

func viewMethod(kind PrimitiveKind, prefix string) string {
	switch kind {
	case Float:
		return prefix + "Float32"
	case Double:
		return prefix + "Float64"
	case U64:
		return prefix + "BigUint64"
	case S64:
		return prefix + "BigInt64"
	}
	name := prefix + "Uint"
	if kind.IsSigned() {
		name = prefix + "Int"
	}
	return fmt.Sprintf("%s%d", name, kind.Size()*8)
}

func isOddWidth(kind PrimitiveKind) bool {
	switch kind {
	case U24, U48, U96, U128, S24, S48, S96, S128:
		return true
	}
	return false
}

func oddWidthHelperName(prefix string, kind PrimitiveKind) string {
	name := prefix
	if kind.Size() > 6 {
		name += "Big"
	}
	if kind.IsSigned() {
		return name + "Int"
	}
	return name + "Uint"
}

func nativeAccessorName(kind PrimitiveKind) string {
	switch kind {
	case Float:
		return "Float"
	case Double:
		return "Double"
	}
	return strings.ToUpper(kind.Name())
}

func orderedHelperName(prefix string, t *Primitive) string {
	suffix := "LE"
	if t.Order == BigEndian {
		suffix = "BE"
	}
	return prefix + nativeAccessorName(t.Kind) + suffix
}

func (e *jsEmitter) pointerReader(t *Pointer, address string) string {
	if t.Width == nil {
		return fmt.Sprintf("%s.readPointer()", address)
	}
	return fmt.Sprintf("ptr(%s)", e.scalarReader(t.Width, address))
}

func (c *compositeEmitter) arrayReader(t *Array, address string, entry *fieldEntry) string {
	kind := characterKind(t.Element)
	if t.Length == nil {
		if kind == Char16 {
			return fmt.Sprintf("%s.readUtf16String()", address)
		}
		return fmt.Sprintf("%s.readUtf8String()", address)
	}
	length := c.expression(t.Length)
	switch kind {
	case Char:
		return fmt.Sprintf("%s(%s, %s)", c.helper("$readString"), address, length)
	case Char16:
		return fmt.Sprintf("%s(%s, %s)", c.helper("$readString16"), address, length)
	}
	stride := c.table.value(entry.accessor+"_stride", c.sizesOfType(t.Element))
	return fmt.Sprintf("%s(%s, %s, %s, (p) => %s)", c.helper("$readArray"), address, length, stride, c.reader(t.Element, "p", entry))
}

func characterKind(t Type) PrimitiveKind {
	if primitive, isPrimitive := Unalias(t).(*Primitive); isPrimitive && (primitive.Kind == Char || primitive.Kind == Char16) {
		return primitive.Kind
	}
	return -1
}

func (c *compositeEmitter) writer(t Type, address string, value string) string {
	switch t := t.(type) {
	case *Primitive:
		return c.primitiveWriter(t, address, value)
	case *Enum:
		return c.primitiveWriter(t.Underlying, address, value)
	case *Pointer:
		pointer := fmt.Sprintf("%s(%s)", c.helper("$pointerOf"), value)
		if t.Width == nil {
			return fmt.Sprintf("%s.writePointer(%s)", address, pointer)
		}
		if t.Width.Kind.Size() == 8 {
			return c.scalarWriter(t.Width, address, fmt.Sprintf("uint64(%s.toString())", pointer))
		}
		return c.scalarWriter(t.Width, address, pointer+".toUInt32()")
	case *Alias:
		return c.writer(t.Target, address, value)
	}
	return ""
}

func (c *compositeEmitter) primitiveWriter(t *Primitive, address string, value string) string {
	switch t.Kind {
	case Bool:
		return fmt.Sprintf("%s.writeU8(%s ? 1 : 0)", address, value)
	case Char:
		return fmt.Sprintf("%s.writeU8(%s.charCodeAt(0))", address, value)
	case Char16:
		return c.scalarWriter(&Primitive{Kind: U16, Order: t.Order}, address, value+".charCodeAt(0)")
	}
	return c.scalarWriter(t, address, value)
}

func (c *compositeEmitter) scalarWriter(t *Primitive, address string, value string) string {
	if isOddWidth(t.Kind) {
		return fmt.Sprintf("%s(%s, %d, %s, %s)", c.helper("$writeUint"), address, t.Kind.Size(), value, c.orderLiteral(t.Order))
	}
	if t.Order == NativeOrder || t.Kind.Size() == 1 {
		return fmt.Sprintf("%s.write%s(%s)", address, nativeAccessorName(t.Kind), value)
	}
	return fmt.Sprintf("%s(%s, %s)", c.helper(orderedHelperName("$write", t)), address, value)
}

func (c *compositeEmitter) emitToJSON(out *strings.Builder) {
	out.WriteString("    toJSON() {\n        return {")
	first := true
	for _, entry := range c.entries {
		if entry.field.Name == "" || entry.field.Hidden {
			continue
		}
		if !first {
			out.WriteString(",")
		}
		first = false
		value := "this." + entry.accessor
		if pointer, isPointer := Unalias(entry.field.Type).(*Pointer); isPointer {
			value = c.pointerReader(pointer, c.address(entry.offset))
		}
		fmt.Fprintf(out, "\n            %s: %s", entry.accessor, value)
	}
	out.WriteString("\n        };\n    }\n")
}

func (c *compositeEmitter) emitPattern(out *strings.Builder) {
	fmt.Fprintf(out, "    static pattern(fields) {\n")
	fmt.Fprintf(out, "        const bytes = new Array(%s.size).fill(null);\n", c.name)
	fmt.Fprintf(out, "        %s.$encode(bytes, 0, fields);\n", c.name)
	fmt.Fprintf(out, "        return %s(bytes);\n    }\n", c.helper("$matchPattern"))
	fmt.Fprintf(out, "    static $encode(bytes, base, fields) {\n")
	for _, entry := range c.entries {
		if entry.field.Name == "" {
			continue
		}
		fmt.Fprintf(out, "        if (fields.%s !== undefined) %s;\n", entry.accessor, c.encoder(entry.field.Type, "base + "+entry.offset, "fields."+entry.accessor, entry))
	}
	out.WriteString("    }\n")
}

func (c *compositeEmitter) encoder(t Type, offset string, value string, entry *fieldEntry) string {
	switch t := t.(type) {
	case *Primitive:
		return c.primitiveEncoder(t, offset, value)
	case *Enum:
		return c.primitiveEncoder(t.Underlying, offset, value)
	case *Struct, *Union:
		return fmt.Sprintf("%s.$encode(bytes, %s, %s)", jsRef(t.(NamedType).TypeName()), offset, value)
	case *Bitfield:
		return fmt.Sprintf("%s(bytes, %s, %s, %s, %s)", c.helper("$putInteger"), offset, c.sizeLiteral(t, entry), value, c.orderLiteral(t.Order))
	case *Pointer:
		return fmt.Sprintf("%s(bytes, %s, %s, %s(%s), %s)", c.helper("$putInteger"), offset, c.sizeLiteral(t, entry), c.helper("$pointerOf"), value, c.orderLiteral(c.pointerOrder(t)))
	case *Array:
		return c.arrayEncoder(t, offset, value, entry)
	case *Alias:
		return c.encoder(t.Target, offset, value, entry)
	}
	panic("unreachable")
}

func (c *compositeEmitter) pointerOrder(t *Pointer) ByteOrder {
	if t.Width == nil {
		return NativeOrder
	}
	return t.Width.Order
}

func (c *compositeEmitter) sizeLiteral(t Type, entry *fieldEntry) string {
	return c.table.value(entry.accessor+"_size", c.sizesOfType(t))
}

func (c *compositeEmitter) primitiveEncoder(t *Primitive, offset string, value string) string {
	order := c.orderLiteral(t.Order)
	size := t.Kind.Size()
	switch t.Kind {
	case Bool:
		return fmt.Sprintf("%s(bytes, %s, 1, %s ? 1 : 0, %s)", c.helper("$putInteger"), offset, value, order)
	case Char, Char16:
		return fmt.Sprintf("%s(bytes, %s, %d, %s.charCodeAt(0), %s)", c.helper("$putInteger"), offset, size, value, order)
	case Float, Double:
		return fmt.Sprintf("%s(bytes, %s, %d, %s, %s)", c.helper("$putFloat"), offset, size, value, order)
	}
	return fmt.Sprintf("%s(bytes, %s, %d, %s, %s)", c.helper("$putInteger"), offset, size, value, order)
}

func (e *jsEmitter) orderLiteral(order ByteOrder) string {
	switch order {
	case LittleEndian:
		return "true"
	case BigEndian:
		return "false"
	}
	e.helper("$littleEndian")
	return "$littleEndian"
}

func (c *compositeEmitter) arrayEncoder(t *Array, offset string, value string, entry *fieldEntry) string {
	length := c.expression(t.Length)
	switch characterKind(t.Element) {
	case Char:
		return fmt.Sprintf("%s(bytes, %s, %s, %s)", c.helper("$putString"), offset, length, value)
	case Char16:
		return fmt.Sprintf("%s(bytes, %s, %s, %s)", c.helper("$putString16"), offset, length, value)
	}
	stride := c.table.value(entry.accessor+"_stride", c.sizesOfType(t.Element))
	element := c.encoder(t.Element, fmt.Sprintf("%s + i * %s", offset, stride), value+"[i]", entry)
	return fmt.Sprintf("%s.forEach((v, i) => %s)", value, strings.ReplaceAll(element, value+"[i]", "v"))
}

func (c *compositeEmitter) expression(v Value) string {
	if values, isStatic := c.staticValues(v); isStatic {
		return c.table.value(c.expressionKey(v), values)
	}
	switch v := v.(type) {
	case *Constant:
		return fmt.Sprintf("%d", v.Value)
	case *EnumMemberRef:
		return fmt.Sprintf("%d", v.Member.Value)
	case *FieldRef:
		return c.fieldValue(v.Path)
	case *ParentFieldRef:
		return fmt.Sprintf("Number(this%s.%s)", strings.Repeat(".$parent", v.Depth), strings.Join(v.Path, "."))
	case *SizeOf:
		return c.table.value("sizeof_"+typeKey(v.Type), c.sizesOfType(v.Type))
	case *UnaryOp:
		operand := c.expression(v.Operand)
		if v.Operator == "!" {
			return fmt.Sprintf("(%s ? 0 : 1)", operand)
		}
		return fmt.Sprintf("(%s%s)", v.Operator, operand)
	case *BinaryOp:
		return c.binaryExpression(v)
	case *Select:
		return fmt.Sprintf("(%s ? %s : %s)", c.expression(v.Condition), c.expression(v.Then), c.expression(v.Else))
	}
	panic("unreachable")
}

func (c *compositeEmitter) staticValues(v Value) ([]int, bool) {
	if !c.layouts[0].isStatic(v) {
		return nil, false
	}
	values := make([]int, len(c.layouts))
	for i, layout := range c.layouts {
		value, err := layout.Evaluate(v, nil)
		if err != nil {
			return nil, false
		}
		values[i] = int(value)
	}
	return values, true
}

func (c *compositeEmitter) expressionKey(v Value) string {
	if key, known := c.expressionKeys[v]; known {
		return key
	}
	key := fmt.Sprintf("expr%d", len(c.expressionKeys))
	c.expressionKeys[v] = key
	return key
}

func typeKey(t Type) string {
	return identifierPattern.ReplaceAllString(DescribeType(t), "_")
}

var identifierPattern = regexp.MustCompile(`[^A-Za-z0-9_]+`)

func (c *compositeEmitter) fieldValue(path []*Field) string {
	value := "this"
	for _, field := range path {
		value += "." + field.Name
	}
	switch t := Unalias(path[len(path)-1].Type).(type) {
	case *Primitive:
		switch t.Kind {
		case Bool:
			return fmt.Sprintf("(%s ? 1 : 0)", value)
		case U64, S64, U96, S96, U128, S128:
			return fmt.Sprintf("Number(%s)", value)
		}
	case *Enum:
		if t.Underlying.Kind.Size() == 8 {
			return fmt.Sprintf("Number(%s)", value)
		}
	}
	return value
}

func (c *compositeEmitter) binaryExpression(v *BinaryOp) string {
	return binaryJavaScript(v.Operator, c.expression(v.Left), c.expression(v.Right))
}

func binaryJavaScript(operator string, left string, right string) string {
	switch operator {
	case "/":
		return fmt.Sprintf("Math.trunc(%s / %s)", left, right)
	case "==", "!=", "<", ">", "<=", ">=":
		if operator == "==" || operator == "!=" {
			operator += "="
		}
		return fmt.Sprintf("(%s %s %s ? 1 : 0)", left, operator, right)
	case "&&", "||":
		return fmt.Sprintf("((%s %s %s) ? 1 : 0)", left, operator, right)
	case "^^":
		return fmt.Sprintf("((!%s !== !%s) ? 1 : 0)", left, right)
	}
	return fmt.Sprintf("(%s %s %s)", left, operator, right)
}

func (e *jsEmitter) emitEnum(out *strings.Builder, t *Enum) {
	openConstant(out, t.Name)
	out.WriteString("Object.freeze({")
	var ranges []string
	for i, member := range t.Members {
		if i > 0 {
			out.WriteString(",")
		}
		first, last := enumLiteral(member.Value, member.Wide), enumLiteral(member.Last, member.WideLast)
		fmt.Fprintf(out, " %s: %s, %q: %q", member.Name, first, strings.TrimSuffix(first, "n"), member.Name)
		if first != last {
			ranges = append(ranges, fmt.Sprintf("[%s, %s, %q]", first, last, member.Name))
		}
	}
	if len(ranges) > 0 {
		fmt.Fprintf(out, ", $ranges: [%s]", strings.Join(ranges, ", "))
	}
	out.WriteString(" });\n")
}

func enumLiteral(value int64, wide *big.Int) string {
	if wide != nil {
		return wide.String() + "n"
	}
	return strconv.FormatInt(value, 10)
}

func (e *jsEmitter) emitBitfield(out *strings.Builder, t *Bitfield) {
	if !t.Simple {
		openClass(out, t.Name)
		out.WriteString("    static $align = 1;\n")
		e.emitParser(out, t)
		closeClass(out, t.Name)
		return
	}
	size := (t.TotalBits + 7) / 8
	big := size > 6
	order := "true"
	if t.Order == BigEndian {
		order = "false"
	}
	read, extract, insert := "$readUint", "$extractBits", "$insertBits"
	if big {
		read, extract, insert = "$readBigUint", "$extractBigBits", "$insertBigBits"
	}

	name := shortName(t.Name)
	openClass(out, t.Name)
	fmt.Fprintf(out, "    constructor(address, parent = null) { this.$address = ptr(address); this.$parent = parent; }\n")
	fmt.Fprintf(out, "    static at(address) { return new %s(address); }\n", name)
	fmt.Fprintf(out, "    static size = %d;\n", size)
	fmt.Fprintf(out, "    get $size() { return %d; }\n", size)
	fmt.Fprintf(out, "    get $value() { return %s(this.$address, %d, %s); }\n", e.helper(read), size, order)
	fmt.Fprintf(out, "    set $value(value) { %s(this.$address, %d, value, %s); }\n", e.helper("$writeUint"), size, order)
	for _, member := range t.Members {
		if member.Name == "" {
			continue
		}
		shift := t.BitPosition(member.Offset, member.Bits, t.Order == BigEndian)
		if t.Order == BigEndian {
			shift = size*8 - shift - member.Bits
		}
		value := fmt.Sprintf("%s(this.$value, %d, %d)", e.helper(extract), shift, member.Bits)
		if member.Signed {
			if big {
				value = fmt.Sprintf("BigInt.asIntN(%d, %s)", member.Bits, value)
			} else {
				value = fmt.Sprintf("%s(%s, %d)", e.helper("$signExtend"), value, member.Bits)
			}
		}
		if big && member.Bits <= 53 {
			value = fmt.Sprintf("Number(%s)", value)
		}
		stored := "value"
		switch {
		case member.Bool:
			value += " !== 0"
			stored = "(value ? 1 : 0)"
		case big:
			stored = "BigInt(value)"
		}
		fmt.Fprintf(out, "    get %s() { return %s; }\n", member.Name, value)
		fmt.Fprintf(out, "    set %s(value) { this.$value = %s(this.$value, %d, %d, %s); }\n", member.Name, e.helper(insert), shift, member.Bits, stored)
	}
	out.WriteString("    toJSON() {\n        return {")
	first := true
	for _, member := range t.Members {
		if member.Name == "" {
			continue
		}
		if !first {
			out.WriteString(",")
		}
		first = false
		fmt.Fprintf(out, "\n            %s: this.%s", member.Name, member.Name)
	}
	out.WriteString("\n        };\n    }\n")
	fmt.Fprintf(out, "    static parse(address) { const view = new %s(address); return { $address: view.$address, $size: %d, $value: view.$value, ...view.toJSON() }; }\n", name, size)
	e.emitParseBody(out, t)
	closeClass(out, t.Name)
}

func (e *jsEmitter) emitAlias(out *strings.Builder, t *Alias) {
	if named, isNamed := Unalias(t.Target).(NamedType); isNamed {
		openConstant(out, t.Name)
		fmt.Fprintf(out, "%s;\n", jsRef(named.TypeName()))
	}
}

func (e *jsEmitter) helper(name string) string {
	e.helpers[name] = true
	for _, dependency := range helperDependencies[name] {
		e.helper(dependency)
	}
	for _, dependency := range standardHelperDependencies[name] {
		e.helper(dependency)
	}
	return name
}

func (e *jsEmitter) sortedHelpers() []string {
	var names []string
	for name := range e.helpers {
		if _, isSource := helperSources[name]; isSource {
			names = append(names, name)
		} else if _, isStandard := standardHelperSources[name]; isStandard {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func helperSource(name string) string {
	if source, isSource := helperSources[name]; isSource {
		return source
	}
	return standardHelperSources[name]
}

var helperDependencies = map[string][]string{
	"$patternReading":     {"$patternInteger"},
	"$packedString":       {"$fit"},
	"$putString":          {"$putInteger"},
	"$putString16":        {"$putInteger"},
	"$readU16LE":          {"$readScalar"},
	"$readU16BE":          {"$readScalar"},
	"$readU32LE":          {"$readScalar"},
	"$readU32BE":          {"$readScalar"},
	"$readS16LE":          {"$readScalar"},
	"$readS16BE":          {"$readScalar"},
	"$readS32LE":          {"$readScalar"},
	"$readS32BE":          {"$readScalar"},
	"$readFloatLE":        {"$readScalar"},
	"$readFloatBE":        {"$readScalar"},
	"$readDoubleLE":       {"$readScalar"},
	"$readDoubleBE":       {"$readScalar"},
	"$readU64LE":          {"$readScalar"},
	"$readU64BE":          {"$readScalar"},
	"$readS64LE":          {"$readScalar"},
	"$readS64BE":          {"$readScalar"},
	"$writeU16LE":         {"$writeScalar"},
	"$writeU16BE":         {"$writeScalar"},
	"$writeU32LE":         {"$writeScalar"},
	"$writeU32BE":         {"$writeScalar"},
	"$writeS16LE":         {"$writeScalar"},
	"$writeS16BE":         {"$writeScalar"},
	"$writeS32LE":         {"$writeScalar"},
	"$writeS32BE":         {"$writeScalar"},
	"$writeFloatLE":       {"$writeScalar"},
	"$writeFloatBE":       {"$writeScalar"},
	"$writeDoubleLE":      {"$writeScalar"},
	"$writeDoubleBE":      {"$writeScalar"},
	"$writeU64LE":         {"$writeScalar"},
	"$writeU64BE":         {"$writeScalar"},
	"$writeS64LE":         {"$writeScalar"},
	"$writeS64BE":         {"$writeScalar"},
	"$readInt":            {"$readUint", "$signExtend"},
	"$alignCursor":        {"$offset"},
	"$cursorOffset":       {"$offset"},
	"$parseArray":         {"$offset"},
	"$parseWhile":         {"$offset"},
	"$assert":             {"$truthy"},
	"$check":              {"$offset"},
	"$padWhile":           {"$offset"},
	"$environment":        {"$mainSection"},
	"$SectionPointer":     {"$pointerDelta"},
	"$sectionEnvironment": {"$sectionOf", "$SectionPointer"},
	"$heapEnvironment":    {"$Section", "$sectionEnvironment"},
	"$add":                {"$display", "$wide", "$fit", "$big"},
	"$sub":                {"$number", "$wide", "$fit", "$big"},
	"$mul":                {"$number", "$wide", "$fit", "$big"},
	"$divide":             {"$number", "$wide", "$fit", "$big"},
	"$modulo":             {"$number", "$wide", "$fit", "$big"},
	"$shl":                {"$number", "$fit", "$big"},
	"$shr":                {"$number", "$fit", "$big"},
	"$band":               {"$number", "$fit", "$big"},
	"$bor":                {"$number", "$fit", "$big"},
	"$bxor":               {"$number", "$fit", "$big"},
	"$bnot":               {"$number", "$fit", "$big"},
	"$cloneLocal":         {"$Section", "$sectionEnvironment", "$placeInSection"},
	"$format":             {"$formatValue"},
	"$formatValue":        {"$display"},
	"$parseCString":       {"$cStringSize"},
	"$parseCString16":     {"$cString16Size"},
	"$readBigInt":         {"$readBigUint"},
	"$extractBigBits":     {},
	"$insertBigBits":      {},
}

var helperSources = map[string]string{
	"$align": `function $align(value, alignment) { return Math.ceil(value / alignment) * alignment; }
`,
	"$offset": `function $offset(base, pointer) { return parseInt(pointer.sub(base).toString(10), 10); }
`,
	"$cursorOffset": `function $cursorOffset(base, cursor) {
    const offset = $offset(base, cursor);
    return offset < 0 ? BigInt.asUintN(64, BigInt(offset)) : offset;
}
`,
	"$alignCursor": `function $alignCursor(base, cursor, alignment) { return base.add(Math.ceil($offset(base, cursor) / alignment) * alignment); }
`,
	"$parsed": `function $parsed(value) { return [value, value.$size]; }
`,
	"$environment": `function $environment(base, limit, sections = [$mainSection(base, limit)], inputs = {}) { return { base, limit, cursor: base, root: null, globals: {}, littleEndian: true, arrayIndex: 0, breaks: false, continues: false, sections, inputs }; }
`,
	"$mainSection": `function $mainSection(base, limit) {
    return {
        id: 0,
        name: "main",
        get size() { return limit; },
        slice(offset, size) { return base.add(offset).readByteArray(size); },
        write() { throw new Error("the main section is read-only"); },
    };
}
`,
	"$Section": `class $Section {
    constructor(id, name, growable = false) {
        this.id = id;
        this.name = name;
        this.growable = growable;
        this.bytes = new Uint8Array(0);
        this.placements = [];
        this.refreshing = false;
    }
    get size() { return this.bytes.length; }
    resize(size) {
        const next = new Uint8Array(size);
        next.set(this.bytes.subarray(0, Math.min(size, this.bytes.length)));
        this.bytes = next;
        this.refresh();
    }
    slice(offset, size) {
        if (this.growable && offset >= 0)
            this.extend(offset + size);
        if (offset < 0 || offset + size > this.bytes.length)
            throw new Error("access violation reading section " + this.name);
        return this.bytes.slice(offset, offset + size).buffer;
    }
    write(offset, bytes) {
        this.extend(offset + bytes.length);
        this.bytes.set(bytes, offset);
        this.refresh();
    }
    extend(size) {
        if (size <= this.bytes.length)
            return;
        const next = new Uint8Array(size);
        next.set(this.bytes);
        this.bytes = next;
    }
    refresh() {
        if (this.refreshing)
            return;
        this.refreshing = true;
        try {
            for (const placement of this.placements)
                placement();
        } finally {
            this.refreshing = false;
        }
    }
}
`,
	"$SectionPointer": `class $SectionPointer {
    constructor(section, offset) {
        this.section = section;
        this.offset = offset;
    }
    add(delta) { return new $SectionPointer(this.section, this.offset + $pointerDelta(delta)); }
    sub(delta) { return new $SectionPointer(this.section, this.offset - $pointerDelta(delta)); }
    compare(other) { const d = this.offset - $pointerDelta(other); return d < 0 ? -1 : (d > 0 ? 1 : 0); }
    equals(other) { return this.compare(other) === 0; }
    isNull() { return false; }
    toString(radix = 16) { return radix === 16 ? "0x" + this.offset.toString(16) : this.offset.toString(radix); }
    toJSON() { return this.toString(); }
    toUInt32() { return this.offset >>> 0; }
    readByteArray(size) { return this.section.slice(this.offset, size); }
    view(size) { return new DataView(this.readByteArray(size)); }
    readU8() { return this.view(1).getUint8(0); }
    readS8() { return this.view(1).getInt8(0); }
    readU16() { return this.view(2).getUint16(0, true); }
    readS16() { return this.view(2).getInt16(0, true); }
    readU32() { return this.view(4).getUint32(0, true); }
    readS32() { return this.view(4).getInt32(0, true); }
    readU64() { return uint64(this.view(8).getBigUint64(0, true).toString()); }
    readS64() { return int64(this.view(8).getBigInt64(0, true).toString()); }
    readFloat() { return this.view(4).getFloat32(0, true); }
    readDouble() { return this.view(8).getFloat64(0, true); }
    readPointer() { return ptr("0x" + this.view(Process.pointerSize)[Process.pointerSize === 8 ? "getBigUint64" : "getUint32"](0, true).toString(16)); }
    readUtf8String(length = -1) {
        const bytes = new Uint8Array(this.section.bytes.buffer, this.offset, length === -1 ? this.section.size - this.offset : length);
        const end = length === -1 ? bytes.indexOf(0) : -1;
        let text = "";
        for (const byte of end === -1 ? bytes : bytes.subarray(0, end))
            text += String.fromCharCode(byte);
        return decodeURIComponent(escape(text));
    }
    readUtf16String(length = -1) {
        const units = length === -1 ? (this.section.size - this.offset) >>> 1 : length;
        const view = this.view(units * 2);
        let text = "";
        for (let i = 0; i !== units; i++) {
            const unit = view.getUint16(i * 2, true);
            if (length === -1 && unit === 0)
                break;
            text += String.fromCharCode(unit);
        }
        return text;
    }
    writeU8(value) { this.section.write(this.offset, new Uint8Array([Number(value) & 0xff])); return this; }
    writeByteArray(bytes) { this.section.write(this.offset, new Uint8Array(bytes)); return this; }
    writePointer(value) {
        const buffer = new ArrayBuffer(Process.pointerSize);
        new DataView(buffer)[Process.pointerSize === 8 ? "setBigUint64" : "setUint32"](0, Process.pointerSize === 8 ? BigInt(value.toString()) : Number(value), true);
        return this.writeByteArray(buffer);
    }
}
`,
	"$pointerDelta": `function $pointerDelta(value) {
    if (typeof value === "object" && value !== null)
        return value.offset;
    return typeof value === "bigint" ? Number(BigInt.asIntN(64, value)) : Number(value);
}
`,
	"$sectionOf": `function $sectionOf(env, id) {
    if (typeof id === "bigint" && id === 0xffffffffffffffffn)
        return env.base.section ?? env.sections[0];
    if (typeof id === "bigint" && id === 0xfffffffffffffffen)
        throw new Error("the pattern-local section cannot be accessed");
    const section = env.sections[Number(id)];
    if (section === undefined || section === null)
        throw new Error("section " + id + " does not exist");
    return section;
}
`,
	"$sectionEnvironment": `function $sectionEnvironment(env, id) {
    const section = $sectionOf(env, id);
    const base = new $SectionPointer(section, 0);
    return { base, get limit() { return section.size; }, cursor: base, root: env.root, globals: env.globals, littleEndian: env.littleEndian, arrayIndex: env.arrayIndex, breaks: false, continues: false, sections: env.sections };
}
`,
	"$heapEnvironment": `function $heapEnvironment(env, size) {
    const section = new $Section(env.sections.length, "heap", true);
    env.sections.push(section);
    section.resize(size);
    return $sectionEnvironment(env, section.id);
}
`,
	"$stringRef": `function $stringRef(text) {
    const bytes = new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
    return { address: { readByteArray() { return bytes.buffer; } }, size: bytes.length };
}
`,
	"$placeInSection": `function $placeInSection(section, refresh) {
    if (section.placements !== undefined)
        section.placements.push(refresh);
    refresh();
}
`,
	"$check": `function $check(env, address, size) {
    if ($offset(env.base, address) + size > env.limit)
        throw new Error("the data ended before the value could be read");
}
`,
	"$truthy": `function $truthy(value) { return typeof value === "string" ? value !== "" : Boolean(Number(value)); }
`,
	"$big": `function $big(value) { return typeof value === "bigint" ? value : BigInt(Math.trunc(Number(value))); }
`,
	"$fit": `function $fit(value) { return (value >= -9007199254740991n && value <= 9007199254740991n) ? Number(value) : value; }
`,
	"$wide": `function $wide(left, right) { return typeof left === "bigint" || typeof right === "bigint" || !Number.isSafeInteger(left) || !Number.isSafeInteger(right); }
`,
	"$add": `function $add(left, right) {
    if (typeof left === "string" || typeof right === "string")
        return $display(left) + $display(right);
    if ($wide(left, right) || (Number.isInteger(left) && Number.isInteger(right) && !Number.isSafeInteger(left + right)))
        return $fit($big(left) + $big(right));
    return left + right;
}
`,
	"$sub": `function $sub(left, right) {
    $number(left); $number(right);
    if ($wide(left, right) || (Number.isInteger(left) && Number.isInteger(right) && !Number.isSafeInteger(left - right)))
        return $fit($big(left) - $big(right));
    return left - right;
}
`,
	"$mul": `function $mul(left, right) {
    if (typeof left === "string") {
        const count = Number(right);
        if (count < 0)
            throw new Error("a string cannot be repeated a negative number of times");
        return left.repeat(count);
    }
    $number(right);
    if ($wide(left, right) || (Number.isInteger(left) && Number.isInteger(right) && !Number.isSafeInteger(left * right)))
        return $fit($big(left) * $big(right));
    return left * right;
}
`,
	"$divide": `function $divide(left, right) {
    $number(left); $number(right);
    if (Number(right) === 0)
        throw new Error("division by zero");
    if ($wide(left, right))
        return $fit($big(left) / $big(right));
    return Number.isInteger(left) && Number.isInteger(right) ? Math.trunc(left / right) : left / right;
}
`,
	"$modulo": `function $modulo(left, right) {
    $number(left); $number(right);
    if (Number(right) === 0)
        throw new Error("division by zero");
    if ($wide(left, right))
        return $fit($big(left) % $big(right));
    return left % right;
}
`,
	"$shl": `function $shl(left, right) { $number(left); $number(right); return $fit($big(left) << $big(right)); }
`,
	"$shr": `function $shr(left, right) { $number(left); $number(right); return $fit($big(left) >> $big(right)); }
`,
	"$band": `function $band(left, right) { $number(left); $number(right); return $fit($big(left) & $big(right)); }
`,
	"$bor": `function $bor(left, right) { $number(left); $number(right); return $fit($big(left) | $big(right)); }
`,
	"$bxor": `function $bxor(left, right) { $number(left); $number(right); return $fit($big(left) ^ $big(right)); }
`,
	"$bnot": `function $bnot(value) { $number(value); return typeof value === "bigint" ? BigInt.asUintN(128, ~value) : $fit(~$big(value)); }
`,
	"$matchCase": `function $matchCase(conditions) {
    const matched = conditions.indexOf(true);
    if (matched !== -1 && conditions.indexOf(true, matched + 1) !== -1)
        throw new Error("ambiguous match: several cases apply");
    return matched;
}
`,
	"$assert": `function $assert(condition, message) {
    if (!$truthy(condition))
        throw new Error("assertion failed: " + message);
}
`,
	"$fail": `function $fail(message) { throw new Error(String(message)); }
`,
	"$snapshot": `function $snapshot(object, env) { return { cursor: env.cursor, fields: Object.keys(object.$fields) }; }
`,
	"$restore": `function $restore(object, env, saved) {
    env.cursor = saved.cursor;
    for (const name of Object.keys(object.$fields)) {
        if (!saved.fields.includes(name)) {
            delete object.$fields[name];
            delete object[name];
        }
    }
}
`,
	"$format": `function $format(text, ...args) {
    let next = 0;
    return text.replace(/\{\{|\}\}|\{([^{}:]*)(?::([^{}]*))?\}/g, (match, index, spec) => {
        if (match === "{{")
            return "{";
        if (match === "}}")
            return "}";
        const position = index === "" ? next++ : Number(index);
        if (position >= args.length)
            return match;
        return $formatValue(args[position], spec ?? "");
    });
}
`,
	"$formatValue": `function $formatValue(value, spec) {
    const m = /^(#)?(0)?(\d+)?(?:\.(\d+))?([xXbocd])?$/.exec(spec) ?? [];
    const [, alternate, zero, width, precision, verb] = m;
    let text;
    switch (verb) {
        case "x":
        case "X":
        case "b":
        case "o": {
            const base = { x: 16, X: 16, b: 2, o: 8 }[verb];
            const number = typeof value === "bigint" ? value : BigInt(Math.trunc(Number(value)));
            text = BigInt.asUintN(64, number).toString(base);
            if (verb === "X")
                text = text.toUpperCase();
            if (alternate)
                text = { x: "0x", X: "0x", b: "0b", o: "0o" }[verb] + text;
            break;
        }
        case "c":
            text = String.fromCharCode(Number(value));
            break;
        default:
            text = (typeof value === "number" && precision !== undefined) ? value.toFixed(Number(precision)) : $display(value);
    }
    const target = Number(width ?? 0);
    if (text.length >= target)
        return text;
    const padding = (zero ? "0" : " ").repeat(target - text.length);
    if (zero && /^0[xbo]/.test(text))
        return text.slice(0, 2) + padding + text.slice(2);
    if (zero && text.startsWith("-"))
        return "-" + padding + text.slice(1);
    return padding + text;
}
`,
	"$display": `function $display(value) {
    if (value === null || value === undefined)
        return "";
    if (typeof value === "object" && value.$label !== undefined)
        return value.$label;
    if (typeof value === "object" && value.$address !== undefined)
        return "<pattern>";
    return String(value);
}
`,
	"$labelled": `function $labelled(members, name, value) {
    const number = typeof value === "bigint" ? value : Number(value);
    let label = members[String(number)];
    if (label === undefined)
        label = (members.$ranges ?? []).find(([first, last]) => first <= number && number <= last)?.[2] ?? number;
    return { $label: name + "::" + label, valueOf() { return number; }, toString() { return this.$label; } };
}
`,
	"$eq": `function $eq(left, right) {
    if (typeof left === "string" && left.length === 1 && typeof right !== "string")
        return left.charCodeAt(0) == right;
    if (typeof right === "string" && right.length === 1 && typeof left !== "string")
        return left == right.charCodeAt(0);
    return left == right;
}
`,
	"$unknown": `function $unknown(name) { throw new Error("unknown identifier " + name); }
`,
	"$callNamed": `function $callNamed(env, $this, name, value) {
    const callee = $named[String(name)];
    if (callee === undefined)
        throw new Error("unknown function " + name);
    return callee(env, $this, value);
}
`,
	"$index": `function $index(object, index) {
    const i = Number(index);
    if (object === null || object === undefined || i < 0 || i >= object.length)
        throw new RangeError("index " + i + " is out of range");
    return object[i];
}
`,
	"$number": `function $number(value) {
    if (typeof value === "string")
        throw new TypeError("cannot use a string as a number");
    return value;
}
`,
	"$cloneLocal": `function $cloneLocal(env, value) {
    if (value === null || typeof value !== "object" || value.$type === undefined)
        return value;
    const section = new $Section(env.sections.length, "heap", true);
    env.sections.push(section);
    section.write(0, new Uint8Array(value.$address.readByteArray(value.$size)));
    const henv = $sectionEnvironment(env, section.id);
    let clone = null;
    $placeInSection(section, () => { clone = value.$type.$parse(henv.base, henv, null, value.$args); });
    return clone;
}
`,
	"$padArray": `function $padArray(elements, length) {
    while (elements.length < length)
        elements.push(0);
    return elements;
}
`,
	"$pointee": `function $pointee(metadata) {
    if (metadata.pointee === undefined) {
        if (metadata.address.readPointer === undefined || metadata.target === undefined)
            throw new Error("pointer cannot be dereferenced here");
        metadata.pointee = metadata.target()[0];
    }
    return metadata.pointee;
}
`,
	"$packedString": `function $packedString(value) {
    if (typeof value !== "string")
        return value;
    let packed = 0n;
    for (let i = value.length - 1; i >= 0; i--)
        packed = (packed << 8n) | BigInt(value.charCodeAt(i) & 0xff);
    return $fit(packed);
}
`,
	"$templateArgument": `function $templateArgument(value) {
    if (typeof value === "string") {
        const text = value.length > 32 ? "..." : value;
        const escapes = { 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r" };
        let encoded = "";
        for (const character of text) {
            const code = character.charCodeAt(0) & 0xff;
            encoded += (code >= 0x20 && code < 0x7f) ? character : (escapes[code] ?? "\\x" + code.toString(16).toUpperCase().padStart(2, "0"));
        }
        return '"' + encoded + '"';
    }
    if (value !== null && typeof value === "object" && value.$type !== undefined)
        return (value.$typeName ?? value.$type.name) + "{ }";
    return String(value);
}
`,
	"$patternReading": `function $patternReading([value, size]) { return [$patternInteger(value), size]; }
`,
	"$patternInteger": `function $patternInteger(value) {
    if (value !== null && typeof value === "object" && value.$transformed !== undefined)
        return value.$transformed;
    if (value === null || typeof value !== "object" || value.$address === undefined || value.$size > 8)
        return value;
    const bytes = new Uint8Array(value.$address.readByteArray(value.$size));
    let number = 0;
    for (let i = bytes.length - 1; i >= 0; i--)
        number = number * 256 + bytes[i];
    return number;
}
`,
	"$scoped": `function $scoped(object, name) {
    for (let scope = object; scope !== null && scope !== undefined; scope = scope.$parent) {
        if (name in scope)
            return scope[name];
    }
    throw new Error("unknown identifier " + name);
}
`,
	"$multiply": `function $multiply(left, right) {
    if (typeof left === "string") {
        const count = Number(right);
        if (count < 0)
            throw new Error("a string cannot be repeated a negative number of times");
        return left.repeat(count);
    }
    return left * right;
}
`,
	"$charAdd": `function $charAdd(left, right, leftIsChar, rightIsChar) {
    if (typeof left === "string" && rightIsChar)
        return left + String.fromCharCode(Number(right));
    if (typeof right === "string" && leftIsChar)
        return String.fromCharCode(Number(left)) + right;
    return left + right;
}
`,
	"$parseArray": `function $parseArray(env, address, length, read) {
    const result = [];
    let cursor = address;
    const outerIndex = env.arrayIndex;
    for (let i = 0; i !== length; i++) {
        env.arrayIndex = i;
        const [value, size] = read(cursor);
        cursor = cursor.add(size);
        if (env.continues) {
            env.continues = false;
            continue;
        }
        result.push(value);
        if (env.breaks) {
            env.breaks = false;
            break;
        }
    }
    env.arrayIndex = outerIndex;
    return [result, $offset(address, cursor)];
}
`,
	"$padWhile": `function $padWhile(env, address, proceed) {
    let size = 0;
    const saved = env.cursor;
    while ($offset(env.base, address) + size < env.limit) {
        env.cursor = address.add(size);
        const more = proceed(env.cursor);
        env.cursor = saved;
        if (!more)
            break;
        size++;
    }
    return size;
}
`,
	"$parseWhile": `function $parseWhile(env, address, proceed, read) {
    const result = [];
    let cursor = address;
    const saved = env.cursor;
    const outerIndex = env.arrayIndex;
    for (;;) {
        env.cursor = cursor;
        env.arrayIndex = result.length;
        const more = proceed(cursor);
        env.cursor = saved;
        if (!more)
            break;
        const [value, size] = read(cursor);
        cursor = cursor.add(size);
        if (env.continues) {
            env.continues = false;
            continue;
        }
        result.push(value);
        if (env.breaks) {
            env.breaks = false;
            break;
        }
    }
    env.arrayIndex = outerIndex;
    return [result, $offset(address, cursor)];
}
`,
	"$parseCString": `function $parseCString(address) {
    const value = address.readUtf8String();
    return [value, $cStringSize(address)];
}
`,
	"$parseCString16": `function $parseCString16(address) {
    const value = address.readUtf16String();
    return [value, $cString16Size(address)];
}
`,
	"$deref": `function $deref(pointer, type) { return pointer.isNull() ? null : new type(pointer); }
`,
	"$pointerOf": `function $pointerOf(value) { return (value === null) ? NULL : (value.$address !== undefined) ? value.$address : ptr(value); }
`,
	"$readArray": `function $readArray(address, length, stride, read) {
    const result = new Array(length);
    for (let i = 0; i !== length; i++)
        result[i] = read(address.add(i * stride));
    return result;
}
`,
	"$readString": `function $readString(address, size) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let length = bytes.indexOf(0);
    if (length === -1)
        length = size;
    return address.readUtf8String(length);
}
`,
	"$readString16": `function $readString16(address, count) {
    const units = new Uint16Array(address.readByteArray(count * 2));
    let length = units.indexOf(0);
    if (length === -1)
        length = count;
    return address.readUtf16String(length);
}
`,
	"$cStringSize": `function $cStringSize(address) {
    let length = 0;
    while (address.add(length).readU8() !== 0)
        length++;
    return length + 1;
}
`,
	"$cString16Size": `function $cString16Size(address) {
    let length = 0;
    while (address.add(length).readU16() !== 0)
        length += 2;
    return length + 2;
}
`,
	"$readScalar": `function $readScalar(address, size, method, littleEndian) { return new DataView(address.readByteArray(size))[method](0, littleEndian); }
`,
	"$writeScalar": `function $writeScalar(address, size, method, value, littleEndian) {
    const buffer = new ArrayBuffer(size);
    new DataView(buffer)[method](0, value, littleEndian);
    address.writeByteArray(buffer);
}
`,
	"$readU16LE":     "function $readU16LE(address) { return $readScalar(address, 2, \"getUint16\", true); }\n",
	"$readU16BE":     "function $readU16BE(address) { return $readScalar(address, 2, \"getUint16\", false); }\n",
	"$readS16LE":     "function $readS16LE(address) { return $readScalar(address, 2, \"getInt16\", true); }\n",
	"$readS16BE":     "function $readS16BE(address) { return $readScalar(address, 2, \"getInt16\", false); }\n",
	"$readU32LE":     "function $readU32LE(address) { return $readScalar(address, 4, \"getUint32\", true); }\n",
	"$readU32BE":     "function $readU32BE(address) { return $readScalar(address, 4, \"getUint32\", false); }\n",
	"$readS32LE":     "function $readS32LE(address) { return $readScalar(address, 4, \"getInt32\", true); }\n",
	"$readS32BE":     "function $readS32BE(address) { return $readScalar(address, 4, \"getInt32\", false); }\n",
	"$readFloatLE":   "function $readFloatLE(address) { return $readScalar(address, 4, \"getFloat32\", true); }\n",
	"$readFloatBE":   "function $readFloatBE(address) { return $readScalar(address, 4, \"getFloat32\", false); }\n",
	"$readDoubleLE":  "function $readDoubleLE(address) { return $readScalar(address, 8, \"getFloat64\", true); }\n",
	"$readDoubleBE":  "function $readDoubleBE(address) { return $readScalar(address, 8, \"getFloat64\", false); }\n",
	"$readU64LE":     "function $readU64LE(address) { return uint64($readScalar(address, 8, \"getBigUint64\", true).toString()); }\n",
	"$readU64BE":     "function $readU64BE(address) { return uint64($readScalar(address, 8, \"getBigUint64\", false).toString()); }\n",
	"$readS64LE":     "function $readS64LE(address) { return int64($readScalar(address, 8, \"getBigInt64\", true).toString()); }\n",
	"$readS64BE":     "function $readS64BE(address) { return int64($readScalar(address, 8, \"getBigInt64\", false).toString()); }\n",
	"$writeU16LE":    "function $writeU16LE(address, value) { $writeScalar(address, 2, \"setUint16\", value, true); }\n",
	"$writeU16BE":    "function $writeU16BE(address, value) { $writeScalar(address, 2, \"setUint16\", value, false); }\n",
	"$writeS16LE":    "function $writeS16LE(address, value) { $writeScalar(address, 2, \"setInt16\", value, true); }\n",
	"$writeS16BE":    "function $writeS16BE(address, value) { $writeScalar(address, 2, \"setInt16\", value, false); }\n",
	"$writeU32LE":    "function $writeU32LE(address, value) { $writeScalar(address, 4, \"setUint32\", value, true); }\n",
	"$writeU32BE":    "function $writeU32BE(address, value) { $writeScalar(address, 4, \"setUint32\", value, false); }\n",
	"$writeS32LE":    "function $writeS32LE(address, value) { $writeScalar(address, 4, \"setInt32\", value, true); }\n",
	"$writeS32BE":    "function $writeS32BE(address, value) { $writeScalar(address, 4, \"setInt32\", value, false); }\n",
	"$writeFloatLE":  "function $writeFloatLE(address, value) { $writeScalar(address, 4, \"setFloat32\", value, true); }\n",
	"$writeFloatBE":  "function $writeFloatBE(address, value) { $writeScalar(address, 4, \"setFloat32\", value, false); }\n",
	"$writeDoubleLE": "function $writeDoubleLE(address, value) { $writeScalar(address, 8, \"setFloat64\", value, true); }\n",
	"$writeDoubleBE": "function $writeDoubleBE(address, value) { $writeScalar(address, 8, \"setFloat64\", value, false); }\n",
	"$writeU64LE":    "function $writeU64LE(address, value) { $writeScalar(address, 8, \"setBigUint64\", BigInt(value.toString()), true); }\n",
	"$writeU64BE":    "function $writeU64BE(address, value) { $writeScalar(address, 8, \"setBigUint64\", BigInt(value.toString()), false); }\n",
	"$writeS64LE":    "function $writeS64LE(address, value) { $writeScalar(address, 8, \"setBigInt64\", BigInt(value.toString()), true); }\n",
	"$writeS64BE":    "function $writeS64BE(address, value) { $writeScalar(address, 8, \"setBigInt64\", BigInt(value.toString()), false); }\n",
	"$matchPattern": `function $matchPattern(bytes) { return bytes.map((b) => (b === null) ? "??" : b.toString(16).padStart(2, "0")).join(" "); }
`,
	"$putInteger": `function $putInteger(bytes, offset, size, value, littleEndian) {
    let v = BigInt.asUintN(size * 8, BigInt(value.toString()));
    for (let i = 0; i !== size; i++) {
        bytes[littleEndian ? offset + i : offset + size - 1 - i] = Number(v & 0xffn);
        v >>= 8n;
    }
}
`,
	"$putFloat": `function $putFloat(bytes, offset, size, value, littleEndian) {
    const buffer = new ArrayBuffer(size);
    const view = new DataView(buffer);
    if (size === 4)
        view.setFloat32(0, value, littleEndian);
    else
        view.setFloat64(0, value, littleEndian);
    new Uint8Array(buffer).forEach((b, i) => { bytes[offset + i] = b; });
}
`,
	"$putString": `function $putString(bytes, offset, size, value) {
    for (let i = 0; i !== value.length; i++)
        bytes[offset + i] = value.charCodeAt(i) & 0xff;
    if (value.length < size)
        bytes[offset + value.length] = 0;
}
`,
	"$putString16": `function $putString16(bytes, offset, count, value) {
    for (let i = 0; i !== value.length; i++)
        $putInteger(bytes, offset + i * 2, 2, value.charCodeAt(i), true);
    if (value.length < count)
        $putInteger(bytes, offset + value.length * 2, 2, 0, true);
}
`,
	"$readBitRange": `function $readBitRange(address, bitOffset, width, bigEndian = false) {
    const first = Math.floor(bitOffset / 8);
    const last = Math.floor((bitOffset + width - 1) / 8);
    const bytes = new Uint8Array(address.add(first).readByteArray(last - first + 1));
    let bits = 0n;
    if (bigEndian) {
        for (let i = 0; i !== width; i++) {
            const index = bitOffset % 8 + i;
            bits = (bits << 1n) | BigInt((bytes[index >> 3] >> (7 - (index & 7))) & 1);
        }
    } else {
        for (let i = 0; i !== bytes.length; i++)
            bits |= BigInt(bytes[i]) << BigInt(8 * i);
        bits = (bits >> BigInt(bitOffset % 8)) & ((1n << BigInt(width)) - 1n);
    }
    return width > 53 ? bits : Number(bits);
}
`,
	"$readUint": `function $readUint(address, size, littleEndian) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let value = 0;
    for (let i = 0; i !== size; i++)
        value = value * 256 + bytes[littleEndian ? size - 1 - i : i];
    return value;
}
`,
	"$readInt": `function $readInt(address, size, littleEndian) { return $signExtend($readUint(address, size, littleEndian), size * 8); }
`,
	"$readBigUint": `function $readBigUint(address, size, littleEndian) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let value = 0n;
    for (let i = 0; i !== size; i++)
        value = (value << 8n) | BigInt(bytes[littleEndian ? size - 1 - i : i]);
    return value;
}
`,
	"$readBigInt": `function $readBigInt(address, size, littleEndian) { return BigInt.asIntN(size * 8, $readBigUint(address, size, littleEndian)); }
`,
	"$writeUint": `function $writeUint(address, size, value, littleEndian) {
    const bytes = new Uint8Array(size);
    let v = BigInt.asUintN(size * 8, BigInt(value));
    for (let i = 0; i !== size; i++) {
        bytes[littleEndian ? i : size - 1 - i] = Number(v & 0xffn);
        v >>= 8n;
    }
    address.writeByteArray(bytes.buffer);
}
`,
	"$extractBits": `function $extractBits(value, offset, bits) { return Math.floor(value / 2 ** offset) % 2 ** bits; }
`,
	"$insertBits": `function $insertBits(value, offset, bits, field) {
    const current = Math.floor(value / 2 ** offset) % 2 ** bits;
    return value + (field % 2 ** bits - current) * 2 ** offset;
}
`,
	"$signExtend": `function $signExtend(value, bits) { return (value >= 2 ** (bits - 1)) ? value - 2 ** bits : value; }
`,
	"$extractBigBits": `function $extractBigBits(value, offset, bits) { return (value >> BigInt(offset)) & ((1n << BigInt(bits)) - 1n); }
`,
	"$insertBigBits": `function $insertBigBits(value, offset, bits, field) {
    const mask = ((1n << BigInt(bits)) - 1n) << BigInt(offset);
    return (value & ~mask) | ((field << BigInt(offset)) & mask);
}
`,
}

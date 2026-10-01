package patterns

import (
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func EmitJavaScript(module *Module, sourceName string) string {
	e := &jsEmitter{
		module:  module,
		layouts: moduleLayouts(module),
	}
	items := inNewspaperOrder(e.emitItems(module))

	var out strings.Builder
	fmt.Fprintf(&out, "// Generated from %s by frida-compile. Do not edit.\n", sourceName)
	writeImports(&out, items)
	emitNamespaceObjects(&out, items)
	for _, item := range items {
		out.WriteString(item.source)
	}
	return out.String()
}

func (e *jsEmitter) emitItems(module *Module) []*moduleItem {
	var items []*moduleItem
	if module.Root != nil {
		items = append(items, e.emitItem(rootParseKey, exported, nil, func(out *strings.Builder) {
			fmt.Fprintf(out, "export function parse(address, size, inputs) { return %s.parse(address, size, inputs); }\n", jsRef(module.Root.Name))
		}))
	}
	for _, t := range module.TypesWithAliasesLast() {
		item := e.emitItem(typeItemKey(t.TypeName()), exported, prerequisitesOf(t), func(out *strings.Builder) {
			switch t := t.(type) {
			case *Struct:
				e.emitComposite(out, t.Name, allFields(t), t)
			case *Union:
				e.emitComposite(out, t.Name, t.Fields, t)
			case *Enum:
				e.emitEnum(out, t)
			case *Bitfield:
				e.emitBitfield(out, t)
			case *Alias:
				e.emitAlias(out, t)
			}
		})
		item.typeName = t.TypeName()
		items = append(items, item)
	}
	if module.DynamicAttributes {
		items = append(items, e.emitItem(namedFunctionsKey, private, nil, func(out *strings.Builder) {
			e.emitNamedFunctions(out, module)
		}))
	}
	for _, f := range module.Functions {
		items = append(items, e.emitItem(functionName(f), private, nil, func(out *strings.Builder) {
			e.emitFunction(out, f)
		}))
	}
	return items
}

const (
	rootParseKey      = "parse()"
	namedFunctionsKey = "$named"
)

func (e *jsEmitter) emitItem(key string, visibility itemVisibility, prerequisites []string, emit func(out *strings.Builder)) *moduleItem {
	item := &moduleItem{key: key, visibility: visibility, prerequisites: prerequisites, helpers: map[string]bool{}}
	e.current = item
	var out strings.Builder
	emit(&out)
	item.source = out.String()
	return item
}

func prerequisitesOf(t NamedType) []string {
	var prerequisites []string
	segments := scopeSegments(t.TypeName())
	for depth := 1; depth < len(segments); depth++ {
		prerequisites = append(prerequisites, typeItemKey(strings.Join(segments[:depth], "::")))
	}
	if alias, isAlias := t.(*Alias); isAlias {
		if target, isNamed := Unalias(alias.Target).(NamedType); isNamed {
			prerequisites = append(prerequisites, typeItemKey(target.TypeName()))
		}
	}
	return prerequisites
}

func (e *jsEmitter) emitNamedFunctions(out *strings.Builder, module *Module) {
	out.WriteString("const $named = {\n")
	for _, f := range module.Functions {
		fmt.Fprintf(out, "    %q: ($env, $this, value) => %s($env, $this, %s),\n", f.Name, e.functionRef(f), attributeArgument(f, "value"))
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

func writeImports(out *strings.Builder, items []*moduleItem) {
	namesByModule := map[string][]string{}
	for _, name := range helpersOf(items) {
		module, isConstant := constantModules[name]
		if !isConstant {
			module = "/runtime.js"
		}
		namesByModule[module] = append(namesByModule[module], name)
	}
	modules := make([]string, 0, len(namesByModule))
	for module := range namesByModule {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	for _, module := range modules {
		fmt.Fprintf(out, "import { %s } from %q;\n", strings.Join(namesByModule[module], ", "), RuntimeScheme+module)
	}
}

func helpersOf(items []*moduleItem) []string {
	used := map[string]bool{}
	for _, item := range items {
		for name := range item.helpers {
			used[name] = true
		}
	}
	names := make([]string, 0, len(used))
	for name := range used {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func emitNamespaceObjects(out *strings.Builder, items []*moduleItem) {
	declared := map[string]bool{}
	for _, item := range items {
		declared[item.typeName] = true
	}
	for _, item := range items {
		if item.typeName == "" {
			continue
		}
		segments := scopeSegments(item.typeName)
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
	module  *Module
	layouts []*ModuleLayout
	parsing bool
	current *moduleItem
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
		if !c.dynamic {
			fmt.Fprintf(&class, "    static size = %s;\n", c.size)
		}
		fmt.Fprintf(&class, "    static $align = %s;\n", c.table.value("align", c.alignsOfComposite()))
		fmt.Fprintf(&class, "    constructor(address, parent = null) { this.$address = ptr(address); this.$parent = parent; }\n")
		fmt.Fprintf(&class, "    static at(address) { return new %s(address); }\n", name)
		e.emitParser(&class, t)
		if !c.dynamic {
			c.emitPattern(&class)
		}
		c.emitToJSON(&class)
		if !c.dynamic {
			fmt.Fprintf(&class, "    get $size() { return %s.size; }\n", name)
		} else {
			fmt.Fprintf(&class, "    get $size() { return %s; }\n", c.size)
		}
		for _, f := range c.entries {
			c.emitAccessors(&class, f)
		}
	} else {
		class.WriteString("    static $align = 1;\n")
		e.emitParser(&class, t)
	}
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
	fmt.Fprintf(out, "][%s];\n", e.helper("$target"))
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
				return c.helper("$cString16Size") + "(" + address.arguments() + ")"
			}
			return c.helper("$cStringSize") + "(" + address.arguments() + ")"
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

func (c *compositeEmitter) address(offset string) location {
	return location{base: "this.$address", offset: offset}
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

func (c *compositeEmitter) reader(t Type, address location, entry *fieldEntry) string {
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
			return fmt.Sprintf("%s(%s, %s)", c.helper("$deref"), pointer, c.typeRef(Unalias(t.Target).(NamedType).TypeName()))
		}
		return pointer
	case *Array:
		return c.arrayReader(t, address, entry)
	case *Alias:
		return c.reader(t.Target, address, entry)
	}
	panic("unreachable")
}

func (c *compositeEmitter) viewOf(t Type, address location) string {
	return fmt.Sprintf("new %s(%s, this)", c.typeRef(Unalias(t).(NamedType).TypeName()), address.pointer())
}

func isView(t Type) bool {
	switch Unalias(t).(type) {
	case *Struct, *Union, *Bitfield:
		return true
	}
	return false
}

func (e *jsEmitter) primitiveReader(t *Primitive, address location) string {
	switch t.Kind {
	case Bool:
		return fmt.Sprintf("(%s !== 0)", address.call("readU8"))
	case Char:
		return fmt.Sprintf("String.fromCharCode(%s)", address.call("readU8"))
	case Char16:
		return fmt.Sprintf("String.fromCharCode(%s)", e.scalarReader(&Primitive{Kind: U16, Order: t.Order}, address))
	}
	return e.scalarReader(t, address)
}

func (e *jsEmitter) scalarReader(t *Primitive, address location) string {
	if isOddWidth(t.Kind) {
		return fmt.Sprintf("%s(%s, %d, %s)", e.helper(oddWidthHelperName("$read", t.Kind)), address.arguments(), t.Kind.Size(), e.orderLiteral(t.Order))
	}
	if t.Order == NativeOrder && e.module.DynamicEndian && t.Kind.Size() > 1 && e.parsing {
		return fmt.Sprintf("%s(%s, %d, %q, $env.littleEndian)", e.helper("$readScalar"), address.arguments(), t.Kind.Size(), viewMethod(t.Kind, "get"))
	}
	if t.Order == NativeOrder || t.Kind.Size() == 1 {
		return address.call("read" + nativeAccessorName(t.Kind))
	}
	return fmt.Sprintf("%s(%s)", e.helper(orderedHelperName("$read", t)), address.arguments())
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

func (e *jsEmitter) pointerReader(t *Pointer, address location) string {
	if t.Width == nil {
		return address.call("readPointer")
	}
	return fmt.Sprintf("ptr(%s)", e.scalarReader(t.Width, address))
}

func (c *compositeEmitter) arrayReader(t *Array, address location, entry *fieldEntry) string {
	kind := characterKind(t.Element)
	if t.Length == nil {
		if kind == Char16 {
			if address.offset == "0" {
				return address.call("readUtf16String")
			}
			return address.call("readUtf16String", "-1")
		}
		return fmt.Sprintf("%s(%s)", c.helper("$readCString"), address.arguments())
	}
	length := c.expression(t.Length)
	switch kind {
	case Char:
		return fmt.Sprintf("%s(%s, %s)", c.helper("$readTerminatedString"), address.arguments(), length)
	case Char16:
		return fmt.Sprintf("%s(%s, %s)", c.helper("$readString16"), address.arguments(), length)
	}
	stride := c.table.value(entry.accessor+"_stride", c.sizesOfType(t.Element))
	element := location{base: address.base, offset: "o"}
	return fmt.Sprintf("%s(%s, %s, %s, (o) => %s)", c.helper("$readArray"), address.arguments(), length, stride, c.reader(t.Element, element, entry))
}

func characterKind(t Type) PrimitiveKind {
	if primitive, isPrimitive := Unalias(t).(*Primitive); isPrimitive && (primitive.Kind == Char || primitive.Kind == Char16) {
		return primitive.Kind
	}
	return -1
}

func (c *compositeEmitter) writer(t Type, address location, value string) string {
	switch t := t.(type) {
	case *Primitive:
		return c.primitiveWriter(t, address, value)
	case *Enum:
		return c.primitiveWriter(t.Underlying, address, value)
	case *Pointer:
		pointer := fmt.Sprintf("%s(%s)", c.helper("$pointerOf"), value)
		if t.Width == nil {
			return address.call("writePointer", pointer)
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

func (c *compositeEmitter) primitiveWriter(t *Primitive, address location, value string) string {
	switch t.Kind {
	case Bool:
		return address.call("writeU8", value+" ? 1 : 0")
	case Char:
		return address.call("writeU8", value+".charCodeAt(0)")
	case Char16:
		return c.scalarWriter(&Primitive{Kind: U16, Order: t.Order}, address, value+".charCodeAt(0)")
	}
	return c.scalarWriter(t, address, value)
}

func (c *compositeEmitter) scalarWriter(t *Primitive, address location, value string) string {
	if isOddWidth(t.Kind) {
		return fmt.Sprintf("%s(%s, %d, %s, %s)", c.helper("$writeUint"), address.arguments(), t.Kind.Size(), value, c.orderLiteral(t.Order))
	}
	if t.Order == NativeOrder || t.Kind.Size() == 1 {
		return address.call("write"+nativeAccessorName(t.Kind), value)
	}
	return fmt.Sprintf("%s(%s, %s)", c.helper(orderedHelperName("$write", t)), address.arguments(), value)
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
		return fmt.Sprintf("%s.$encode(bytes, %s, %s)", c.typeRef(t.(NamedType).TypeName()), offset, value)
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
	fmt.Fprintf(out, "    static size = %d;\n", size)
	fmt.Fprintf(out, "    constructor(address, parent = null) { this.$address = ptr(address); this.$parent = parent; }\n")
	fmt.Fprintf(out, "    static at(address) { return new %s(address); }\n", name)
	fmt.Fprintf(out, "    static parse(address) { const view = new %s(address); return { $address: view.$address, $size: %d, $value: view.$value, ...view.toJSON() }; }\n", name, size)
	e.emitParseBody(out, t)
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
	fmt.Fprintf(out, "    get $size() { return %d; }\n", size)
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
	fmt.Fprintf(out, "    get $value() { return %s(this.$address, 0, %d, %s); }\n", e.helper(read), size, order)
	fmt.Fprintf(out, "    set $value(value) { %s(this.$address, 0, %d, value, %s); }\n", e.helper("$writeUint"), size, order)
	closeClass(out, t.Name)
}

func (e *jsEmitter) emitAlias(out *strings.Builder, t *Alias) {
	if named, isNamed := Unalias(t.Target).(NamedType); isNamed {
		openConstant(out, t.Name)
		fmt.Fprintf(out, "%s;\n", e.typeRef(named.TypeName()))
	}
}

func (e *jsEmitter) helper(name string) string {
	e.current.helpers[name] = true
	return name
}

func (e *jsEmitter) typeRef(name string) string {
	e.reference(typeItemKey(name))
	return jsRef(name)
}

func typeItemKey(name string) string {
	return "type " + name
}

func (e *jsEmitter) functionRef(f *Function) string {
	name := functionName(f)
	e.reference(name)
	return name
}

func (e *jsEmitter) namedFunctionsRef() string {
	e.reference(namedFunctionsKey)
	return namedFunctionsKey
}

func (e *jsEmitter) reference(key string) {
	if !slices.Contains(e.current.references, key) {
		e.current.references = append(e.current.references, key)
	}
}

type location struct {
	base   string
	offset string
}

func at(base string) location {
	return location{base: base, offset: "0"}
}

func (l location) call(method string, arguments ...string) string {
	if l.offset != "0" {
		arguments = append(arguments, l.offset)
	}
	return fmt.Sprintf("%s.%s(%s)", l.base, method, strings.Join(arguments, ", "))
}

func (l location) arguments() string {
	return l.base + ", " + l.offset
}

func (l location) pointer() string {
	if l.offset == "0" {
		return l.base
	}
	return fmt.Sprintf("%s.add(%s)", l.base, l.offset)
}

func inEnvironment(offset string) location {
	return location{base: "$env.base", offset: offset}
}

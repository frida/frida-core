package patterns

import (
	"fmt"
	"strings"
)

func EmitDeclarations(module *Module, sourceName string) string {
	d := &declarationEmitter{module: module, layout: module.Layout(Targets[0])}
	var out strings.Builder
	fmt.Fprintf(&out, "// Generated from %s by frida-compile. Do not edit.\n", sourceName)
	openNamespaces := []string{}
	for _, t := range module.TypesWithAliasesLast() {
		namespaces := namespacesOf(t.TypeName())
		openNamespaces = d.switchNamespaces(&out, openNamespaces, namespaces)
		var declaration strings.Builder
		declaration.WriteString("\n")
		switch t := t.(type) {
		case *Struct:
			d.emitComposite(&declaration, t.Name, t.Doc, allFields(t), t)
		case *Union:
			d.emitComposite(&declaration, t.Name, t.Doc, t.Fields, t)
		case *Enum:
			d.emitEnum(&declaration, t)
		case *Bitfield:
			d.emitBitfield(&declaration, t)
		case *Alias:
			d.emitAlias(&declaration, t)
		}
		text := declaration.String()
		if len(namespaces) > 0 {
			text = strings.ReplaceAll(text, "export declare ", "export ")
		}
		out.WriteString(indent(text, len(namespaces)))
	}
	d.switchNamespaces(&out, openNamespaces, nil)
	if module.Root != nil {
		inputs := moduleInputs(module)
		if len(inputs) > 0 {
			fmt.Fprintf(&out, "\nexport declare namespace %s {\n    interface Inputs {\n", tsRef(module.Root.Name))
			for _, input := range inputs {
				writeDoc(&out, "        ", "")
				fmt.Fprintf(&out, "        %s?: %s;\n", input.Name, d.inputType(input))
			}
			out.WriteString("    }\n}\n")
			fmt.Fprintf(&out, "\nexport declare function parse(address: NativePointer, size?: number, inputs?: %s.Inputs): %s.Parsed;\n", tsRef(module.Root.Name), tsRef(module.Root.Name))
		} else {
			fmt.Fprintf(&out, "\nexport declare function parse(address: NativePointer, size?: number): %s.Parsed;\n", tsRef(module.Root.Name))
		}
	}
	return out.String()
}

func namespacesOf(qualifiedName string) []string {
	segments := scopeSegments(qualifiedName)
	return segments[:len(segments)-1]
}

func (d *declarationEmitter) switchNamespaces(out *strings.Builder, open []string, wanted []string) []string {
	shared := 0
	for shared < len(open) && shared < len(wanted) && open[shared] == wanted[shared] {
		shared++
	}
	for depth := len(open); depth > shared; depth-- {
		fmt.Fprintf(out, "%s}\n", strings.Repeat("    ", depth-1))
	}
	for depth := shared; depth < len(wanted); depth++ {
		keyword := "namespace"
		if depth == 0 {
			keyword = "export declare namespace"
		}
		fmt.Fprintf(out, "%s%s %s {\n", strings.Repeat("    ", depth), keyword, wanted[depth])
	}
	return wanted
}

func indent(text string, depth int) string {
	if depth == 0 {
		return text
	}
	prefix := strings.Repeat("    ", depth)
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

func tsRef(qualifiedName string) string {
	return jsRef(qualifiedName)
}

type declarationEmitter struct {
	module *Module
	layout *ModuleLayout
}

func (d *declarationEmitter) emitComposite(out *strings.Builder, qualifiedName string, doc string, fields []*Field, t Type) {
	view := hasView(t)
	dynamic := !view || d.layout.Of(t).Dynamic
	name := shortName(qualifiedName)

	writeDoc(out, "", doc)
	fmt.Fprintf(out, "export declare class %s {\n", name)
	if view {
		fmt.Fprintf(out, "    constructor(address: NativePointer);\n")
		fmt.Fprintf(out, "    static at(address: NativePointer): %s;\n", name)
		if !dynamic {
			fmt.Fprintf(out, "    static readonly size: number;\n")
			fmt.Fprintf(out, "    static pattern(fields: %s.Fields): string;\n", name)
		}
	}
	fmt.Fprintf(out, "    static parse(address: NativePointer, size?: number): %s.Parsed;\n", name)
	if view {
		fmt.Fprintf(out, "    readonly $address: NativePointer;\n")
		fmt.Fprintf(out, "    readonly $size: number;\n")
		for _, field := range fields {
			if field.Name == "" {
				continue
			}
			writeDoc(out, "    ", field.Doc)
			d.emitFieldAccessor(out, field)
		}
		fmt.Fprintf(out, "    toJSON(): %s.Values;\n", name)
	}
	out.WriteString("}\n")

	fmt.Fprintf(out, "export declare namespace %s {\n", name)
	if !dynamic {
		out.WriteString("    interface Fields {\n")
		for _, field := range fields {
			if field.Name != "" {
				fmt.Fprintf(out, "        %s?: %s;\n", field.Name, d.fieldsType(field.Type))
			}
		}
		out.WriteString("    }\n")
	}
	if view {
		out.WriteString("    interface Values {\n")
		for _, field := range fields {
			if field.Name == "" || field.Hidden {
				continue
			}
			optional := ""
			if field.Guard != nil {
				optional = "?"
			}
			fmt.Fprintf(out, "        %s%s: %s;\n", field.Name, optional, d.valuesType(field.Type))
		}
		out.WriteString("    }\n")
	}
	out.WriteString("    interface Parsed {\n")
	out.WriteString("        readonly $address: NativePointer;\n")
	out.WriteString("        readonly $size: number;\n")
	for _, field := range fields {
		if field.Name == "" {
			continue
		}
		writeDoc(out, "        ", field.Doc)
		optional := ""
		if field.Guard != nil {
			optional = "?"
		}
		fmt.Fprintf(out, "        %s%s: %s;\n", field.Name, optional, d.parsedType(field.Type))
	}
	out.WriteString("    }\n}\n")
}

func (d *declarationEmitter) inputType(local *Local) string {
	if local.Type == nil {
		if _, isString := local.Init.(*StringConstant); isString {
			return "string"
		}
		return "number | bigint | string | boolean"
	}
	return d.parsedType(local.Type)
}

func (d *declarationEmitter) parsedType(t Type) string {
	switch t := t.(type) {
	case *Primitive:
		return primitiveType(t.Kind)
	case *Enum:
		return tsRef(t.Name)
	case *Struct, *Union, *Bitfield:
		return tsRef(t.(NamedType).TypeName()) + ".Parsed"
	case *Alias:
		return d.parsedType(t.Target)
	case *Pointer:
		return "NativePointer"
	case *Array:
		if characterKind(t.Element) != -1 {
			return "string"
		}
		return arrayOf(d.parsedType(t.Element))
	}
	panic("unreachable")
}

func (d *declarationEmitter) emitFieldAccessor(out *strings.Builder, field *Field) {
	absent := ""
	if field.Guard != nil {
		absent = " | undefined"
	}
	switch t := Unalias(field.Type).(type) {
	case *Primitive, *Enum:
		if absent == "" {
			fmt.Fprintf(out, "    %s: %s;\n", field.Name, d.viewType(field.Type))
		} else {
			fmt.Fprintf(out, "    get %s(): %s%s;\n", field.Name, d.viewType(field.Type), absent)
			fmt.Fprintf(out, "    set %s(value: %s);\n", field.Name, d.viewType(field.Type))
		}
	case *Pointer:
		if isView(t.Target) {
			fmt.Fprintf(out, "    get %s(): %s | null%s;\n", field.Name, d.typeName(t.Target), absent)
			fmt.Fprintf(out, "    set %s(value: %s | NativePointer | null);\n", field.Name, d.typeName(t.Target))
		} else {
			fmt.Fprintf(out, "    get %s(): NativePointer%s;\n", field.Name, absent)
			fmt.Fprintf(out, "    set %s(value: NativePointer);\n", field.Name)
		}
	default:
		fmt.Fprintf(out, "    readonly %s: %s%s;\n", field.Name, d.viewType(field.Type), absent)
	}
}

func (d *declarationEmitter) viewType(t Type) string {
	switch t := t.(type) {
	case *Primitive:
		return primitiveType(t.Kind)
	case *Enum, *Struct, *Union, *Bitfield:
		return tsRef(t.(NamedType).TypeName())
	case *Alias:
		return tsRef(t.Name)
	case *Pointer:
		if isView(t.Target) {
			return d.typeName(t.Target) + " | null"
		}
		return "NativePointer"
	case *Array:
		if characterKind(t.Element) != -1 {
			return "string"
		}
		return arrayOf(d.viewType(t.Element))
	}
	panic("unreachable")
}

func (d *declarationEmitter) fieldsType(t Type) string {
	switch t := t.(type) {
	case *Primitive:
		switch t.Kind {
		case U64, S64:
			return "number | UInt64 | Int64"
		case U96, U128, S96, S128:
			return "number | bigint"
		}
		return primitiveType(t.Kind)
	case *Enum:
		return tsRef(t.Name)
	case *Struct, *Union:
		return tsRef(t.(NamedType).TypeName()) + ".Fields"
	case *Bitfield:
		return "number"
	case *Alias:
		return d.fieldsType(t.Target)
	case *Pointer:
		if isView(t.Target) {
			return d.typeName(t.Target) + " | NativePointer"
		}
		return "NativePointer"
	case *Array:
		if characterKind(t.Element) != -1 {
			return "string"
		}
		return arrayOf(d.fieldsType(t.Element))
	}
	panic("unreachable")
}

func (d *declarationEmitter) valuesType(t Type) string {
	if _, isPointer := Unalias(t).(*Pointer); isPointer {
		return "NativePointer"
	}
	return d.viewType(t)
}

func (d *declarationEmitter) typeName(t Type) string {
	return tsRef(Unalias(t).(NamedType).TypeName())
}

func arrayOf(element string) string {
	if strings.Contains(element, " ") {
		return "(" + element + ")[]"
	}
	return element + "[]"
}

func primitiveType(kind PrimitiveKind) string {
	switch kind {
	case U64:
		return "UInt64"
	case S64:
		return "Int64"
	case U96, U128, S96, S128:
		return "bigint"
	case Bool:
		return "boolean"
	case Char, Char16:
		return "string"
	}
	return "number"
}

func (d *declarationEmitter) emitEnum(out *strings.Builder, t *Enum) {
	writeDoc(out, "", t.Doc)
	if hasWideMembers(t) {
		fmt.Fprintf(out, "export type %s = bigint;\n", shortName(t.Name))
		fmt.Fprintf(out, "export declare const %s: {\n", shortName(t.Name))
		for _, member := range t.Members {
			writeDoc(out, "    ", member.Doc)
			fmt.Fprintf(out, "    readonly %s: bigint;\n", member.Name)
		}
		out.WriteString("};\n")
		return
	}
	fmt.Fprintf(out, "export declare enum %s {\n", shortName(t.Name))
	for _, member := range t.Members {
		writeDoc(out, "    ", member.Doc)
		fmt.Fprintf(out, "    %s = %d,\n", member.Name, member.Value)
	}
	out.WriteString("}\n")
}

func hasWideMembers(t *Enum) bool {
	for _, member := range t.Members {
		if member.Wide != nil || member.WideLast != nil {
			return true
		}
	}
	return false
}

func (d *declarationEmitter) emitBitfield(out *strings.Builder, t *Bitfield) {
	if !t.Simple {
		d.emitDynamicBitfield(out, t)
		return
	}
	big := (t.TotalBits+7)/8 > 6

	name := shortName(t.Name)
	writeDoc(out, "", t.Doc)
	fmt.Fprintf(out, "export declare class %s {\n", name)
	fmt.Fprintf(out, "    constructor(address: NativePointer);\n")
	fmt.Fprintf(out, "    static at(address: NativePointer): %s;\n", name)
	fmt.Fprintf(out, "    static readonly size: number;\n")
	fmt.Fprintf(out, "    readonly $address: NativePointer;\n")
	fmt.Fprintf(out, "    readonly $size: number;\n")
	if big {
		fmt.Fprintf(out, "    $value: bigint;\n")
	} else {
		fmt.Fprintf(out, "    $value: number;\n")
	}
	for _, member := range t.Members {
		if member.Name == "" {
			continue
		}
		writeDoc(out, "    ", member.Doc)
		fmt.Fprintf(out, "    %s: %s;\n", member.Name, bitfieldMemberType(member, big))
	}
	fmt.Fprintf(out, "    toJSON(): %s.Values;\n", name)
	fmt.Fprintf(out, "    static parse(address: NativePointer): %s.Parsed;\n", name)
	out.WriteString("}\n")

	fmt.Fprintf(out, "export declare namespace %s {\n    interface Values {\n", name)
	for _, member := range t.Members {
		if member.Name != "" {
			fmt.Fprintf(out, "        %s: %s;\n", member.Name, bitfieldMemberType(member, big))
		}
	}
	out.WriteString("    }\n")
	out.WriteString("    interface Parsed extends Values {\n")
	out.WriteString("        readonly $address: NativePointer;\n")
	out.WriteString("        readonly $size: number;\n")
	if big {
		out.WriteString("        readonly $value: bigint;\n")
	} else {
		out.WriteString("        readonly $value: number;\n")
	}
	out.WriteString("    }\n}\n")
}

func (d *declarationEmitter) emitDynamicBitfield(out *strings.Builder, t *Bitfield) {
	name := shortName(t.Name)
	writeDoc(out, "", t.Doc)
	fmt.Fprintf(out, "export declare class %s {\n", name)
	fmt.Fprintf(out, "    static parse(address: NativePointer, size?: number): %s.Parsed;\n", name)
	out.WriteString("}\n")
	fmt.Fprintf(out, "export declare namespace %s {\n    interface Parsed {\n", name)
	out.WriteString("        readonly $address: NativePointer;\n")
	out.WriteString("        readonly $size: number;\n")
	out.WriteString("        readonly $value: number | bigint;\n")
	for _, statement := range flattenBitfield(t.Body) {
		switch s := statement.(type) {
		case *BitfieldMember:
			if s.Name != "" {
				fmt.Fprintf(out, "        %s?: %s;\n", s.Name, bitfieldMemberType(s, true))
			}
		case *Field:
			if s.Name != "" {
				fmt.Fprintf(out, "        %s?: %s;\n", s.Name, d.parsedType(s.Type))
			}
		}
	}
	out.WriteString("    }\n}\n")
}

func flattenBitfield(statements []Statement) []Statement {
	var flattened []Statement
	for _, statement := range statements {
		switch s := statement.(type) {
		case *Conditional:
			flattened = append(flattened, flattenBitfield(s.Then)...)
			flattened = append(flattened, flattenBitfield(s.Else)...)
		case *Match:
			for _, matchCase := range s.Cases {
				flattened = append(flattened, flattenBitfield(matchCase.Then)...)
			}
			flattened = append(flattened, flattenBitfield(s.Default)...)
		default:
			flattened = append(flattened, s)
		}
	}
	return flattened
}

func bitfieldMemberType(member *BitfieldMember, big bool) string {
	switch {
	case member.Bool:
		return "boolean"
	case member.Enum != nil:
		return tsRef(member.Enum.Name)
	case big && member.Bits > 53:
		return "bigint"
	}
	return "number"
}

func (d *declarationEmitter) emitAlias(out *strings.Builder, t *Alias) {
	name := shortName(t.Name)
	writeDoc(out, "", t.Doc)
	if named, isNamed := Unalias(t.Target).(NamedType); isNamed {
		fmt.Fprintf(out, "export type %s = %s;\n", name, tsRef(named.TypeName()))
		fmt.Fprintf(out, "export declare const %s: typeof %s;\n", name, tsRef(named.TypeName()))
		return
	}
	fmt.Fprintf(out, "export type %s = %s;\n", name, d.viewType(t.Target))
}

func writeDoc(out *strings.Builder, indent string, doc string) {
	if doc == "" {
		return
	}
	fmt.Fprintf(out, "%s/**\n", indent)
	for _, line := range strings.Split(doc, "\n") {
		fmt.Fprintf(out, "%s * %s\n", indent, line)
	}
	fmt.Fprintf(out, "%s */\n", indent)
}

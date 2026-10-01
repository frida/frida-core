package patterns

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

func (e *jsEmitter) emitParser(out *strings.Builder, t Type) {
	fmt.Fprintf(out, "    static parse(address, size = Infinity, inputs = {}) { return %s.$parse(0, %s(ptr(address), size, undefined, inputs), null); }\n", shortName(t.(NamedType).TypeName()), e.helper("$environment"))
	e.emitParseBody(out, t)
}

func (e *jsEmitter) emitParseBody(out *strings.Builder, t Type) {
	e.parsing = true
	defer func() { e.parsing = false }()
	p := &parserEmitter{jsEmitter: e, t: t, out: out}
	out.WriteString("    static $parse($start, $env, $parent, $args = [], $startBit = 0) {\n")
	for i, param := range typeParams(t) {
		fmt.Fprintf(out, "        let %s = $args[%d];\n", localName(param), i)
	}
	if s, isStruct := t.(*Struct); isStruct && s.Global {
		fmt.Fprintf(out, "        $env = %s($env.base.add($start), $env.limit, $env.sections, $env.inputs);\n", e.helper("$environment"))
		out.WriteString("        $start = 0;\n")
	}
	out.WriteString("        $env.cursor = $start;\n")
	fmt.Fprintf(out, "        const $this = new %s(%s, $env.base.add($start), $parent, $args);\n", e.helper("$Pattern"), shortName(t.(NamedType).TypeName()))
	if s, isStruct := t.(*Struct); isStruct && s.Global {
		out.WriteString("        $env.root = $this;\n")
	}
	if naming := namingOf(t); hasDynamicNaming(t) {
		fmt.Fprintf(out, "        Object.defineProperty($this, \"$typeName\", { value: %s });\n", e.instanceName(naming))
	}
	out.WriteString("        const $fields = $this.$fields;\n")
	switch t := t.(type) {
	case *Struct:
		p.abi = t.ABI
		p.global = t.Global
		p.staticCursor = staticCursor{known: true}
		out.WriteString("        $body: {\n")
		p.emitStatements(structBody(t), "            ")
		p.leaveStaticCursor("            ")
		out.WriteString("        }\n")
		out.WriteString("        $this.$size = $env.cursor - $start;\n")
	case *Union:
		p.abi = t.ABI
		p.union = true
		out.WriteString("        $body: {\n")
		p.emitStatements(t.Body, "            ")
		out.WriteString("        }\n")
		out.WriteString("        $this.$size = Math.max(0, ...Object.values($fields).map((f) => f.offset - $start + f.size));\n")
	case *Bitfield:
		p.bits = true
		out.WriteString("        let $bit = $startBit;\n")
		out.WriteString("        $body: {\n")
		p.emitStatements(t.Body, "            ")
		out.WriteString("        }\n")
		if t.FixedBits > 0 {
			fmt.Fprintf(out, "        $bit = $startBit + %d;\n", t.FixedBits)
		}
		out.WriteString("        $this.$bits = $bit - $startBit;\n")
		out.WriteString("        $this.$size = Math.ceil($bit / 8);\n")
		out.WriteString("        $this.$value = $readBitRange($env.base, $start, 0, Math.min(64, $this.$size * 8));\n")
		e.helper("$readBitRange")
	}
	for _, typed := range attributedTypes(t) {
		for _, use := range typed {
			p.emitTypeAttribute(use, "        ")
		}
	}
	out.WriteString("        return $this;\n    }\n")
}

func (e *jsEmitter) instanceName(naming []NamePart) string {
	parts := make([]string, len(naming))
	for i, part := range naming {
		if part.Param == nil {
			parts[i] = strconv.Quote(part.Text)
		} else {
			parts[i] = fmt.Sprintf("%s(%s)", e.helper("$templateArgument"), localName(part.Param))
		}
	}
	return strings.Join(parts, " + ")
}

func (p *parserEmitter) emitTypeAttribute(use *AttributeUse, indent string) {
	fmt.Fprintf(p.out, "%s{\n", indent)
	fmt.Fprintf(p.out, "%s    const $meta = {};\n", indent)
	p.emitAttribute(use, indent+"    ", "$this", "$meta")
	fmt.Fprintf(p.out, "%s    for (const key of Object.keys($meta)) Object.defineProperty($this, \"$\" + key, { value: $meta[key], configurable: true });\n", indent)
	fmt.Fprintf(p.out, "%s}\n", indent)
}

func typeParams(t Type) []*Local {
	switch t := t.(type) {
	case *Struct:
		return t.Params
	case *Union:
		return t.Params
	case *Bitfield:
		return t.Params
	}
	return nil
}

func typeArgs(t Type) []Value {
	switch t := t.(type) {
	case *Struct:
		return t.Args
	case *Union:
		return t.Args
	case *Bitfield:
		return t.Args
	}
	return nil
}

func (e *jsEmitter) emitFunction(out *strings.Builder, f *Function) {
	e.parsing = true
	defer func() { e.parsing = false }()
	p := &parserEmitter{jsEmitter: e, out: out, inFunction: true}
	fmt.Fprintf(out, "function %s($env, $this", functionName(f))
	for _, param := range f.Params {
		fmt.Fprintf(out, ", %s", localName(param))
	}
	out.WriteString(") {\n")
	p.emitStatements(f.Body, "    ")
	out.WriteString("}\n")
}

func functionName(f *Function) string {
	return "$fn_" + strings.ReplaceAll(f.Name, "::", "_")
}

type parserEmitter struct {
	*jsEmitter
	t            Type
	abi          ABI
	global       bool
	union        bool
	bits         bool
	inFunction   bool
	scoping      bool
	loops        int
	out          *strings.Builder
	cursor       string
	staticCursor staticCursor
}

type staticCursor struct {
	known  bool
	offset int
	moved  bool
}

func (p *parserEmitter) emitStatements(statements []Statement, indent string) {
	for _, statement := range statements {
		if _, isField := statement.(*Field); !isField {
			p.leaveStaticCursor(indent)
		}
		switch s := statement.(type) {
		case *Field:
			p.emitField(s, indent, !p.union)
		case *BitfieldMember:
			p.emitBitMember(s, indent)
		case *Local:
			if s.Type == nil && !isDefaultInit(s.Init) && !isStringInit(s.Init) {
				fmt.Fprintf(p.out, "%s%s = %s($env, %s);\n", indent, p.localDeclaration(s), p.helper("$cloneLocal"), p.expression(s.Init))
			} else if s.StringCount != nil {
				fmt.Fprintf(p.out, "%s%s = new Array(Number(%s)).fill(\"\");\n", indent, p.localDeclaration(s), p.expression(s.StringCount))
			} else if isHeapBacked(s.Type) {
				p.emitHeapLocal(s, indent)
			} else if array, isArray := Unalias(s.Type).(*Array); isArray && array.Length != nil && isDefaultInit(s.Init) && !isCharacter(array.Element) {
				fmt.Fprintf(p.out, "%s%s = new Array(Number(%s)).fill(0);\n", indent, p.localDeclaration(s), p.expression(array.Length))
			} else if isArray && array.Length != nil && !isCharacter(array.Element) {
				fmt.Fprintf(p.out, "%s%s = %s(%s, Number(%s));\n", indent, p.localDeclaration(s), p.helper("$padArray"), p.expression(s.Init), p.expression(array.Length))
			} else if s.Member && !s.Export {
				fmt.Fprintf(p.out, "%sObject.defineProperty($this, %q, { value: %s, writable: true, configurable: true });\n", indent, s.Name, p.expression(s.Init))
			} else if s.Input {
				fmt.Fprintf(p.out, "%s%s = (%q in $env.inputs) ? $env.inputs[%q] : %s;\n", indent, p.localAccess(s), s.Name, s.Name, p.expression(s.Init))
			} else if s.Export || s.Global {
				fmt.Fprintf(p.out, "%s%s = %s;\n", indent, p.localAccess(s), p.expression(s.Init))
			} else {
				fmt.Fprintf(p.out, "%slet %s = %s;\n", indent, localName(s), p.expression(s.Init))
			}
		case *Assignment:
			switch target := s.Target.(type) {
			case *Cursor:
				fmt.Fprintf(p.out, "%s$env.cursor = %s(%s);\n", indent, p.helper("$pointerDelta"), p.expression(s.Value))
			case *LocalRef:
				fmt.Fprintf(p.out, "%s%s = %s;\n", indent, p.localAccess(target.Local), p.expression(s.Value))
			case *GlobalRef:
				fmt.Fprintf(p.out, "%s%s = %s;\n", indent, p.globalAccess(target), p.expression(s.Value))
			case *MemberOf:
				if store := p.memberStore(target, p.expression(s.Value)); store != "" {
					fmt.Fprintf(p.out, "%s%s;\n", indent, store)
				} else {
					fmt.Fprintf(p.out, "%s%s = %s;\n", indent, p.expression(target), p.expression(s.Value))
				}
			case *Index:
				if store := p.elementStore(target, p.expression(s.Value)); store != "" {
					fmt.Fprintf(p.out, "%s%s;\n", indent, store)
				}
				fmt.Fprintf(p.out, "%s%s = %s;\n", indent, p.lvalue(target), p.expression(s.Value))
			default:
				fmt.Fprintf(p.out, "%s%s = %s;\n", indent, p.lvalue(target), p.expression(s.Value))
			}
		case *Conditional:
			fmt.Fprintf(p.out, "%sif (%s) {\n", indent, p.condition(s.Condition))
			p.emitStatements(s.Then, indent+"    ")
			if len(s.Else) > 0 {
				fmt.Fprintf(p.out, "%s} else {\n", indent)
				p.emitStatements(s.Else, indent+"    ")
			}
			fmt.Fprintf(p.out, "%s}\n", indent)
		case *Match:
			conditions := make([]string, len(s.Cases))
			for i, matchCase := range s.Cases {
				conditions[i] = p.condition(matchCase.Condition)
			}
			fmt.Fprintf(p.out, "%s{\n", indent)
			fmt.Fprintf(p.out, "%s    const $case = %s([%s]);\n", indent, p.helper("$matchCase"), strings.Join(conditions, ", "))
			for i, matchCase := range s.Cases {
				fmt.Fprintf(p.out, "%s    if ($case === %d) {\n", indent, i)
				p.emitStatements(matchCase.Then, indent+"        ")
				fmt.Fprintf(p.out, "%s    }\n", indent)
			}
			if len(s.Default) > 0 {
				fmt.Fprintf(p.out, "%s    if ($case === -1) {\n", indent)
				p.emitStatements(s.Default, indent+"        ")
				fmt.Fprintf(p.out, "%s    }\n", indent)
			}
			fmt.Fprintf(p.out, "%s}\n", indent)
		case *Return:
			if s.Value == nil && !p.inFunction {
				fmt.Fprintf(p.out, "%sbreak $body;\n", indent)
			} else if s.Value == nil {
				fmt.Fprintf(p.out, "%sreturn;\n", indent)
			} else {
				fmt.Fprintf(p.out, "%sreturn %s;\n", indent, p.expression(s.Value))
			}
		case *Loop:
			fmt.Fprintf(p.out, "%s{\n", indent)
			p.emitStatements(s.Init, indent+"    ")
			fmt.Fprintf(p.out, "%s    while (%s) {\n", indent, p.condition(s.Condition))
			p.loops++
			if len(s.Step) == 0 {
				p.emitStatements(s.Body, indent+"        ")
			} else {
				fmt.Fprintf(p.out, "%s        try {\n", indent)
				p.emitStatements(s.Body, indent+"            ")
				fmt.Fprintf(p.out, "%s        } finally {\n", indent)
				p.emitStatements(s.Step, indent+"            ")
				fmt.Fprintf(p.out, "%s        }\n", indent)
			}
			p.loops--
			fmt.Fprintf(p.out, "%s    }\n", indent)
			fmt.Fprintf(p.out, "%s}\n", indent)
		case *Break:
			if p.loops == 0 && !p.inFunction {
				fmt.Fprintf(p.out, "%s$env.breaks = true;\n", indent)
				fmt.Fprintf(p.out, "%sbreak $body;\n", indent)
				continue
			}
			fmt.Fprintf(p.out, "%sbreak;\n", indent)
		case *Continue:
			if p.loops == 0 && !p.inFunction {
				fmt.Fprintf(p.out, "%s$env.continues = true;\n", indent)
				fmt.Fprintf(p.out, "%sbreak $body;\n", indent)
				continue
			}
			fmt.Fprintf(p.out, "%scontinue;\n", indent)
		case *Try:
			fmt.Fprintf(p.out, "%s{\n", indent)
			fmt.Fprintf(p.out, "%s    const $saved = %s($this, $env);\n", indent, p.helper("$snapshot"))
			fmt.Fprintf(p.out, "%s    try {\n", indent)
			p.emitStatements(s.Body, indent+"        ")
			fmt.Fprintf(p.out, "%s    } catch ($e) {\n", indent)
			fmt.Fprintf(p.out, "%s        %s($this, $env, $saved);\n", indent, p.helper("$restore"))
			p.emitStatements(s.Catch, indent+"        ")
			fmt.Fprintf(p.out, "%s    }\n", indent)
			fmt.Fprintf(p.out, "%s}\n", indent)
		case *Evaluation:
			fmt.Fprintf(p.out, "%s%s;\n", indent, p.expression(s.Value))
		case *Failure:
			fmt.Fprintf(p.out, "%sthrow new Error(%s);\n", indent, strconv.Quote(s.Message))
		}
	}
}

func (p *parserEmitter) condition(v Value) string {
	return fmt.Sprintf("%s(%s)", p.helper("$truthy"), p.expression(v))
}

func isStringInit(v Value) bool {
	_, isString := v.(*StringConstant)
	return isString
}

func isDefaultInit(v Value) bool {
	_, isConstant := v.(*Constant)
	return isConstant
}

func (p *parserEmitter) localDeclaration(local *Local) string {
	if local.Member && !local.Export {
		fmt.Fprintf(p.out, "Object.defineProperty($this, %q, { value: null, writable: true, configurable: true });\n", local.Name)
		return "$this." + local.Name
	}
	if !local.Export && !local.Global {
		return "let " + localName(local)
	}
	return p.localAccess(local)
}

func (p *parserEmitter) emitHeapLocal(local *Local, indent string) {
	switch {
	case local.Member && !local.Export:
		fmt.Fprintf(p.out, "%sObject.defineProperty($this, %q, { value: null, writable: true, configurable: true });\n", indent, local.Name)
	case !local.Export && !local.Global:
		fmt.Fprintf(p.out, "%slet %s;\n", indent, localName(local))
	}
	fmt.Fprintf(p.out, "%s{\n", indent)
	fmt.Fprintf(p.out, "%s    const $henv = %s($env, %s);\n", indent, p.helper("$heapEnvironment"), p.allocationSize(local.Type))
	if !isDefaultInit(local.Init) {
		fmt.Fprintf(p.out, "%s    const $source = %s;\n", indent, p.expression(local.Init))
		fmt.Fprintf(p.out, "%s    $henv.base.section.write(0, new Uint8Array($source.$address.readByteArray($source.$size)));\n", indent)
	}
	fmt.Fprintf(p.out, "%s    %s($henv.base.section, () => { %s = (($env) => %s)($henv)[0]; });\n", indent, p.helper("$placeInSection"),
		p.localAccess(local), p.reader(local.Type, "0"))
	fmt.Fprintf(p.out, "%s}\n", indent)
}

func (p *parserEmitter) allocationSize(t Type) string {
	if array, isArray := Unalias(t).(*Array); isArray && array.Length != nil {
		return fmt.Sprintf("Number(%s) * %s", p.expression(array.Length), p.allocationSize(array.Element))
	}
	return fmt.Sprintf("%d", p.staticSize(t))
}

func (p *parserEmitter) staticSize(t Type) int {
	size := -1
	for _, layout := range moduleLayouts(p.module) {
		computed := layout.Of(t)
		if computed.Dynamic || (size != -1 && computed.Size != size) {
			return 0
		}
		size = computed.Size
	}
	return size
}

func (p *parserEmitter) elementStore(target *Index, value string) string {
	array, isArray := Unalias(staticTypeOf(target.Object)).(*Array)
	if !isArray {
		return ""
	}
	var metadata string
	switch object := target.Object.(type) {
	case *MemberOf:
		if object.Field == nil {
			return ""
		}
		metadata = fmt.Sprintf("%s.$fields.%s", p.expression(object.Object), object.Name)
	case *FieldRef:
		metadata = fmt.Sprintf("%s.$fields.%s", p.fieldPath(object.Path[:len(object.Path)-1]), object.Path[len(object.Path)-1].Name)
	default:
		return ""
	}
	primitive := primitiveOf(array.Element)
	if primitive == nil {
		return ""
	}
	address := location{base: metadata + ".base", offset: fmt.Sprintf("%s.offset + Number(%s) * %d", metadata, p.expression(target.Index), primitive.Kind.Size())}
	return p.primitiveStore(primitive, address, fmt.Sprintf("%d", primitive.Kind.Size()), value)
}

func primitiveOf(t Type) *Primitive {
	switch t := Unalias(t).(type) {
	case *Primitive:
		return t
	case *Enum:
		return t.Underlying
	}
	return nil
}

func (p *parserEmitter) memberStore(target *MemberOf, value string) string {
	if target.Field == nil {
		return ""
	}
	primitive := primitiveOf(target.Field.Type)
	if primitive == nil {
		return ""
	}
	metadata := fmt.Sprintf("%s.$fields.%s", p.expression(target.Object), target.Name)
	return p.primitiveStore(primitive, location{base: metadata + ".base", offset: metadata + ".offset"}, metadata+".size", value)
}

func (p *parserEmitter) primitiveStore(primitive *Primitive, address location, size string, value string) string {
	switch {
	case primitive.Kind == Float || primitive.Kind == Double:
		return fmt.Sprintf("%s(%s, %s, %q, %s, %s)", p.helper("$writeScalar"), address.arguments(), size, viewMethod(primitive.Kind, "set"), value, p.orderLiteral(primitive.Order))
	case primitive.Kind == Char || primitive.Kind == Char16:
		return fmt.Sprintf("%s(%s, %s, String(%s).charCodeAt(0), %s)", p.helper("$writeUint"), address.arguments(), size, value, p.orderLiteral(primitive.Order))
	case primitive.Kind == Bool:
		return fmt.Sprintf("%s(%s, %s, %s(%s) ? 1 : 0, %s)", p.helper("$writeUint"), address.arguments(), size, p.helper("$truthy"), value, p.orderLiteral(primitive.Order))
	}
	return fmt.Sprintf("%s(%s, %s, %s, %s)", p.helper("$writeUint"), address.arguments(), size, value, p.orderLiteral(primitive.Order))
}

func localName(local *Local) string {
	return "$v_" + local.Name
}

func (p *parserEmitter) localAccess(local *Local) string {
	if local.Export || local.Member {
		return "$this." + local.Name
	}
	if local.Global {
		return "$env.globals." + local.Name
	}
	if local.Ref {
		return localName(local) + ".v"
	}
	return localName(local)
}

func (p *parserEmitter) globalAccess(ref *GlobalRef) string {
	access := "$env.root." + ref.Path[0]
	if ref.Local != nil {
		access = p.localAccess(ref.Local)
	} else if ref.Field == nil {
		access = fmt.Sprintf("%s(%q)", p.helper("$unknown"), ref.Path[0])
	}
	for _, name := range ref.Rest {
		access += "." + name
	}
	return access
}

func (p *parserEmitter) emitBitMember(member *BitfieldMember, indent string) {
	width := p.expression(member.bits)
	if member.Name == "" {
		fmt.Fprintf(p.out, "%s$bit += %s;\n", indent, width)
		return
	}
	t := p.t.(*Bitfield)
	value := fmt.Sprintf("%s($env.base, $start, $pos, $width, $big)", p.helper("$readBitRange"))
	switch {
	case member.Bool:
		value += " !== 0"
	case member.Signed:
		value = fmt.Sprintf("%s(%s, $width)", p.helper("$signExtend"), value)
	}
	fmt.Fprintf(p.out, "%s{\n", indent)
	fmt.Fprintf(p.out, "%s    const $width = %s;\n", indent, width)
	fmt.Fprintf(p.out, "%s    const $big = %s;\n", indent, p.bigEndian(t))
	fmt.Fprintf(p.out, "%s    const $pos = %s;\n", indent, p.bitPosition(t))
	fmt.Fprintf(p.out, "%s    $this.%s = %s;\n", indent, member.Name, value)
	fmt.Fprintf(p.out, "%s    %s.%s = new %s($env.base, $start + Math.floor($pos / 8), Math.ceil(($pos %% 8 + $width) / 8), $pos, $width);\n", indent, p.fields(), member.Name, p.helper("$BitSpan"))
	fmt.Fprintf(p.out, "%s    $bit += $width;\n", indent)
	fmt.Fprintf(p.out, "%s}\n", indent)
}

func (p *parserEmitter) bigEndian(t *Bitfield) string {
	switch t.Order {
	case BigEndian:
		return "true"
	case LittleEndian:
		return "false"
	}
	return "!$env.littleEndian"
}

func (p *parserEmitter) bitPosition(t *Bitfield) string {
	switch t.Direction {
	case MostToLeastSignificant:
		return fmt.Sprintf("($big ? $bit : %d - $bit - $width)", t.FixedBits)
	case LeastToMostSignificant:
		return fmt.Sprintf("($big ? %d - $bit - $width : $bit)", t.FixedBits)
	}
	return "$bit"
}

func (p *parserEmitter) emitNestedBitfield(field *Field, indent string) {
	fmt.Fprintf(p.out, "%s{\n", indent)
	fmt.Fprintf(p.out, "%s    const $first = $bit;\n", indent)
	switch t := Unalias(field.Type).(type) {
	case *Bitfield:
		fmt.Fprintf(p.out, "%s    const $value = %s.$parse($start + Math.floor($bit / 8), $env, $this, [%s], $bit %% 8);\n", indent, p.typeRef(t.Name), p.typeArguments(t))
		fmt.Fprintf(p.out, "%s    $bit += $value.$bits;\n", indent)
	case *Array:
		element := Unalias(t.Element).(*Bitfield)
		fmt.Fprintf(p.out, "%s    const $value = [];\n", indent)
		fmt.Fprintf(p.out, "%s    for (let $i = 0, $n = Number(%s); $i !== $n; $i++) {\n", indent, p.expression(t.Length))
		fmt.Fprintf(p.out, "%s        const $item = %s.$parse($start + Math.floor($bit / 8), $env, $this, [%s], $bit %% 8);\n", indent, p.typeRef(element.Name), p.typeArguments(element))
		fmt.Fprintf(p.out, "%s        $value.push($item);\n", indent)
		fmt.Fprintf(p.out, "%s        $bit += $item.$bits;\n", indent)
		fmt.Fprintf(p.out, "%s    }\n", indent)
	}
	fmt.Fprintf(p.out, "%s    $this.%s = $value;\n", indent, field.Name)
	fmt.Fprintf(p.out, "%s    %s.%s = new %s($env.base, $start + Math.floor($first / 8), Math.ceil(($first %% 8 + $bit - $first) / 8), $first, $bit - $first);\n", indent, p.fields(), field.Name, p.helper("$BitSpan"))
	fmt.Fprintf(p.out, "%s}\n", indent)
}

func (p *parserEmitter) emitField(field *Field, indent string, sequential bool) {
	if p.bits && isBitfieldOrArrayOf(field.Type) && field.Name != "" {
		p.emitNestedBitfield(field, indent)
		return
	}
	uses := slices.Concat(field.Attributes, typeAttributesApplyingToField(field.Type))
	if size, align, isFixed := p.fixedLayout(field.Type); isFixed && p.staticCursor.known && sequential && field.Address == nil &&
		field.Section == nil && !field.NoUniqueAddress && field.Order == NativeOrder && field.PointerBase == nil && len(uses) == 0 &&
		field.Name != "" {
		p.emitStaticField(field, indent, size, align)
		return
	}
	p.leaveStaticCursor(indent)
	if p.bits {
		fmt.Fprintf(p.out, "%s$bit = Math.ceil($bit / 8) * 8;\n", indent)
		fmt.Fprintf(p.out, "%s$env.cursor = $start + $bit / 8;\n", indent)
	}
	if p.union {
		fmt.Fprintf(p.out, "%s$env.cursor = $start;\n", indent)
	}
	address := "$env.cursor"
	env := "$env"
	if field.Section != nil {
		env = "$senv"
		address = fmt.Sprintf("%s(%s)", p.helper("$pointerDelta"), p.expression(field.Address))
	} else if field.Address != nil {
		address = fmt.Sprintf("%s(%s)", p.helper("$pointerDelta"), p.expression(field.Address))
	} else if sequential {
		address = p.aligned("$env.cursor", field.Type)
	}
	advance := sequential && (field.Address == nil || p.global) && !field.NoUniqueAddress && field.Section == nil

	if _, isPadding := field.Type.(*Padding); isPadding || field.Name == "" {
		fmt.Fprintf(p.out, "%s$env.cursor = %s + %s;\n", indent, address, p.sizeOf(field.Type, address))
		return
	}

	reader := p.reader(field.Type, "$at")
	if field.Section != nil {
		reader = fmt.Sprintf("(($env) => %s)($senv)", reader)
	}
	fmt.Fprintf(p.out, "%s{\n", indent)
	if !advance {
		fmt.Fprintf(p.out, "%s    const $resume = $env.cursor;\n", indent)
	}
	if field.Section != nil {
		fmt.Fprintf(p.out, "%s    const $senv = %s($env, %s);\n", indent, p.helper("$sectionEnvironment"), p.expression(field.Section))
		fmt.Fprintf(p.out, "%s    %s($senv.base.section, () => {\n", indent, p.helper("$placeInSection"))
		indent += "    "
	}
	fmt.Fprintf(p.out, "%s    const $at = %s;\n", indent, address)
	size, _, isFixed := p.fixedLayout(field.Type)
	switch {
	case field.Order != NativeOrder:
		fmt.Fprintf(p.out, "%s    const $order = %s.littleEndian;\n", indent, env)
		fmt.Fprintf(p.out, "%s    %s.littleEndian = %t;\n", indent, env, field.Order == LittleEndian)
		fmt.Fprintf(p.out, "%s    let $value, $n;\n", indent)
		fmt.Fprintf(p.out, "%s    try { [$value, $n] = %s; } finally { %s.littleEndian = $order; }\n", indent, reader, env)
	case isFixed && field.Section == nil:
		fmt.Fprintf(p.out, "%s    let $value = %s;\n", indent, p.fixedReader(field.Type, "$at"))
		fmt.Fprintf(p.out, "%s    const $n = %d;\n", indent, size)
	default:
		fmt.Fprintf(p.out, "%s    let [$value, $n] = %s;\n", indent, reader)
	}
	fmt.Fprintf(p.out, "%s    %s(%s, $at, $n);\n", indent, p.helper("$check"), env)
	if field.PointerBase != nil {
		fmt.Fprintf(p.out, "%s    $value = $value.add(%s($env, $this, $value));\n", indent, p.functionRef(field.PointerBase))
	}
	fmt.Fprintf(p.out, "%s    $this.%s = $value;\n", indent, field.Name)
	fmt.Fprintf(p.out, "%s    %s.%s = new %s(%s.base, $at, $n);\n", indent, p.fields(), field.Name, p.helper("$Span"), env)
	p.emitFieldMetadata(field, indent+"    ", "$value")
	for _, use := range uses {
		p.emitAttribute(use, indent+"    ", "$this."+field.Name, p.fields()+"."+field.Name)
	}
	if advance {
		if hasAttribute(uses, "fixed_size") {
			fmt.Fprintf(p.out, "%s    $env.cursor = $at + %s.%s.size;\n", indent, p.fields(), field.Name)
		} else {
			fmt.Fprintf(p.out, "%s    $env.cursor = $at + $n;\n", indent)
		}
		if p.bits {
			fmt.Fprintf(p.out, "%s    $bit = ($env.cursor - $start) * 8;\n", indent)
		}
	}
	if field.Section != nil {
		indent = indent[4:]
		fmt.Fprintf(p.out, "%s    });\n", indent)
	}
	if !advance {
		fmt.Fprintf(p.out, "%s    $env.cursor = $resume;\n", indent)
	}
	fmt.Fprintf(p.out, "%s}\n", indent)
}

func typeAttributesApplyingToField(t Type) []*AttributeUse {
	var uses []*AttributeUse
	if isView(t) {
		for alias, isAlias := t.(*Alias); isAlias; alias, isAlias = alias.Target.(*Alias) {
			uses = append(uses, alias.Attributes...)
		}
		return uses
	}
	for _, typed := range attributedTypes(t) {
		uses = append(uses, typed...)
	}
	return uses
}

func (p *parserEmitter) emitStaticField(field *Field, indent string, size int, align int) {
	offset := (p.staticCursor.offset + align - 1) / align * align
	at := "$start"
	if offset != 0 {
		at = fmt.Sprintf("$start + %d", offset)
	}
	value := fmt.Sprintf("%s($env, %s, %d, %s)", p.helper("$checked"), at, size, p.fixedReader(field.Type, at))
	if _, isPointer := Unalias(field.Type).(*Pointer); isPointer {
		fmt.Fprintf(p.out, "%s{\n", indent)
		fmt.Fprintf(p.out, "%s    const $value = %s;\n", indent, value)
		fmt.Fprintf(p.out, "%s    $this.%s = $value;\n", indent, field.Name)
		fmt.Fprintf(p.out, "%s    %s.%s = new %s($env.base, %s, %d);\n", indent, p.fields(), field.Name, p.helper("$Span"), at, size)
		p.emitFieldMetadata(field, indent+"    ", "$value")
		fmt.Fprintf(p.out, "%s}\n", indent)
	} else {
		fmt.Fprintf(p.out, "%s$this.%s = %s;\n", indent, field.Name, value)
		fmt.Fprintf(p.out, "%s%s.%s = new %s($env.base, %s, %d);\n", indent, p.fields(), field.Name, p.helper("$Span"), at, size)
		p.emitFieldMetadata(field, indent, "")
	}
	p.staticCursor.offset = offset + size
	p.staticCursor.moved = true
}

func (p *parserEmitter) emitFieldMetadata(field *Field, indent string, value string) {
	if pointer, isPointer := Unalias(field.Type).(*Pointer); isPointer {
		fmt.Fprintf(p.out, "%s%s.%s.target = () => %s;\n", indent, p.fields(), field.Name, p.reader(pointer.Target, fmt.Sprintf("%s($env.base, %s)", p.helper("$offset"), value)))
	}
	if field.Hidden {
		fmt.Fprintf(p.out, "%s%s.%s.hidden = true;\n", indent, p.fields(), field.Name)
	}
	if field.Doc != "" {
		fmt.Fprintf(p.out, "%s%s.%s.comment = %s;\n", indent, p.fields(), field.Name, strconv.Quote(field.Doc))
	}
}

func (p *parserEmitter) fields() string {
	if p.inFunction {
		return "$this.$fields"
	}
	return "$fields"
}

func (p *parserEmitter) leaveStaticCursor(indent string) {
	if p.staticCursor.moved {
		fmt.Fprintf(p.out, "%s$env.cursor = $start + %d;\n", indent, p.staticCursor.offset)
	}
	p.staticCursor = staticCursor{}
}

func (p *parserEmitter) fixedLayout(t Type) (size int, align int, isFixed bool) {
	switch t := Unalias(t).(type) {
	case *Primitive:
		size = t.Kind.Size()
	case *Enum:
		if t.Encoding != nil {
			return 0, 0, false
		}
		size = t.Underlying.Kind.Size()
	case *Pointer:
		if t.Width == nil {
			return 0, 0, false
		}
		size = t.Width.Kind.Size()
	default:
		return 0, 0, false
	}
	align = 1
	if p.abi != PackedABI {
		align = naturalAlign(size)
	}
	return size, align, true
}

func (p *parserEmitter) fixedReader(t Type, offset string) string {
	switch t := Unalias(t).(type) {
	case *Primitive:
		return p.primitiveReader(t, inEnvironment(offset))
	case *Enum:
		return p.primitiveReader(t.Underlying, inEnvironment(offset))
	case *Pointer:
		return p.pointerReader(t, inEnvironment(offset))
	}
	panic("unreachable")
}

func hasAttribute(uses []*AttributeUse, name string) bool {
	for _, use := range uses {
		if use.Name == name {
			return true
		}
	}
	return false
}

func (p *parserEmitter) emitAttribute(use *AttributeUse, indent string, target string, metadata string) {
	arguments := make([]string, len(use.Arguments))
	for i, argument := range use.Arguments {
		arguments[i] = p.expression(argument)
	}
	switch use.Name {
	case "name":
		fmt.Fprintf(p.out, "%s%s.displayName = %s(%s);\n", indent, metadata, p.helper("$display"), arguments[0])
	case "comment":
		fmt.Fprintf(p.out, "%s%s.comment = %s(%s);\n", indent, metadata, p.helper("$display"), arguments[0])
	case "color":
		fmt.Fprintf(p.out, "%s%s.color = %s(%s);\n", indent, metadata, p.helper("$display"), arguments[0])
	case "hidden", "highlight_hidden", "tree_hidden":
		fmt.Fprintf(p.out, "%s%s.hidden = true;\n", indent, metadata)
	case "inline":
		fmt.Fprintf(p.out, "%s%s.inline = true;\n", indent, metadata)
	case "sealed":
		fmt.Fprintf(p.out, "%s%s.sealed = true;\n", indent, metadata)
	case "format", "format_read":
		fmt.Fprintf(p.out, "%s%s.formatted = %s(%s);\n", indent, metadata, p.helper("$display"), p.attributeCall(use, target))
	case "format_entries", "format_read_entries":
		fmt.Fprintf(p.out, "%s%s.formattedEntries = %s.map((entry) => %s(%s));\n", indent, metadata, target, p.helper("$display"), p.attributeCall(use, "entry"))
	case "fixed_size":
		if target == "$this" {
			fmt.Fprintf(p.out, "%s$this.$size = Number(%s);\n", indent, arguments[0])
		} else {
			fmt.Fprintf(p.out, "%s%s.size = Number(%s);\n", indent, metadata, arguments[0])
		}
	case "transform":
		if target == "$this" {
			fmt.Fprintf(p.out, "%sObject.defineProperty($this, \"$transformed\", { value: %s, configurable: true });\n", indent, p.attributeCall(use, target))
		} else {
			fmt.Fprintf(p.out, "%s%s = %s;\n", indent, target, p.attributeCall(use, target))
		}
	case "transform_entries":
		fmt.Fprintf(p.out, "%s%s = %s.map((entry) => %s);\n", indent, target, target, p.attributeCall(use, "entry"))
	}
}

func (p *parserEmitter) attributeCall(use *AttributeUse, argument string) string {
	if use.Dynamic != nil {
		return fmt.Sprintf("%s(%s, $env, $this, %s, %s)", p.helper("$callNamed"), p.namedFunctionsRef(), p.expression(use.Dynamic), argument)
	}
	if use.Function != nil {
		return fmt.Sprintf("%s($env, $this, %s)", p.functionRef(use.Function), attributeArgument(use.Function, argument))
	}
	return fmt.Sprintf("%s($env, %s)", p.helper(builtins[use.Builtin].js), argument)
}

func attributeArgument(f *Function, argument string) string {
	if len(f.Params) > 0 && f.Params[0].Ref {
		return fmt.Sprintf("{ v: %s }", argument)
	}
	return argument
}

func (p *parserEmitter) aligned(cursor string, t Type) string {
	if p.abi == PackedABI {
		return cursor
	}
	align := p.alignOf(t)
	if align == "1" {
		return cursor
	}
	return fmt.Sprintf("%s(%s, %s, %s)", p.helper("$alignCursor"), p.start(), cursor, align)
}

func (p *parserEmitter) start() string {
	if p.inFunction {
		return fmt.Sprintf("%s($env.base, $this.$address)", p.helper("$offset"))
	}
	return "$start"
}

func (p *parserEmitter) alignOf(t Type) string {
	switch t := Unalias(t).(type) {
	case *Primitive:
		return fmt.Sprintf("%d", naturalAlign(t.Kind.Size()))
	case *Enum:
		if t.Encoding != nil {
			return p.alignOf(t.Encoding)
		}
		return fmt.Sprintf("%d", naturalAlign(t.Underlying.Kind.Size()))
	case *Pointer:
		if t.Width != nil {
			return fmt.Sprintf("%d", naturalAlign(t.Width.Kind.Size()))
		}
		return "Process.pointerSize"
	case *Bitfield:
		return fmt.Sprintf("%d", naturalAlign((t.TotalBits+7)/8))
	case *Array:
		return p.alignOf(t.Element)
	case *Struct, *Union:
		return p.typeRef(t.(NamedType).TypeName()) + ".$align"
	}
	return "1"
}

func naturalAlign(size int) int {
	if size&(size-1) != 0 || size > 8 {
		return 1
	}
	return size
}

func (p *parserEmitter) sizeOf(t Type, address string) string {
	switch t := Unalias(t).(type) {
	case *Primitive:
		return fmt.Sprintf("%d", t.Kind.Size())
	case *Enum:
		if t.Encoding != nil {
			return p.sizeOf(t.Encoding, address)
		}
		return fmt.Sprintf("%d", t.Underlying.Kind.Size())
	case *Pointer:
		if t.Width != nil {
			return fmt.Sprintf("%d", t.Width.Kind.Size())
		}
		return "Process.pointerSize"
	case *Bitfield:
		return fmt.Sprintf("%d", (t.TotalBits+7)/8)
	case *Padding:
		if t.While != nil {
			condition := p.withCursor("p", func() string { return p.condition(t.While) })
			return fmt.Sprintf("%s($env, %s, (p) => %s)", p.helper("$padWhile"), address, condition)
		}
		return p.expression(t.Size)
	}
	return fmt.Sprintf("%s[1]", p.reader(t, address))
}

func (p *parserEmitter) reader(t Type, address string) string {
	switch t := t.(type) {
	case *Primitive:
		return fmt.Sprintf("[%s, %d]", p.primitiveReader(t, inEnvironment(address)), t.Kind.Size())
	case *Enum:
		if t.Encoding != nil {
			return fmt.Sprintf("%s(%s)", p.helper("$patternReading"), p.reader(Unalias(t.Encoding), address))
		}
		return fmt.Sprintf("[%s, %d]", p.primitiveReader(t.Underlying, inEnvironment(address)), t.Underlying.Kind.Size())
	case *Struct, *Union, *Bitfield:
		return fmt.Sprintf("%s(%s.$parse(%s, $env, $this, [%s]))", p.helper("$parsed"), p.typeRef(t.(NamedType).TypeName()), address, p.typeArguments(t))
	case *Pointer:
		return fmt.Sprintf("[%s, %s]", p.pointerReader(t, inEnvironment(address)), p.sizeOf(t, address))
	case *Array:
		return p.arrayReader(t, address)
	case *Alias:
		return p.reader(t.Target, address)
	}
	panic("unreachable")
}

func (p *parserEmitter) typeArguments(t Type) string {
	arguments := make([]string, len(typeArgs(t)))
	p.scoping = true
	for i, arg := range typeArgs(t) {
		arguments[i] = p.expression(arg)
	}
	p.scoping = false
	return strings.Join(arguments, ", ")
}

func (p *parserEmitter) arrayReader(t *Array, address string) string {
	kind := characterKind(t.Element)
	if t.While != nil {
		condition := p.withCursor("p", func() string { return p.condition(t.While) })
		return fmt.Sprintf("%s($env, %s, (p) => %s, (p) => %s)", p.helper("$parseWhile"), address, condition, p.reader(t.Element, "p"))
	}
	if t.Length == nil {
		if kind == Char16 {
			return fmt.Sprintf("%s(%s)", p.helper("$parseCString16"), inEnvironment(address).arguments())
		}
		return fmt.Sprintf("%s(%s)", p.helper("$parseCString"), inEnvironment(address).arguments())
	}
	length := numeric(p.expression(t.Length))
	switch kind {
	case Char:
		return fmt.Sprintf("[%s(%s, %s), %s]", p.helper("$readString"), inEnvironment(address).arguments(), length, length)
	case Char16:
		return fmt.Sprintf("[%s(%s, %s), (%s) * 2]", p.helper("$readString16"), inEnvironment(address).arguments(), length, length)
	}
	return fmt.Sprintf("%s($env, %s, %s, (p) => %s)", p.helper("$parseArray"), address, length, p.reader(t.Element, "p"))
}

func (p *parserEmitter) withCursor(variable string, emit func() string) string {
	previous := p.cursor
	p.cursor = variable
	result := emit()
	p.cursor = previous
	return result
}

func (p *parserEmitter) cursorVariable() string {
	if p.cursor == "" {
		return "$env.cursor"
	}
	return p.cursor
}

func (p *parserEmitter) expression(v Value) string {
	switch v := v.(type) {
	case *Constant:
		if v.Wide != nil {
			return v.Wide.String() + "n"
		}
		if v.Unsigned {
			return fmt.Sprintf("%dn", uint64(v.Value))
		}
		return fmt.Sprintf("%d", v.Value)
	case *StringConstant:
		return jsString(v.Value)
	case *FloatConstant:
		return strconv.FormatFloat(v.Value, 'g', -1, 64)
	case *EnumMemberRef:
		return fmt.Sprintf("%d", v.Member.Value)
	case *FieldRef:
		return integral(p.fieldPath(v.Path), v.Path[len(v.Path)-1].Type)
	case *ParentFieldRef:
		return fmt.Sprintf("%s.%s", p.ancestor(v.Depth), strings.Join(v.Path, "."))
	case *LocalRef:
		if p.scoping && v.Local.Member && !v.Local.Export {
			return fmt.Sprintf("%s($this, %q)", p.helper("$scoped"), v.Local.Name)
		}
		return p.localAccess(v.Local)
	case *BitRef:
		return "$this." + v.Member.Name
	case *GlobalRef:
		return p.globalAccess(v)
	case *ArrayValue:
		elements := make([]string, len(v.Elements))
		for i, element := range v.Elements {
			elements[i] = p.expression(element)
		}
		return "[" + strings.Join(elements, ", ") + "]"
	case *Index:
		return fmt.Sprintf("%s(%s, %s)", p.helper("$index"), p.expression(v.Object), p.expression(v.Index))
	case *MemberOf:
		return fmt.Sprintf("%s.%s", p.memberOwner(v.Object), v.Name)
	case *Cursor:
		return fmt.Sprintf("%s(%s)", p.helper("$cursorOffset"), p.cursorVariable())
	case *AddressOf:
		return p.targetOffset(v.Target)
	case *SizeOfValue:
		return p.targetSize(v.Target)
	case *ThisRef:
		return p.ancestor(v.Depth)
	case *SizeOf:
		return p.typeSize(v.Type)
	case *Builtin:
		return p.builtin(v)
	case *Labelled:
		return fmt.Sprintf("%s(%s, %q, %s)", p.helper("$labelled"), p.typeRef(v.Enum.Name), v.Enum.Name, p.expression(v.Value))
	case *TemplateArgument:
		return fmt.Sprintf("%s(%s)", p.helper("$templateArgument"), p.expression(v.Value))
	case *PatternTypeName:
		return p.expression(v.Target) + ".$typeName"
	case *FunctionCall:
		return p.functionCall(v)
	case *Cast:
		return p.cast(v)
	case *UnaryOp:
		operand := p.expression(v.Operand)
		if v.Operator == "!" {
			return fmt.Sprintf("!%s(%s)", p.helper("$truthy"), operand)
		}
		if v.Operator == "~" {
			return fmt.Sprintf("%s(%s)", p.helper("$bnot"), operand)
		}
		return fmt.Sprintf("(%s%s)", v.Operator, operand)
	case *BinaryOp:
		return p.binary(v)
	case *Select:
		return fmt.Sprintf("(%s ? %s : %s)", p.condition(v.Condition), p.expression(v.Then), p.expression(v.Else))
	}
	panic("unreachable")
}

func (p *parserEmitter) typeSize(t Type) string {
	if size := p.staticSize(t); size > 0 {
		return strconv.Itoa(size)
	}
	return p.sizeOf(t, "$env.cursor")
}

func jsString(value string) string {
	var literal strings.Builder
	literal.WriteByte('"')
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&literal, "\\u%04X", 0xDC00+int(value[0]))
		case r >= 0x20 && r < 0x7f && r != '"' && r != '\\':
			literal.WriteRune(r)
		case r < 0x10000:
			fmt.Fprintf(&literal, "\\u%04X", r)
		default:
			fmt.Fprintf(&literal, "\\u{%X}", r)
		}
		value = value[size:]
	}
	literal.WriteByte('"')
	return literal.String()
}

func (p *parserEmitter) binary(v *BinaryOp) string {
	left := p.operand(v.Left)
	right := p.operand(v.Right)
	switch v.Operator {
	case "&&", "||":
		return fmt.Sprintf("(%s(%s) %s %s(%s))", p.helper("$truthy"), left, v.Operator, p.helper("$truthy"), right)
	case "^^":
		return fmt.Sprintf("(%s(%s) !== %s(%s))", p.helper("$truthy"), left, p.helper("$truthy"), right)
	case "==":
		return fmt.Sprintf("%s(%s, %s)", p.helper("$eq"), left, right)
	case "!=":
		return fmt.Sprintf("!%s(%s, %s)", p.helper("$eq"), left, right)
	case "<", ">", "<=", ">=":
		return fmt.Sprintf("(%s %s %s)", left, v.Operator, right)
	case "+":
		if isCharConstant(v.Left) || isCharConstant(v.Right) {
			return fmt.Sprintf("%s(%s, %s, %t, %t)", p.helper("$charAdd"), left, right, isCharConstant(v.Left), isCharConstant(v.Right))
		}
	case "/", "%":
		if isStaticallyFloating(v.Left) || isStaticallyFloating(v.Right) {
			return fmt.Sprintf("(Number(%s) %s Number(%s))", left, v.Operator, right)
		}
	}
	if helper, isArithmetic := arithmeticHelpers[v.Operator]; isArithmetic {
		return fmt.Sprintf("%s(%s, %s)", p.helper(helper), left, right)
	}
	return fmt.Sprintf("(%s %s %s)", left, v.Operator, right)
}

var arithmeticHelpers = map[string]string{
	"+": "$add", "-": "$sub", "*": "$mul", "/": "$divide", "%": "$modulo",
	"<<": "$shl", ">>": "$shr", "&": "$band", "|": "$bor", "^": "$bxor",
}

func (p *parserEmitter) operand(v Value) string {
	if isComposite(staticTypeOf(v)) {
		return fmt.Sprintf("%s(%s)", p.helper("$patternInteger"), p.expression(v))
	}
	return p.expression(v)
}

func isStaticallyFloating(v Value) bool {
	switch v := v.(type) {
	case *FloatConstant:
		return true
	case *Cast:
		return v.Kind.IsFloatingPoint()
	case *UnaryOp:
		return isStaticallyFloating(v.Operand)
	case *BinaryOp:
		return arithmeticHelpers[v.Operator] != "" && (isStaticallyFloating(v.Left) || isStaticallyFloating(v.Right))
	case *Select:
		return isStaticallyFloating(v.Then) || isStaticallyFloating(v.Else)
	}
	primitive, isPrimitive := Unalias(staticTypeOf(v)).(*Primitive)
	return isPrimitive && primitive.Kind.IsFloatingPoint()
}

func isCharConstant(v Value) bool {
	constant, isConstant := v.(*Constant)
	return isConstant && constant.Char
}

func (p *parserEmitter) functionCall(call *FunctionCall) string {
	arguments := []string{"$env", "$this"}
	fixed := len(call.Function.Params)
	if call.Function.Variadic {
		fixed--
	}
	var pack []string
	for i, argument := range call.Arguments {
		switch {
		case i >= fixed:
			pack = append(pack, p.argument(argument))
		case call.Function.Params[i].Ref:
			arguments = append(arguments, p.reference(argument))
		default:
			arguments = append(arguments, p.argument(argument))
		}
	}
	if call.Function.Variadic {
		arguments = append(arguments, "["+strings.Join(pack, ", ")+"]")
	}
	return fmt.Sprintf("%s(%s)", p.functionRef(call.Function), strings.Join(arguments, ", "))
}

func (p *parserEmitter) argument(v Value) string {
	if isPack(v) {
		return "..." + p.expression(v)
	}
	return p.expression(v)
}

func (p *parserEmitter) reference(v Value) string {
	if local, isLocal := v.(*LocalRef); isLocal && local.Local.Ref {
		return localName(local.Local)
	}
	if !isReference(v) {
		return fmt.Sprintf("{ v: %s }", p.expression(v))
	}
	return fmt.Sprintf("{ get v() { return %s; }, set v($x) { %s = $x; } }", p.expression(v), p.lvalue(v))
}

func (p *parserEmitter) lvalue(v Value) string {
	if index, isIndex := v.(*Index); isIndex {
		return fmt.Sprintf("%s[%s]", p.expression(index.Object), p.expression(index.Index))
	}
	return p.expression(v)
}

func (p *parserEmitter) cast(v *Cast) string {
	operand := p.expression(v.Operand)
	switch {
	case v.Kind == Bool:
		return fmt.Sprintf("%s(%s)", p.helper("$truthy"), operand)
	case v.Kind.IsFloatingPoint():
		return fmt.Sprintf("Number(%s)", operand)
	case v.Kind == Char || v.Kind == Char16:
		return fmt.Sprintf("String.fromCharCode(Number(%s))", operand)
	}
	operand = fmt.Sprintf("%s(%s)", p.helper("$packedString"), operand)
	switch {
	case v.Kind.Size() >= 8:
		return fmt.Sprintf("Number(%s)", operand)
	case v.Kind.IsSigned():
		return fmt.Sprintf("%s(Number(%s) & %d, %d)", p.helper("$signExtend"), operand, 1<<(v.Kind.Size()*8)-1, v.Kind.Size()*8)
	}
	return fmt.Sprintf("(Number(%s) & %d)", operand, 1<<(v.Kind.Size()*8)-1)
}

func (p *parserEmitter) fieldPath(path []*Field) string {
	value := "$this"
	for _, field := range path {
		if _, isPointer := Unalias(field.Type).(*Pointer); isPointer {
			value = fmt.Sprintf("%s(%s.$fields.%s)", p.helper("$pointee"), value, field.Name)
			continue
		}
		value += "." + field.Name
	}
	return value
}

func pointerTypeOf(path []*Field) *Pointer {
	pointer, _ := Unalias(path[len(path)-1].Type).(*Pointer)
	return pointer
}

func integral(value string, t Type) string {
	switch t := Unalias(t).(type) {
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

func (p *parserEmitter) ancestor(depth int) string {
	if p.inFunction && depth > 0 {
		depth--
	}
	return "$this" + strings.Repeat(".$parent", depth)
}

func (p *parserEmitter) targetOffset(target Value) string {
	if member, isMember := target.(*MemberOf); isMember && member.Field == nil {
		return fmt.Sprintf("%s($env, %s)", p.helper("$addressOf"), p.memberSpan(member))
	}
	location := p.targetLocation(target)
	if location.offset == "0" {
		return fmt.Sprintf("%s($env.base, %s)", p.helper("$offset"), location.base)
	}
	return location.offset
}

func (p *parserEmitter) targetLocation(target Value) location {
	switch v := target.(type) {
	case *FieldRef:
		owner, last := p.fieldPath(v.Path[:len(v.Path)-1]), v.Path[len(v.Path)-1].Name
		return fieldLocation(fmt.Sprintf("%s.$fields.%s", owner, last))
	case *ParentFieldRef:
		return fieldLocation(fmt.Sprintf("%s.$fields.%s", parentOwner(p.ancestor(v.Depth), v.Path), v.Path[len(v.Path)-1]))
	case *ThisRef:
		return at(p.ancestor(v.Depth) + ".$address")
	case *GlobalRef:
		if v.Local != nil {
			return at(p.globalAccess(v) + ".$address")
		}
		return fieldLocation(fmt.Sprintf("%s.$fields.%s", parentOwner("$env.root", v.Path), v.Path[len(v.Path)-1]))
	case *MemberOf:
		if v.Field != nil {
			return fieldLocation(fmt.Sprintf("%s.$fields.%s", p.memberOwner(v.Object), v.Name))
		}
		span := p.memberSpan(v)
		return location{base: span + ".base", offset: span + ".offset"}
	case *Index, *LocalRef:
		return at(p.expression(v) + ".$address")
	}
	panic("unreachable")
}

func fieldLocation(metadata string) location {
	return location{base: metadata + ".base", offset: metadata + ".offset"}
}

func parentOwner(ancestor string, path []string) string {
	owner := ancestor
	for _, name := range path[:len(path)-1] {
		owner += "." + name
	}
	return owner
}

func (p *parserEmitter) targetSize(target Value) string {
	switch v := target.(type) {
	case *FieldRef:
		owner, last := p.fieldPath(v.Path[:len(v.Path)-1]), v.Path[len(v.Path)-1].Name
		if pointerTypeOf(v.Path) != nil {
			return fmt.Sprintf("%s.$fields.%s.target()[1]", owner, last)
		}
		return fmt.Sprintf("%s.$fields.%s.size", owner, last)
	case *ParentFieldRef:
		return fmt.Sprintf("%s.$fields.%s.size", parentOwner(p.ancestor(v.Depth), v.Path), v.Path[len(v.Path)-1])
	case *ThisRef:
		if v.Depth == 0 {
			return fmt.Sprintf("(%s - $start)", p.cursorVariable())
		}
		return p.ancestor(v.Depth) + ".$size"
	case *GlobalRef:
		if v.Local != nil {
			return p.globalAccess(v) + ".$size"
		}
		return fmt.Sprintf("%s.$fields.%s.size", parentOwner("$env.root", v.Path), v.Path[len(v.Path)-1])
	case *MemberOf:
		if v.Field != nil {
			if _, isPointer := Unalias(v.Field.Type).(*Pointer); isPointer {
				return fmt.Sprintf("%s.$fields.%s.target()[1]", p.memberOwner(v.Object), v.Name)
			}
			return fmt.Sprintf("%s.$fields.%s.size", p.memberOwner(v.Object), v.Name)
		}
		return p.memberSpan(v) + ".size"
	case *Index, *LocalRef:
		return fmt.Sprintf("%s(%s)", p.helper("$sizeOf"), p.expression(v))
	}
	panic("unreachable")
}

func (p *parserEmitter) memberSpan(member *MemberOf) string {
	return fmt.Sprintf("%s(%s, %q)", p.helper("$memberSpan"), p.memberOwner(member.Object), member.Name)
}

func (p *parserEmitter) memberOwner(object Value) string {
	if member, isMember := object.(*MemberOf); isMember && member.Field == nil {
		return fmt.Sprintf("%s(%s, %q)", p.helper("$memberOwner"), p.memberOwner(member.Object), member.Name)
	}
	if _, isPointer := Unalias(staticTypeOf(object)).(*Pointer); isPointer {
		switch o := object.(type) {
		case *MemberOf:
			return fmt.Sprintf("%s(%s.$fields.%s)", p.helper("$pointee"), p.memberOwner(o.Object), o.Name)
		case *FieldRef:
			return fmt.Sprintf("%s(%s.$fields.%s)", p.helper("$pointee"), p.fieldPath(o.Path[:len(o.Path)-1]), o.Path[len(o.Path)-1].Name)
		}
	}
	return p.expression(object)
}

func (p *parserEmitter) builtin(call *Builtin) string {
	arguments := []string{"$env"}
	for i, argument := range call.Arguments {
		if i == 0 && call.Name == "std::mem::copy_value_to_section" {
			if denotesPattern(argument) {
				location := p.targetLocation(argument)
				arguments = append(arguments, fmt.Sprintf("{ base: %s, offset: %s, size: %s }", location.base, location.offset, p.targetSize(argument)))
			} else {
				arguments = append(arguments, fmt.Sprintf("%s(%s)", p.helper("$stringRef"), p.expression(argument)))
			}
			continue
		}
		arguments = append(arguments, p.argument(argument))
	}
	return fmt.Sprintf("%s(%s)", p.helper(builtins[call.Name].js), strings.Join(arguments, ", "))
}

func denotesPattern(v Value) bool {
	switch v := v.(type) {
	case *FieldRef, *ParentFieldRef, *ThisRef, *Index, *MemberOf:
		return true
	case *GlobalRef:
		return v.Field != nil
	case *LocalRef:
		return isView(v.Local.Type)
	}
	return false
}

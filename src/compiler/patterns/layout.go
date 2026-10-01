package patterns

import (
	"fmt"
	"math/big"
	"strings"
)

type Target struct {
	PointerSize int
	MaxAlign    int
}

var Targets = []Target{
	{PointerSize: 8, MaxAlign: 8},
	{PointerSize: 4, MaxAlign: 8},
	{PointerSize: 4, MaxAlign: 4},
}

type ModuleLayout struct {
	Module *Module
	Target Target

	types   map[Type]*TypeLayout
	structs map[Type]*CompositeLayout
	pending map[Type]bool
	errors  []Diagnostic
}

type TypeLayout struct {
	Size    int
	Align   int
	Dynamic bool
}

type CompositeLayout struct {
	Fields []FieldLayout
	Size   int
	Align  int
}

type FieldLayout struct {
	Field   *Field
	Offset  int
	Align   int
	Dynamic bool
	Type    *TypeLayout
}

func (m *Module) Layout(target Target) *ModuleLayout {
	return &ModuleLayout{
		Module:  m,
		Target:  target,
		types:   map[Type]*TypeLayout{},
		structs: map[Type]*CompositeLayout{},
		pending: map[Type]bool{},
	}
}

func classifyStructs(m *Module) []Diagnostic {
	c := &classifier{verdicts: map[Type]bool{}, pending: map[Type]bool{}}
	for _, t := range m.Types {
		switch t := t.(type) {
		case *Struct:
			t.Simple = c.isSimple(t)
		case *Union:
			t.Simple = c.isSimple(t)
		}
	}
	return c.diagnostics
}

type classifier struct {
	verdicts    map[Type]bool
	pending     map[Type]bool
	guards      int
	diagnostics []Diagnostic
}

func (c *classifier) isSimple(t Type) bool {
	return c.visit(t, true)
}

func (c *classifier) visit(t Type, byValue bool) bool {
	if verdict, known := c.verdicts[t]; known {
		return verdict
	}
	if !byValue {
		c.guards++
		defer func() { c.guards-- }()
	}
	if c.pending[t] {
		if c.guards == 0 {
			c.diagnostics = append(c.diagnostics, Diagnostic{Position: typePosition(t), Message: "type contains itself by value"})
		}
		return false
	}
	c.pending[t] = true
	verdict := c.classify(t)
	delete(c.pending, t)
	c.verdicts[t] = verdict
	return verdict
}

func (c *classifier) classify(t Type) bool {
	switch t := t.(type) {
	case *Struct:
		if t.Base != nil && !c.isSimple(t.Base) {
			return false
		}
		return uniqueFieldNames(allFields(t)) && c.simpleStatements(t.Body)
	case *Union:
		if !t.Simple {
			return false
		}
		for _, field := range t.Fields {
			if field.Address != nil || !c.isSimple(field.Type) || !constantlySized(field.Type) {
				return false
			}
		}
		return true
	case *Bitfield:
		return t.Simple
	case *Enum:
		return t.Encoding == nil
	case *Array:
		if t.While != nil || (t.Length != nil && !isStaticValue(t.Length)) {
			return false
		}
		_, isConstant := t.Length.(*Constant)
		return c.visit(t.Element, t.Length == nil || isConstant)
	case *Alias:
		return c.isSimple(t.Target)
	case *Padding:
		return t.While == nil && isStaticValue(t.Size)
	}
	return true
}

func (c *classifier) simpleStatements(statements []Statement) bool {
	for _, statement := range statements {
		switch s := statement.(type) {
		case *Field:
			if s.Address != nil || !c.isSimple(s.Type) {
				return false
			}
		case *Conditional:
			if !isStaticValue(s.Condition) || !c.simpleStatements(s.Then) || !c.simpleStatements(s.Else) {
				return false
			}
		case *Match:
			for _, matchCase := range s.Cases {
				if !isStaticValue(matchCase.Condition) || !c.simpleStatements(matchCase.Then) {
					return false
				}
			}
			if !c.simpleStatements(s.Default) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func uniqueFieldNames(fields []*Field) bool {
	names := map[string]bool{}
	for _, field := range fields {
		if field.Name != "" && names[field.Name] {
			return false
		}
		names[field.Name] = true
	}
	return true
}

func isStaticValue(v Value) bool {
	switch v := v.(type) {
	case *Constant, *EnumMemberRef, *FieldRef, *ParentFieldRef, *SizeOf:
		return true
	case *SizeOfValue:
		return staticallySizedTarget(v)
	case *UnaryOp:
		return isStaticValue(v.Operand)
	case *BinaryOp:
		return isStaticValue(v.Left) && isStaticValue(v.Right)
	case *Select:
		return isStaticValue(v.Condition) && isStaticValue(v.Then) && isStaticValue(v.Else)
	}
	return false
}

func staticallySizedTarget(v *SizeOfValue) bool {
	ref, isFieldRef := v.Target.(*FieldRef)
	return isFieldRef && staticallySized(ref.Path[len(ref.Path)-1].Type)
}

func constantlySized(t Type) bool {
	switch t := t.(type) {
	case *Array:
		_, isConstant := t.Length.(*Constant)
		return t.While == nil && isConstant && constantlySized(t.Element)
	case *Struct:
		for _, field := range allFields(t) {
			if field.Guard != nil || !constantlySized(field.Type) {
				return false
			}
		}
		return t.Simple
	case *Union:
		for _, field := range t.Fields {
			if !constantlySized(field.Type) {
				return false
			}
		}
		return t.Simple
	case *Alias:
		return constantlySized(t.Target)
	case *Padding:
		_, isConstant := t.Size.(*Constant)
		return isConstant
	case *Enum:
		return t.Encoding == nil || constantlySized(t.Encoding)
	}
	return staticallySized(t)
}

func staticallySized(t Type) bool {
	switch t := t.(type) {
	case *Array:
		return t.While == nil && t.Length != nil && isStaticValue(t.Length) && staticallySized(t.Element)
	case *Struct:
		return t.Simple && staticallySizedFields(allFields(t))
	case *Union:
		return t.Simple && staticallySizedFields(t.Fields)
	case *Bitfield:
		return t.Simple
	case *Alias:
		return staticallySized(t.Target)
	case *Padding:
		return t.While == nil && isStaticValue(t.Size)
	case *Enum:
		return t.Encoding == nil || staticallySized(t.Encoding)
	}
	return true
}

func staticallySizedFields(fields []*Field) bool {
	for _, field := range fields {
		if field.Guard != nil || !staticallySized(field.Type) {
			return false
		}
	}
	return true
}

func (m *Module) validate() []Diagnostic {
	var diagnostics []Diagnostic
	for _, t := range m.Types {
		if enum, isEnum := t.(*Enum); isEnum {
			m.finalizeEnum(enum)
		}
	}
	for _, t := range m.Types {
		if bitfield, isBitfield := t.(*Bitfield); isBitfield {
			diagnostics = append(diagnostics, m.finalizeBitfield(bitfield)...)
		}
	}
	if len(diagnostics) > 0 {
		return diagnostics
	}
	for _, target := range Targets {
		layout := m.Layout(target)
		for _, t := range m.Types {
			layout.Of(t)
		}
		diagnostics = append(diagnostics, layout.errors...)
		if len(diagnostics) > 0 {
			return diagnostics
		}
	}
	return nil
}

func (m *Module) finalizeEnum(t *Enum) {
	if t.Underlying == nil {
		return
	}
	var members []*EnumMember
	next := big.NewInt(0)
	for _, member := range t.Members {
		if member.expr != nil {
			value, err := m.wideConstant(member.expr)
			if err != nil {
				m.warnAboutMember(t, member, err)
				continue
			}
			next = value
		}
		member.Value, member.Wide = narrowEnumValue(next)
		member.Last, member.WideLast = member.Value, member.Wide
		last := next
		if member.last != nil {
			value, err := m.wideConstant(member.last)
			if err != nil {
				m.warnAboutMember(t, member, err)
				continue
			}
			last = value
			member.Last, member.WideLast = narrowEnumValue(last)
		}
		next = new(big.Int).Add(last, big.NewInt(1))
		members = append(members, member)
	}
	t.Members = members
}

func (m *Module) warnAboutMember(t *Enum, member *EnumMember, err error) {
	m.Warnings = append(m.Warnings, Diagnostic{Position: t.Position, Message: fmt.Sprintf("%s::%s: %s", t.Name, member.Name, err)})
}

func (m *Module) finalizeBitfield(t *Bitfield) []Diagnostic {
	var diagnostics []Diagnostic
	if t.direction != nil && t.fixedBits != nil {
		direction, directionErr := m.constant(t.direction)
		size, sizeErr := m.constant(t.fixedBits)
		if directionErr != nil || sizeErr != nil || size <= 0 || direction < 0 || direction > 1 {
			return append(diagnostics, Diagnostic{Position: t.Position, Message: fmt.Sprintf("%s: bitfield_order expects a constant direction and a positive size", t.Name)})
		}
		t.Direction = BitOrder(direction + 1)
		t.FixedBits = int(size)
	}
	offset := 0
	for _, member := range t.Members {
		bits, err := m.constant(member.bits)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Position: t.Position, Message: fmt.Sprintf("%s.%s: %s", t.Name, member.Name, err)})
			continue
		}
		if bits <= 0 || bits > 64 {
			diagnostics = append(diagnostics, Diagnostic{Position: t.Position, Message: fmt.Sprintf("%s.%s: bit width must be between 1 and 64", t.Name, member.Name)})
			continue
		}
		member.Offset = offset
		member.Bits = int(bits)
		offset += int(bits)
	}
	t.TotalBits = offset
	if t.FixedBits > 0 {
		if offset > t.FixedBits {
			diagnostics = append(diagnostics, Diagnostic{Position: t.Position, Message: fmt.Sprintf("%s: the fields exceed the %d bits of bitfield_order", t.Name, t.FixedBits)})
		}
		t.TotalBits = t.FixedBits
	}
	return diagnostics
}

func (m *Module) constant(v Value) (int64, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid expression")
	}
	var result int64
	for i, target := range Targets {
		value, err := m.Layout(target).Evaluate(v, nil)
		if err != nil {
			return m.runtimeConstant(v)
		}
		if i == 0 {
			result = value
		} else if value != result {
			return 0, fmt.Errorf("expression depends on the target's pointer size")
		}
	}
	return result, nil
}

func (m *Module) runtimeConstant(v Value) (int64, error) {
	main := &section{}
	d := &decoder{layout: m.Layout(Targets[0]), sections: []*section{main}, active: main, littleEndian: true}
	f := d.newFrame(&DecodedValue{}, 0, nil, true)
	return f.evalInt(v)
}

func (m *Module) wideConstant(v Value) (*big.Int, error) {
	if number, err := m.constant(v); err == nil {
		return big.NewInt(number), nil
	}
	main := &section{}
	d := &decoder{layout: m.Layout(Targets[0]), sections: []*section{main}, active: main, littleEndian: true}
	f := d.newFrame(&DecodedValue{}, 0, nil, true)
	result, err := f.eval(v)
	if err != nil {
		return nil, err
	}
	return toBig(patternNumber(result))
}

func narrowEnumValue(v *big.Int) (int64, *big.Int) {
	if v.IsInt64() {
		return v.Int64(), nil
	}
	return 0, new(big.Int).Set(v)
}

func (l *ModuleLayout) Of(t Type) *TypeLayout {
	if layout, computed := l.types[t]; computed {
		return layout
	}
	if l.pending[t] {
		l.fail(t, "type contains itself by value")
		return &TypeLayout{Size: 0, Align: 1}
	}
	l.pending[t] = true
	layout := l.compute(t)
	delete(l.pending, t)
	l.types[t] = layout
	return layout
}

func (l *ModuleLayout) compute(t Type) *TypeLayout {
	switch t := t.(type) {
	case *Primitive:
		return l.scalar(t.Kind.Size())
	case *Pointer:
		if t.Width != nil {
			return l.scalar(t.Width.Kind.Size())
		}
		return l.scalar(l.Target.PointerSize)
	case *Enum:
		if t.Encoding != nil {
			return l.Of(t.Encoding)
		}
		return l.scalar(t.Underlying.Kind.Size())
	case *Bitfield:
		if !t.Simple {
			return &TypeLayout{Align: 1, Dynamic: true}
		}
		size := (t.TotalBits + 7) / 8
		return &TypeLayout{Size: size, Align: l.alignFor(size)}
	case *Padding:
		if t.While != nil || !l.isStatic(t.Size) {
			return &TypeLayout{Align: 1, Dynamic: true}
		}
		size, err := l.Evaluate(t.Size, nil)
		if err != nil {
			l.fail(t, err.Error())
			size = 0
		}
		return &TypeLayout{Size: int(size), Align: 1}
	case *Alias:
		return l.Of(t.Target)
	case *Array:
		return l.computeArray(t)
	case *Struct:
		if !t.Simple {
			return &TypeLayout{Align: 1, Dynamic: true}
		}
		return l.computeStruct(t)
	case *Union:
		if !t.Simple {
			return &TypeLayout{Align: 1, Dynamic: true}
		}
		return l.computeUnion(t)
	}
	panic("unreachable")
}

func (l *ModuleLayout) scalar(size int) *TypeLayout {
	return &TypeLayout{Size: size, Align: l.alignFor(size)}
}

func (l *ModuleLayout) alignFor(size int) int {
	if size&(size-1) != 0 {
		return 1
	}
	return min(size, l.Target.MaxAlign)
}

func fieldAlign(abi ABI, fieldType *TypeLayout) int {
	if abi == PackedABI {
		return 1
	}
	return fieldType.Align
}

func (l *ModuleLayout) computeArray(t *Array) *TypeLayout {
	element := l.Of(t.Element)
	if t.Length == nil || element.Dynamic {
		return &TypeLayout{Align: element.Align, Dynamic: true}
	}
	if length, isConstant := t.Length.(*Constant); isConstant {
		if length.Value < 0 {
			l.fail(t, "array length must not be negative")
		}
		return &TypeLayout{Size: int(length.Value) * element.Size, Align: element.Align}
	}
	if !l.isStatic(t.Length) {
		return &TypeLayout{Align: element.Align, Dynamic: true}
	}
	length, err := l.Evaluate(t.Length, nil)
	if err != nil {
		l.fail(t, err.Error())
	}
	return &TypeLayout{Size: int(length) * element.Size, Align: element.Align}
}

func (l *ModuleLayout) computeStruct(t *Struct) *TypeLayout {
	composite := &CompositeLayout{Align: 1}
	offset := 0
	dynamic := false
	for _, field := range allFields(t) {
		fieldType := l.Of(field.Type)
		align := fieldAlign(t.ABI, fieldType)
		composite.Align = max(composite.Align, align)
		if !dynamic {
			offset = alignUp(offset, align)
		}
		composite.Fields = append(composite.Fields, FieldLayout{Field: field, Offset: offset, Align: align, Dynamic: dynamic, Type: fieldType})
		switch {
		case field.NoUniqueAddress:
		case fieldType.Dynamic || field.Guard != nil:
			dynamic = true
		default:
			offset += fieldType.Size
		}
	}
	composite.Size = alignUp(offset, composite.Align)
	l.structs[t] = composite
	return &TypeLayout{Size: composite.Size, Align: composite.Align, Dynamic: dynamic}
}

func (l *ModuleLayout) computeUnion(t *Union) *TypeLayout {
	composite := &CompositeLayout{Align: 1}
	for _, field := range t.Fields {
		fieldType := l.Of(field.Type)
		if fieldType.Dynamic {
			l.fail(t, "unions may not contain dynamically sized fields")
			continue
		}
		align := fieldAlign(t.ABI, fieldType)
		composite.Align = max(composite.Align, align)
		composite.Size = max(composite.Size, fieldType.Size)
		composite.Fields = append(composite.Fields, FieldLayout{Field: field, Align: align, Type: fieldType})
	}
	composite.Size = alignUp(composite.Size, composite.Align)
	l.structs[t] = composite
	return &TypeLayout{Size: composite.Size, Align: composite.Align}
}

func (l *ModuleLayout) Composite(t Type) *CompositeLayout {
	l.Of(t)
	return l.structs[t]
}

func alignUp(offset, align int) int {
	return (offset + align - 1) / align * align
}

func (l *ModuleLayout) isStatic(v Value) bool {
	switch v := v.(type) {
	case *Constant, *EnumMemberRef, *SizeOf:
		return true
	case *SizeOfValue:
		return staticallySizedTarget(v)
	case *UnaryOp:
		return l.isStatic(v.Operand)
	case *BinaryOp:
		return l.isStatic(v.Left) && l.isStatic(v.Right)
	case *Select:
		return l.isStatic(v.Condition) && l.isStatic(v.Then) && l.isStatic(v.Else)
	}
	return false
}

type FieldValues interface {
	Field(path []*Field) (int64, error)
	ParentField(depth int, path []string) (int64, error)
	Dynamic(v Value) (int64, error)
}

func (l *ModuleLayout) Evaluate(v Value, readField FieldValues) (int64, error) {
	switch v := v.(type) {
	case *Constant:
		if v.Wide != nil {
			return 0, fmt.Errorf("the value does not fit 64 bits")
		}
		return v.Value, nil
	case *EnumMemberRef:
		if v.Member.Wide != nil {
			return 0, fmt.Errorf("the value does not fit 64 bits")
		}
		return v.Member.Value, nil
	case *FieldRef:
		if readField == nil {
			return 0, fmt.Errorf("%s is not a constant", v.Path[0].Name)
		}
		return readField.Field(v.Path)
	case *ParentFieldRef:
		if readField == nil {
			return 0, fmt.Errorf("parent.%s is not a constant", strings.Join(v.Path, "."))
		}
		return readField.ParentField(v.Depth, v.Path)
	case *SizeOfValue:
		if readField == nil {
			if !staticallySizedTarget(v) {
				return 0, fmt.Errorf("expression is not a constant")
			}
			return int64(l.Of(v.Target.(*FieldRef).Path[len(v.Target.(*FieldRef).Path)-1].Type).Size), nil
		}
		return readField.Dynamic(v)
	case *LocalRef, *GlobalRef, *BitRef, *Cursor, *AddressOf, *Builtin, *ThisRef, *FunctionCall, *Cast, *StringConstant, *FloatConstant, *Index, *MemberOf, *ArrayValue:
		if readField == nil {
			return 0, fmt.Errorf("expression is not a constant")
		}
		return readField.Dynamic(v)
	case *SizeOf:
		layout := l.Of(v.Type)
		if layout.Dynamic {
			return 0, fmt.Errorf("sizeof a dynamically sized type")
		}
		return int64(layout.Size), nil
	case *UnaryOp:
		operand, err := l.Evaluate(v.Operand, readField)
		if err != nil {
			return 0, err
		}
		return applyUnary(v.Operator, operand), nil
	case *BinaryOp:
		left, err := l.Evaluate(v.Left, readField)
		if err != nil {
			return 0, err
		}
		right, err := l.Evaluate(v.Right, readField)
		if err != nil {
			return 0, err
		}
		if (v.Operator == "/" || v.Operator == "%") && right == 0 {
			return 0, fmt.Errorf("division by zero")
		}
		return applyBinary(v.Operator, left, right), nil
	case *Select:
		condition, err := l.Evaluate(v.Condition, readField)
		if err != nil {
			return 0, err
		}
		if condition != 0 {
			return l.Evaluate(v.Then, readField)
		}
		return l.Evaluate(v.Else, readField)
	}
	panic("unreachable")
}

func (l *ModuleLayout) fail(t Type, message string) {
	l.errors = append(l.errors, Diagnostic{Position: typePosition(t), Message: message})
}

func typePosition(t Type) Position {
	switch t := t.(type) {
	case *Struct:
		return t.Position
	case *Union:
		return t.Position
	case *Enum:
		return t.Position
	case *Bitfield:
		return t.Position
	case *Alias:
		return t.Position
	}
	return Position{}
}

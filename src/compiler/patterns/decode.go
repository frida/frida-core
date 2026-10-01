package patterns

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

const maxDecodedElements = 1024

const maxPointerDepth = 16

type DecodedValue struct {
	ID          int             `json:"id"`
	Name        string          `json:"name,omitempty"`
	Type        string          `json:"type"`
	Address     string          `json:"address"`
	Offset      int             `json:"offset"`
	Size        *int            `json:"size"`
	Value       any             `json:"value,omitempty"`
	ValueKind   string          `json:"value_kind,omitempty"`
	Label       string          `json:"label,omitempty"`
	Count       *int            `json:"count,omitempty"`
	Fields      []*DecodedValue `json:"fields,omitempty"`
	Elements    []*DecodedValue `json:"elements,omitempty"`
	Truncated   bool            `json:"truncated,omitempty"`
	Error       string          `json:"error,omitempty"`
	DisplayName string          `json:"display_name,omitempty"`
	Formatted   string          `json:"formatted,omitempty"`
	Comment     string          `json:"comment,omitempty"`
	Color       string          `json:"color,omitempty"`
	Hidden      bool            `json:"hidden,omitempty"`
	Inline      bool            `json:"inline,omitempty"`
	Sealed      bool            `json:"sealed,omitempty"`
	BitOffset   *int            `json:"bit_offset,omitempty"`
	Bits        int             `json:"bits,omitempty"`
	Section     int             `json:"section,omitempty"`
	Visualizer  *Visualizer     `json:"visualizer,omitempty"`

	raw     runtimeValue
	frame   *frame
	typ     Type
	pointee *DecodedValue
	ending  flow
	storage storage
}

type storage int

const (
	byteStorage storage = iota
	valueStorage
)

func DecodeSource(source string, typeName string, data []byte, address uint64, target Target, inputs map[string]any) (string, error) {
	module, t, err := compileType(source, typeName)
	if err != nil {
		return "", err
	}
	value := DecodeWith(module, target, t, data, address, inputs)
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

func CallFunctionSource(source string, typeName string, data []byte, address uint64, target Target, inputs map[string]any, patternID int,
	functionName string) (string, error) {
	module, t, err := compileType(source, typeName)
	if err != nil {
		return "", err
	}
	output, err := CallFunction(module, target, t, data, address, inputs, patternID, functionName)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(struct {
		Output string `json:"output"`
	}{output})
	return string(encoded), err
}

func compileType(source string, typeName string) (*Module, Type, error) {
	module, diagnostics := Compile(source)
	if len(diagnostics) > 0 {
		return nil, nil, diagnostics[0]
	}
	for _, candidate := range module.Types {
		if candidate.TypeName() == typeName {
			return module, candidate, nil
		}
	}
	return nil, nil, fmt.Errorf("unknown type %s", typeName)
}

func Decode(module *Module, target Target, t Type, data []byte, address uint64) *DecodedValue {
	return DecodeWith(module, target, t, data, address, nil)
}

func DecodeWith(module *Module, target Target, t Type, data []byte, address uint64, inputs map[string]any) *DecodedValue {
	root := newDecoder(module, target, data, address, inputs).decode("", t, 0, nil)
	identify(root)
	return root
}

func CallFunction(module *Module, target Target, t Type, data []byte, address uint64, inputs map[string]any, patternID int,
	functionName string) (string, error) {
	function := module.function(functionName)
	if function == nil {
		return "", fmt.Errorf("unknown function %s", functionName)
	}
	d := newDecoder(module, target, data, address, inputs)
	root := d.decode("", t, 0, nil)
	identify(root)
	pattern := root.find(patternID)
	if pattern == nil {
		return "", fmt.Errorf("pattern %d is not part of the decoded value", patternID)
	}
	d.steps, d.log = 0, nil
	if _, err := d.newFrame(root, 0, nil, true).invoke(function, []runtimeValue{pattern}); err != nil {
		return "", err
	}
	return strings.Join(d.log, "\n"), nil
}

func newDecoder(module *Module, target Target, data []byte, address uint64, inputs map[string]any) *decoder {
	main := &section{data: data}
	d := &decoder{layout: module.Layout(target), sections: []*section{main}, active: main, base: address, littleEndian: true, inputs: map[string]runtimeValue{}}
	for name, value := range inputs {
		d.inputs[name] = inputValue(value)
	}
	return d
}

func inputValue(value any) runtimeValue {
	switch value := value.(type) {
	case float64:
		if value == math.Trunc(value) && math.Abs(value) < 1<<53 {
			return int64(value)
		}
		return value
	case int:
		return int64(value)
	case int64, uint64, bool, string:
		return value
	case json.Number:
		if number, err := value.Int64(); err == nil {
			return number
		}
		if number, err := strconv.ParseFloat(string(value), 64); err == nil {
			return number
		}
	}
	return fmt.Sprint(value)
}

func identify(root *DecodedValue) {
	nextID := 1
	var visualized []*DecodedValue
	var walk func(node *DecodedValue)
	walk = func(node *DecodedValue) {
		node.ID = nextID
		nextID++
		if node.Visualizer != nil {
			visualized = append(visualized, node)
		}
		for _, child := range node.Fields {
			walk(child)
		}
		for _, child := range node.Elements {
			walk(child)
		}
	}
	walk(root)
	for _, node := range visualized {
		for i := range node.Visualizer.Arguments {
			argument := &node.Visualizer.Arguments[i]
			if argument.target != nil {
				argument.Pattern = argument.target.ID
			}
		}
	}
}

func (v *DecodedValue) find(id int) *DecodedValue {
	if v.ID == id {
		return v
	}
	for _, children := range [][]*DecodedValue{v.Fields, v.Elements} {
		for _, child := range children {
			if found := child.find(id); found != nil {
				return found
			}
		}
	}
	return nil
}

type decoder struct {
	layout       *ModuleLayout
	sections     []*section
	active       *section
	base         uint64
	littleEndian bool
	steps        int
	pointers     int
	inputs       map[string]runtimeValue
	log          []string
	adopt        func(value *DecodedValue)
}

type section struct {
	id         int
	name       string
	data       []byte
	placements []*placement
	refreshing bool
}

type placement struct {
	node   *DecodedValue
	t      Type
	order  ByteOrder
	offset int
	frame  *frame
}

func (f *frame) allocationSize(t Type) (int, error) {
	if array, isArray := Unalias(t).(*Array); isArray && array.Length != nil {
		length, err := f.evalInt(array.Length)
		if err != nil {
			return 0, err
		}
		element, err := f.allocationSize(array.Element)
		return int(length) * element, err
	}
	layout := f.decoder.layout.Of(t)
	if layout.Dynamic {
		return 0, fmt.Errorf("%s has no static size", DescribeType(t))
	}
	return layout.Size, nil
}

func (d *decoder) createSection(name string) *section {
	created := &section{id: len(d.sections), name: name}
	d.sections = append(d.sections, created)
	return created
}

func (d *decoder) section(id int64) (*section, error) {
	if id < 0 || int(id) >= len(d.sections) || d.sections[id] == nil {
		return nil, fmt.Errorf("section %d does not exist", id)
	}
	return d.sections[id], nil
}

func (d *decoder) within(s *section, run func()) {
	saved := d.active
	d.active = s
	defer func() { d.active = saved }()
	run()
}

func (s *section) ensure(size int) {
	if size > len(s.data) {
		s.data = append(s.data, make([]byte, size-len(s.data))...)
	}
}

func (d *decoder) write(s *section, offset int, bytes []byte) {
	s.ensure(offset + len(bytes))
	copy(s.data[offset:], bytes)
	d.refresh(s)
}

func (d *decoder) refresh(s *section) {
	if s.refreshing {
		return
	}
	s.refreshing = true
	defer func() { s.refreshing = false }()
	d.within(s, func() {
		for _, p := range s.placements {
			fresh := d.decodeOrdered(p.t, p.order, p.offset, p.frame)
			fresh.Name = p.node.Name
			*p.node = *fresh
		}
	})
}

func (d *decoder) cloneLocal(name string, original *DecodedValue, f *frame) (*DecodedValue, error) {
	source := d.sections[original.Section].data
	if original.Offset+*original.Size > len(source) {
		return nil, errTruncated
	}
	heap := d.createSection(name)
	heap.data = append([]byte{}, source[original.Offset:original.Offset+*original.Size]...)
	var node *DecodedValue
	d.within(heap, func() {
		node = d.decode(name, original.typ, 0, f)
	})
	heap.placements = append(heap.placements, &placement{node: node, t: original.typ, offset: 0, frame: f})
	node.holdValues()
	return node, nil
}

func (v *DecodedValue) holdValues() {
	v.storage = valueStorage
	for _, child := range v.Fields {
		child.holdValues()
	}
	for _, element := range v.Elements {
		element.holdValues()
	}
}

func (d *decoder) allocateLocal(local *Local, f *frame) *DecodedValue {
	heap := d.createSection(local.Name)
	if size, err := f.allocationSize(local.Type); err == nil {
		heap.ensure(size)
	}
	var node *DecodedValue
	d.within(heap, func() {
		node = d.decode(local.Name, local.Type, 0, f)
	})
	heap.placements = append(heap.placements, &placement{node: node, t: local.Type, offset: 0, frame: f})
	return node
}

type frame struct {
	decoder     *decoder
	value       *DecodedValue
	abi         ABI
	originOwner bool
	section     *section
	base        int
	cursor      int
	nodes       map[*Field]*DecodedValue
	locals      map[*Local]runtimeValue
	exports     map[*Local]*DecodedValue
	parent      *frame
	caller      *frame
	depth       int
	arrayIndex  int
	bits        bool
	bitfield    *Bitfield
	bitCursor   int
	bitNodes    map[*BitfieldMember]*DecodedValue
	union       bool
	unionEnd    int
}

func (d *decoder) newFrame(value *DecodedValue, offset int, parent *frame, ownOrigin bool) *frame {
	base := offset
	if parent != nil && !ownOrigin {
		base = parent.base
	}
	if parent != nil && parent.section != d.active && !ownOrigin {
		base = 0
	}
	return &frame{
		decoder:     d,
		value:       value,
		originOwner: ownOrigin,
		section:     d.active,
		base:        base,
		cursor:      offset,
		nodes:       map[*Field]*DecodedValue{},
		locals:      map[*Local]runtimeValue{},
		exports:     map[*Local]*DecodedValue{},
		bitNodes:    map[*BitfieldMember]*DecodedValue{},
		parent:      parent,
	}
}

func (f *frame) node(path []*Field) (*DecodedValue, error) {
	scope := f
	for i, field := range path {
		node, isDecoded := scope.nodes[field]
		if !isDecoded {
			return nil, fmt.Errorf("%s is not available", field.Name)
		}
		if node.pointee != nil {
			node = node.pointee
		}
		if i == len(path)-1 {
			return node, nil
		}
		if node.frame == nil {
			return nil, fmt.Errorf("%s has no fields", field.Name)
		}
		scope = node.frame
	}
	panic("unreachable")
}

func (f *frame) parentNode(depth int, path []string) (*DecodedValue, error) {
	scope, err := f.ancestor(depth)
	if err != nil {
		return nil, err
	}
	var node *DecodedValue
	for _, name := range path {
		if scope == nil {
			return nil, fmt.Errorf("parent.%s is not available", strings.Join(path, "."))
		}
		node = scope.nodeNamed(name)
		if node == nil {
			node = scope.localNamed(name)
		}
		if node == nil {
			return nil, fmt.Errorf("parent.%s is not available", strings.Join(path, "."))
		}
		scope = node.frame
	}
	return node, nil
}

func (f *frame) nodeNamed(name string) *DecodedValue {
	for field, node := range f.nodes {
		if field.Name == name {
			return node
		}
	}
	return nil
}

func (f *frame) ancestor(depth int) (*frame, error) {
	scope := f
	for i := 0; i != depth; i++ {
		if scope.parent == nil {
			return nil, fmt.Errorf("there is no parent at this level")
		}
		scope = scope.parent
	}
	return scope, nil
}

func (f *frame) target(v Value) (*DecodedValue, error) {
	switch v := v.(type) {
	case *FieldRef:
		return f.node(v.Path)
	case *ParentFieldRef:
		return f.parentNode(v.Depth, v.Path)
	case *ThisRef:
		scope, err := f.ancestor(v.Depth)
		if err != nil {
			return nil, err
		}
		return scope.value, nil
	case *GlobalRef:
		current, err := f.global(v)
		if err != nil {
			return nil, err
		}
		node, isPattern := current.(*DecodedValue)
		if !isPattern {
			return nil, fmt.Errorf("%s is not a pattern", strings.Join(v.Path, "."))
		}
		return node, nil
	case *Index:
		return f.element(v)
	case *MemberOf:
		return f.memberOf(v)
	case *LocalRef:
		node, isPattern := f.locals[v.Local].(*DecodedValue)
		if !isPattern {
			return nil, fmt.Errorf("%s is not a pattern", v.Local.Name)
		}
		return node, nil
	}
	panic("unreachable")
}

func (d *decoder) decode(name string, t Type, offset int, scope *frame) *DecodedValue {
	value := d.decodeBare(name, t, offset, scope)
	if scope != nil {
		attributes := scope
		if value.frame != nil {
			attributes = value.frame
		}
		for _, attributed := range attributedTypes(t) {
			if err := attributes.applyAttributes(value, attributed); err != nil {
				value.fail(err)
			}
		}
	}
	return value
}

func attributedTypes(t Type) [][]*AttributeUse {
	var chain [][]*AttributeUse
	for {
		switch typed := t.(type) {
		case *Alias:
			chain = append(chain, typed.Attributes)
			t = typed.Target
			continue
		case *Struct:
			chain = append(chain, typed.Attributes)
		case *Union:
			chain = append(chain, typed.Attributes)
		case *Bitfield:
			chain = append(chain, typed.Attributes)
		case *Enum:
			chain = append(chain, typed.Attributes)
		}
		return chain
	}
}

func (d *decoder) decodeBare(name string, t Type, offset int, scope *frame) *DecodedValue {
	value := &DecodedValue{Name: name, Type: DescribeType(t), Address: d.addressOf(offset), Offset: offset, Section: d.active.id, typ: t}
	switch t := Unalias(t).(type) {
	case *Primitive:
		d.decodePrimitive(value, t, offset)
	case *Enum:
		if t.Encoding != nil {
			d.decodeEncodedEnum(value, t, offset, scope)
		} else {
			d.decodePrimitive(value, t.Underlying, offset)
		}
		if !value.Truncated {
			if number, err := toBig(value.raw); err == nil {
				value.Label = enumLabelWide(t, number)
			}
		}
	case *Pointer:
		d.decodePointer(value, t, offset)
		d.dereference(value, t, nil, scope)
	case *Bitfield:
		d.decodeBitfield(value, t, offset, scope)
	case *Struct:
		d.decodeStruct(value, t, offset, scope)
	case *Union:
		d.decodeUnion(value, t, offset, scope)
	case *Array:
		d.decodeArray(value, t, offset, scope)
	case *Padding:
		d.decodePadding(value, t, offset, scope)
	}
	return value
}

func (d *decoder) decodePadding(value *DecodedValue, t *Padding, offset int, scope *frame) {
	if t.While == nil {
		size, err := scope.evalInt(t.Size)
		if err != nil {
			value.fail(err)
			return
		}
		padding := int(size)
		value.Size = &padding
		return
	}
	owner := scope.cursorOwner()
	saved := owner.cursor
	defer func() { owner.cursor = saved }()
	padding := 0
	for {
		if err := d.step(); err != nil {
			value.fail(err)
			return
		}
		owner.cursor = offset + padding
		if _, available := d.bytes(owner.cursor, 1); !available {
			break
		}
		proceed, err := scope.truthy(t.While)
		if err != nil {
			value.fail(err)
			return
		}
		if !proceed {
			break
		}
		padding++
	}
	value.Size = &padding
}

func (d *decoder) decodeEncodedEnum(value *DecodedValue, t *Enum, offset int, scope *frame) {
	encoded := d.decode(value.Name, t.Encoding, offset, scope)
	value.Size, value.Truncated, value.Error = encoded.Size, encoded.Truncated, encoded.Error
	value.raw = patternNumber(encoded)
	value.Value = jsonValue(value.raw)
	value.ValueKind = primitiveValueKind(t.Underlying.Kind)
}

func (d *decoder) decodePrimitive(value *DecodedValue, t *Primitive, offset int) {
	size := t.Kind.Size()
	value.Size = &size
	bytes, available := d.bytes(offset, size)
	if !available {
		value.Truncated = true
		return
	}
	value.Value = d.primitiveValue(t, bytes)
	value.ValueKind = primitiveValueKind(t.Kind)
	value.raw = d.rawValue(t, bytes)
}

func (d *decoder) rawValue(t *Primitive, bytes []byte) runtimeValue {
	switch {
	case t.Kind == Bool:
		return bytes[0] != 0
	case t.Kind == Char || t.Kind == Char16:
		return d.primitiveValue(t, bytes)
	case t.Kind.IsFloatingPoint():
		return d.primitiveValue(t, bytes)
	case t.Kind.IsSigned():
		return narrow(d.bigInteger(t, bytes))
	}
	return narrow(d.bigInteger(t, bytes))
}

func (d *decoder) primitiveValue(t *Primitive, bytes []byte) any {
	order := d.byteOrder(t.Order)
	switch t.Kind {
	case Float:
		return float64(math.Float32frombits(order.Uint32(bytes)))
	case Double:
		return math.Float64frombits(order.Uint64(bytes))
	case Bool:
		return bytes[0] != 0
	case Char:
		return string(rune(bytes[0]))
	case Char16:
		return string(utf16.Decode([]uint16{order.Uint16(bytes)}))
	}
	if t.Kind.Size() > 8 {
		return d.bigInteger(t, bytes).String()
	}
	if t.Kind.IsSigned() {
		return integerJSON(uint64(d.integerValue(t, bytes)), true)
	}
	return integerJSON(uint64(d.integerValue(t, bytes)), false)
}

func (d *decoder) integerValue(t *Primitive, bytes []byte) int64 {
	value := d.bigInteger(t, bytes)
	if value.IsInt64() {
		return value.Int64()
	}
	return int64(value.Uint64())
}

func (d *decoder) bigInteger(t *Primitive, bytes []byte) *big.Int {
	ordered := make([]byte, len(bytes))
	copy(ordered, bytes)
	if d.byteOrder(t.Order) == binary.LittleEndian {
		for i, j := 0, len(ordered)-1; i < j; i, j = i+1, j-1 {
			ordered[i], ordered[j] = ordered[j], ordered[i]
		}
	}
	value := new(big.Int).SetBytes(ordered)
	if t.Kind.IsSigned() && len(ordered) > 0 && ordered[0]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(len(ordered)*8)))
	}
	return value
}

func primitiveValueKind(kind PrimitiveKind) string {
	switch {
	case kind.IsSigned():
		return "int"
	case kind.IsInteger():
		return "uint"
	case kind.IsFloatingPoint():
		return "float"
	case kind == Bool:
		return "bool"
	}
	return "string"
}

func (d *decoder) byteOrder(order ByteOrder) binary.ByteOrder {
	if order == BigEndian || (order == NativeOrder && !d.littleEndian) {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func enumLabel(t *Enum, number int64) string {
	return enumLabelWide(t, big.NewInt(number))
}

func enumLabelWide(t *Enum, number *big.Int) string {
	for _, member := range t.Members {
		first, last := big.NewInt(member.Value), big.NewInt(member.Last)
		if member.Wide != nil {
			first = member.Wide
		}
		if member.WideLast != nil {
			last = member.WideLast
		}
		if first.Cmp(number) <= 0 && number.Cmp(last) <= 0 {
			return member.Name
		}
	}
	return ""
}

func (d *decoder) decodePointer(value *DecodedValue, t *Pointer, offset int) {
	size := d.layout.Of(t).Size
	value.Size = &size
	bytes, available := d.bytes(offset, size)
	if !available {
		value.Truncated = true
		return
	}
	order := d.byteOrder(NativeOrder)
	if t.Width != nil {
		order = d.byteOrder(t.Width.Order)
	}
	var target uint64
	switch size {
	case 1:
		target = uint64(bytes[0])
	case 2:
		target = uint64(order.Uint16(bytes))
	case 4:
		target = uint64(order.Uint32(bytes))
	default:
		target = order.Uint64(bytes)
	}
	value.Value = fmt.Sprintf("0x%x", target)
	value.ValueKind = "pointer"
	value.raw = target
}

func (d *decoder) dereference(node *DecodedValue, t *Pointer, base *Function, scope *frame) {
	if node.Truncated || node.Section != 0 || scope == nil {
		return
	}
	target := node.raw.(uint64)
	if base != nil {
		result, err := scope.invoke(base, []runtimeValue{target})
		if err != nil {
			node.fail(err)
			return
		}
		rebased, err := toInt(result)
		if err != nil {
			node.fail(err)
			return
		}
		target += uint64(rebased)
		node.raw = target
		node.Value = fmt.Sprintf("0x%x", target)
	}
	node.pointee, node.Fields, node.frame = nil, nil, nil
	offset := int64(target) - int64(d.base)
	if target == 0 || d.pointers >= maxPointerDepth || offset < 0 || offset >= int64(len(d.sections[0].data)) {
		return
	}
	d.pointers++
	defer func() { d.pointers-- }()
	d.within(d.sections[0], func() {
		node.pointee = d.decode("*"+node.Name, t.Target, int(offset), scope)
	})
	node.Fields = []*DecodedValue{node.pointee}
	node.frame = node.pointee.frame
}

func (d *decoder) decodeBitfield(value *DecodedValue, t *Bitfield, offset int, parent *frame) {
	if !t.Simple {
		d.decodeDynamicBitfield(value, t, offset, parent)
		return
	}
	size := d.layout.Of(t).Size
	value.Size = &size
	bytes, available := d.bytes(offset, size)
	if !available {
		value.Truncated = true
		return
	}
	storage := uint64(0)
	for i := 0; i != size; i++ {
		index := i
		if d.littleEndian {
			index = size - 1 - i
		}
		storage = storage<<8 | uint64(bytes[index])
	}
	value.Value = integerJSON(storage, false)
	value.ValueKind = "uint"
	value.raw = storage
	value.Fields = []*DecodedValue{}
	f := d.newFrame(value, offset, parent, false)
	f.bits = true
	f.bitfield = t
	value.frame = f
	bigEndian := d.byteOrder(t.Order) == binary.BigEndian
	for _, member := range t.Members {
		if member.Name == "" {
			continue
		}
		position := t.BitPosition(member.Offset, member.Bits, bigEndian)
		bits := extractBits(bytes, position, member.Bits, bigEndian)
		first := position / 8
		span := (position+member.Bits-1)/8 - first + 1
		field := &DecodedValue{
			Name:      member.Name,
			Type:      bitfieldMemberDescription(member, member.Bits),
			Address:   d.addressOf(offset + first),
			Offset:    offset + first,
			Size:      &span,
			BitOffset: &position,
			Bits:      member.Bits,
		}
		switch {
		case member.Bool:
			field.Value, field.ValueKind, field.raw = bits != 0, "bool", bits != 0
		case member.Signed:
			signed := signExtend(bits, member.Bits)
			field.Value, field.ValueKind, field.raw = integerJSON(uint64(signed), true), "int", signed
		default:
			field.Value, field.ValueKind, field.raw = integerJSON(bits, false), "uint", bits
			if member.Enum != nil {
				field.Label = enumLabel(member.Enum, int64(bits))
			}
		}
		value.Fields = append(value.Fields, field)
		f.bitNodes[member] = field
	}
}

func (d *decoder) decodeDynamicBitfield(value *DecodedValue, t *Bitfield, offset int, parent *frame) {
	d.decodeBitfieldBits(value, t, offset, 0, parent)
}

func (d *decoder) decodeBitfieldBits(value *DecodedValue, t *Bitfield, offset int, startBit int, parent *frame) {
	f := d.newFrame(value, offset, parent, false)
	f.bits = true
	f.bitfield = t
	f.bitCursor = startBit
	value.frame = f
	value.raw = value
	value.Fields = []*DecodedValue{}
	if err := f.bindArguments(t.Params, t.Args, parent); err != nil {
		value.fail(err)
		return
	}
	ending, _, err := f.execute(t.Body)
	if err != nil {
		value.fail(err)
		return
	}
	value.ending = ending
	if t.FixedBits > 0 {
		f.bitCursor = startBit + t.FixedBits
	}
	value.Bits = f.bitCursor - startBit
	if startBit > 0 {
		value.BitOffset = &startBit
	}
	size := (f.bitCursor + 7) / 8
	value.Size = &size
	storage := uint64(0)
	for i := 0; i != min(size, 8); i++ {
		if b, available := d.bytes(offset+i, 1); available {
			storage |= uint64(b[0]) << (8 * i)
		}
	}
	value.Value = integerJSON(storage, false)
	value.ValueKind = "uint"
}

func (f *frame) placeBits(member *BitfieldMember) error {
	d := f.decoder
	width, err := f.evalInt(member.bits)
	if err != nil {
		return err
	}
	if width <= 0 || width > 64 {
		return fmt.Errorf("bit width must be between 1 and 64")
	}
	bigEndian := d.byteOrder(f.bitfield.Order) == binary.BigEndian
	position := f.bitfield.BitPosition(f.bitCursor, int(width), bigEndian)
	first := f.value.Offset + position/8
	last := f.value.Offset + (position+int(width)-1)/8
	bytes, available := d.bytes(first, last-first+1)
	if !available {
		return errTruncated
	}
	bits := extractBits(bytes, position%8, int(width), bigEndian)
	bitOffset := position
	f.bitCursor += int(width)
	if member.Name == "" {
		return nil
	}
	size := last - first + 1
	node := &DecodedValue{Name: member.Name, Type: bitfieldMemberDescription(member, int(width)), Address: fmt.Sprintf("0x%x", d.base+uint64(first)), Offset: first, Size: &size}
	node.BitOffset = &bitOffset
	node.Bits = int(width)
	switch {
	case member.Bool:
		node.Value, node.ValueKind, node.raw = bits != 0, "bool", bits != 0
	case member.Signed:
		signed := signExtend(bits, int(width))
		node.Value, node.ValueKind, node.raw = integerJSON(uint64(signed), true), "int", signed
	default:
		node.Value, node.ValueKind, node.raw = integerJSON(bits, false), "uint", bits
		if member.Enum != nil {
			node.Label = enumLabel(member.Enum, int64(bits))
		}
	}
	f.value.Fields = append(f.value.Fields, node)
	f.bitNodes[member] = node
	return nil
}

func bitfieldMemberDescription(member *BitfieldMember, width int) string {
	switch {
	case member.Bool:
		return fmt.Sprintf("bool : %d", width)
	case member.Enum != nil:
		return fmt.Sprintf("%s : %d", member.Enum.Name, width)
	case member.Signed:
		return fmt.Sprintf("signed : %d", width)
	}
	return fmt.Sprintf(": %d", width)
}

func signExtend(bits uint64, width int) int64 {
	shift := 64 - uint(width)
	return int64(bits<<shift) >> shift
}

func integerJSON(value uint64, signed bool) any {
	if signed {
		if v := int64(value); v >= -1<<53 && v <= 1<<53 {
			return v
		}
		return fmt.Sprintf("%d", int64(value))
	}
	if value <= 1<<53 {
		return int64(value)
	}
	return fmt.Sprintf("%d", value)
}

func (d *decoder) decodeStruct(value *DecodedValue, t *Struct, offset int, parent *frame) {
	f := d.newFrame(value, offset, parent, t.Global)
	f.abi = t.ABI
	value.frame = f
	value.raw = value
	d.adoptPending(value)
	value.Fields = []*DecodedValue{}
	if err := f.bindArguments(t.Params, t.Args, parent); err != nil {
		value.fail(err)
		return
	}
	if t.Naming != nil {
		value.Type = f.instanceName(t.Naming)
	}
	ending, _, err := f.execute(structBody(t))
	if err != nil {
		value.fail(err)
		return
	}
	value.end(ending)
	size := f.cursor - offset
	if t.Simple {
		size = alignUp(size, d.layout.Composite(t).Align)
	}
	value.Size = &size
}

func (f *frame) applyAttributes(node *DecodedValue, uses []*AttributeUse) error {
	for _, use := range uses {
		if err := f.applyAttribute(node, use); err != nil {
			return err
		}
	}
	return nil
}

func (f *frame) applyAttribute(node *DecodedValue, use *AttributeUse) error {
	if presentation, isVisualizer := visualizerPresentations[use.Name]; isVisualizer {
		return f.attachVisualizer(node, use, presentation)
	}
	arguments := make([]runtimeValue, len(use.Arguments))
	for i, argument := range use.Arguments {
		result, err := f.eval(argument)
		if err != nil {
			return err
		}
		arguments[i] = result
	}
	switch use.Name {
	case "name":
		node.DisplayName = display(arguments[0])
	case "comment":
		node.Comment = display(arguments[0])
	case "color":
		node.Color = display(arguments[0])
	case "hidden", "highlight_hidden", "tree_hidden":
		node.Hidden = true
	case "inline":
		node.Inline = true
	case "sealed":
		node.Sealed = true
	case "fixed_size":
		size, err := toInt(arguments[0])
		if err != nil {
			return err
		}
		fixed := int(size)
		node.Size = &fixed
	case "format", "format_read":
		result, err := f.invokeAttribute(use, node)
		if err != nil {
			return err
		}
		node.Formatted = display(result)
	case "format_entries", "format_read_entries":
		for _, element := range node.Elements {
			result, err := f.invokeAttribute(use, element)
			if err != nil {
				return err
			}
			element.Formatted = display(result)
		}
	case "transform":
		result, err := f.invokeAttribute(use, node)
		if err != nil {
			return err
		}
		node.raw = result
		node.Value = jsonValue(result)
	case "transform_entries":
		for _, element := range node.Elements {
			result, err := f.invokeAttribute(use, element)
			if err != nil {
				return err
			}
			element.raw = result
			element.Value = jsonValue(result)
		}
	}
	return nil
}

type Visualizer struct {
	Name         string               `json:"name"`
	Presentation string               `json:"presentation"`
	Arguments    []VisualizerArgument `json:"arguments"`
}

type VisualizerArgument struct {
	Kind      string `json:"kind"`
	Value     any    `json:"value,omitempty"`
	ValueKind string `json:"value_kind,omitempty"`
	Pattern   int    `json:"pattern,omitempty"`
	Address   string `json:"address,omitempty"`
	Size      *int   `json:"size,omitempty"`
	Data      []byte `json:"data,omitempty"`

	target *DecodedValue
}

var visualizerPresentations = map[string]string{
	"hex::visualize":        "detached",
	"hex::inline_visualize": "inline",
}

func (f *frame) attachVisualizer(node *DecodedValue, use *AttributeUse, presentation string) error {
	visualizer := &Visualizer{Presentation: presentation, Arguments: []VisualizerArgument{}}
	for i, argument := range use.Arguments {
		value, err := f.visualizerArgument(argument, node)
		if err != nil {
			return err
		}
		if i == 0 {
			visualizer.Name = display(value)
			continue
		}
		visualizer.Arguments = append(visualizer.Arguments, f.decoder.describeVisualizerArgument(value))
	}
	node.Visualizer = visualizer
	return nil
}

func (f *frame) visualizerArgument(argument Value, node *DecodedValue) (runtimeValue, error) {
	if this, isThis := argument.(*ThisRef); isThis && this.Depth == 0 {
		return node, nil
	}
	return f.eval(argument)
}

func (d *decoder) describeVisualizerArgument(value runtimeValue) VisualizerArgument {
	if pattern, isPattern := value.(*DecodedValue); isPattern {
		scalar, kind := scalarJSON(pattern.raw)
		return VisualizerArgument{
			Kind:      "pattern",
			Value:     scalar,
			ValueKind: kind,
			Address:   pattern.Address,
			Size:      pattern.Size,
			Data:      d.bytesOf(pattern),
			target:    pattern,
		}
	}
	scalar, kind := scalarJSON(value)
	return VisualizerArgument{Kind: "value", Value: scalar, ValueKind: kind}
}

func (d *decoder) bytesOf(node *DecodedValue) []byte {
	data := d.sections[node.Section].data
	if node.Size == nil || node.Offset+*node.Size > len(data) {
		return nil
	}
	return append([]byte{}, data[node.Offset:node.Offset+*node.Size]...)
}

func jsonValue(v runtimeValue) any {
	switch v := v.(type) {
	case *big.Int:
		return v.String()
	case charValue:
		return string(rune(v))
	case enumValue:
		return integerJSON(uint64(v.value), true)
	case int64:
		return integerJSON(uint64(v), true)
	case uint64:
		return integerJSON(v, false)
	case float64, bool, string:
		return v
	}
	return nil
}

func (f *frame) invokeAttribute(use *AttributeUse, node *DecodedValue) (runtimeValue, error) {
	if use.Dynamic != nil {
		named, err := f.eval(use.Dynamic)
		if err != nil {
			return nil, err
		}
		name := display(named)
		if function := f.decoder.layout.Module.function(name); function != nil {
			return f.invoke(function, []runtimeValue{node})
		}
		if definition, isBuiltin := builtins[name]; isBuiltin {
			return definition.call(f, []runtimeValue{node})
		}
		return nil, fmt.Errorf("unknown function %s", name)
	}
	if use.Function != nil {
		return f.invoke(use.Function, []runtimeValue{node})
	}
	return builtins[use.Builtin].call(f, []runtimeValue{node})
}

func (f *frame) bindArguments(params []*Local, args []Value, site *frame) error {
	for i, param := range params {
		argument, err := site.eval(args[i])
		if err != nil {
			return err
		}
		f.locals[param] = argument
	}
	return nil
}

func (v *DecodedValue) fail(err error) {
	if err == errTruncated {
		v.Truncated = true
		return
	}
	v.Error = err.Error()
}

func (v *DecodedValue) end(ending flow) {
	v.ending = ending
	if ending == flowContinue {
		v.Fields = []*DecodedValue{}
	}
}

func isBitfieldOrArrayOf(t Type) bool {
	switch t := Unalias(t).(type) {
	case *Bitfield:
		return true
	case *Array:
		_, isBitfield := Unalias(t.Element).(*Bitfield)
		return isBitfield && t.While == nil && t.Length != nil
	}
	return false
}

func (f *frame) placeNestedBitfield(field *Field) error {
	d := f.decoder
	var node *DecodedValue
	switch t := Unalias(field.Type).(type) {
	case *Bitfield:
		node = d.decodeNestedBitfield(field.Name, t, f)
	case *Array:
		count, err := f.evalInt(t.Length)
		if err != nil {
			return err
		}
		startBit := f.bitCursor
		node = &DecodedValue{Name: field.Name, Type: DescribeType(t), Address: d.addressOf(f.value.Offset + startBit/8), Offset: f.value.Offset + startBit/8, Section: d.active.id, typ: t}
		node.raw = node
		node.Elements = []*DecodedValue{}
		length := int(count)
		node.Count = &length
		for i := 0; i != length; i++ {
			element := d.decodeNestedBitfield("", Unalias(t.Element).(*Bitfield), f)
			if i < maxDecodedElements {
				node.Elements = append(node.Elements, element)
			}
			if element.Error != "" {
				node.fail(fmt.Errorf("%s", element.Error))
				break
			}
		}
		node.Bits = f.bitCursor - startBit
		offsetInByte := startBit % 8
		node.BitOffset = &offsetInByte
		size := (offsetInByte + node.Bits + 7) / 8
		node.Size = &size
	}
	if field.Hidden {
		node.Hidden = true
	}
	f.value.Fields = append(f.value.Fields, node)
	f.nodes[field] = node
	if node.Error != "" {
		return fmt.Errorf("%s", node.Error)
	}
	return nil
}

func (d *decoder) decodeNestedBitfield(name string, t *Bitfield, parent *frame) *DecodedValue {
	offset := parent.value.Offset + parent.bitCursor/8
	startBit := parent.bitCursor % 8
	node := &DecodedValue{Name: name, Type: DescribeType(t), Address: d.addressOf(offset), Offset: offset, Section: d.active.id, typ: t}
	d.decodeBitfieldBits(node, t, offset, startBit, parent)
	parent.bitCursor += node.Bits
	return node
}

func extractBits(bytes []byte, position int, width int, bigEndian bool) uint64 {
	var value uint64
	for i := 0; i != width; i++ {
		index := position + i
		var bit uint64
		if bigEndian {
			bit = uint64(bytes[index/8]>>(7-index%8)) & 1
			value = value<<1 | bit
		} else {
			bit = uint64(bytes[index/8]>>(index%8)) & 1
			value |= bit << i
		}
	}
	return value
}

func (d *decoder) decodeOrdered(t Type, order ByteOrder, offset int, f *frame) *DecodedValue {
	if order == NativeOrder {
		return d.decode("", t, offset, f)
	}
	saved := d.littleEndian
	d.littleEndian = order == LittleEndian
	defer func() { d.littleEndian = saved }()
	return d.decode("", t, offset, f)
}

func structBody(t *Struct) []Statement {
	if t.Base == nil {
		return t.Body
	}
	return append(structBody(t.Base), t.Body...)
}

func (f *frame) setLocal(local *Local, assigned runtimeValue) {
	f.locals[local] = assigned
	if !local.Export {
		return
	}
	node, exported := f.exports[local]
	if !exported {
		node = &DecodedValue{Name: local.Name, Type: "auto", Address: f.value.Address, Offset: f.value.Offset}
		if local.Type != nil {
			node.Type = DescribeType(local.Type)
		}
		size := 0
		node.Size = &size
		f.exports[local] = node
		f.value.Fields = append(f.value.Fields, node)
	}
	node.raw = assigned
	if pattern, isPattern := assigned.(*DecodedValue); isPattern {
		node.Value, node.Fields, node.Elements = nil, pattern.Fields, pattern.Elements
		return
	}
	node.Value, node.ValueKind = scalarJSON(assigned)
}

func scalarJSON(v runtimeValue) (any, string) {
	switch v := v.(type) {
	case *big.Int:
		return v.String(), "uint"
	case charValue:
		return string(rune(v)), "string"
	case enumValue:
		return integerJSON(uint64(v.value), true), "int"
	case int64:
		return integerJSON(uint64(v), true), "int"
	case uint64:
		return integerJSON(v, false), "uint"
	case float64:
		return v, "float"
	case bool:
		return v, "bool"
	case string:
		return v, "string"
	}
	return nil, ""
}

func (f *frame) place(field *Field) error {
	d := f.decoder
	if f.bits && isBitfieldOrArrayOf(field.Type) {
		return f.placeNestedBitfield(field)
	}
	if f.bits {
		f.bitCursor = alignUp(f.bitCursor, 8)
		f.cursorOwner().cursor = f.value.Offset + f.bitCursor/8
	}
	if f.union {
		f.cursorOwner().cursor = f.value.Offset
	}
	offset := f.cursorOwner().cursor
	if field.Address != nil {
		address, err := f.evalInt(field.Address)
		if err != nil {
			return err
		}
		offset = f.cursorOwner().base + int(address)
	} else {
		offset = alignUp(offset, fieldAlign(f.abi, d.layout.Of(field.Type)))
	}
	var node *DecodedValue
	if field.Section != nil {
		id, err := f.evalInt(field.Section)
		if err != nil {
			return err
		}
		target, err := d.section(id)
		if err != nil {
			return err
		}
		address, _ := f.evalInt(field.Address)
		offset = int(address)
		d.within(target, func() {
			node = d.decodeOrdered(field.Type, field.Order, offset, f)
		})
		target.placements = append(target.placements, &placement{node: node, t: field.Type, order: field.Order, offset: offset, frame: f})
	} else {
		if isStructOrUnion(field.Type) {
			d.adopt = func(value *DecodedValue) { f.nodes[field] = value }
		}
		node = d.decodeOrdered(field.Type, field.Order, offset, f)
		d.adopt = nil
	}
	node.Name = field.Name
	if pointer, isPointer := Unalias(field.Type).(*Pointer); isPointer && field.PointerBase != nil {
		d.dereference(node, pointer, field.PointerBase, f)
	}
	if field.Hidden {
		node.Hidden = true
	}
	if field.Doc != "" {
		node.Comment = field.Doc
	}
	if node.Size != nil {
		if err := f.applyAttributes(node, field.Attributes); err != nil {
			return err
		}
	}
	f.value.Fields = append(f.value.Fields, node)
	f.nodes[field] = node
	if node.Truncated {
		f.value.Truncated = true
	}
	if node.Size == nil {
		if node.Error != "" {
			return fmt.Errorf("%s", node.Error)
		}
		return errTruncated
	}
	if (field.Address == nil || f.originOwner) && !field.NoUniqueAddress && field.Section == nil {
		f.cursorOwner().cursor = offset + *node.Size
		if f.bits {
			f.bitCursor = (offset + *node.Size - f.value.Offset) * 8
		}
		if f.union {
			f.unionEnd = max(f.unionEnd, offset+*node.Size-f.value.Offset)
		}
	}
	return nil
}

func isStructOrUnion(t Type) bool {
	switch Unalias(t).(type) {
	case *Struct, *Union:
		return true
	}
	return false
}

func (d *decoder) decodeUnion(value *DecodedValue, t *Union, offset int, parent *frame) {
	f := d.newFrame(value, offset, parent, false)
	f.abi = t.ABI
	f.union = true
	value.frame = f
	value.raw = value
	d.adoptPending(value)
	value.Fields = []*DecodedValue{}
	if err := f.bindArguments(t.Params, t.Args, parent); err != nil {
		value.fail(err)
		return
	}
	if t.Naming != nil {
		value.Type = f.instanceName(t.Naming)
	}
	ending, _, err := f.execute(t.Body)
	if err != nil {
		value.fail(err)
		return
	}
	value.end(ending)
	size := f.unionEnd
	value.Size = &size
}

func (d *decoder) adoptPending(value *DecodedValue) {
	if adopt := d.adopt; adopt != nil {
		d.adopt = nil
		adopt(value)
	}
}

func (d *decoder) decodeArray(value *DecodedValue, t *Array, offset int, scope *frame) {
	value.raw = value
	if t.While != nil {
		d.decodeWhileArray(value, t, offset, scope)
		return
	}
	if t.Length == nil {
		d.decodeString(value, t, offset, -1)
		return
	}
	length, err := scope.evalInt(t.Length)
	if err != nil {
		value.fail(err)
		return
	}
	if length < 0 {
		value.Error = "array length must not be negative"
		return
	}
	count := int(length)
	if characterKind(t.Element) != -1 {
		d.decodeString(value, t, offset, count)
		size := count * characterKind(t.Element).Size()
		value.Size = &size
		return
	}
	value.Count = &count
	value.Elements = []*DecodedValue{}
	end := offset
	for i := 0; i != count; i++ {
		scope.arrayIndex = i
		elementValue := d.decode("", t.Element, end, scope)
		if elementValue.ending != flowContinue && len(value.Elements) < maxDecodedElements {
			value.Elements = append(value.Elements, elementValue)
		}
		if elementValue.Truncated {
			value.Truncated = true
		}
		if elementValue.Size == nil {
			return
		}
		end += *elementValue.Size
		if elementValue.ending == flowBreak {
			break
		}
	}
	size := end - offset
	value.Size = &size
}

func (d *decoder) decodeWhileArray(value *DecodedValue, t *Array, offset int, scope *frame) {
	value.Elements = []*DecodedValue{}
	end := offset
	count := 0
	for {
		if err := d.step(); err != nil {
			value.fail(err)
			return
		}
		owner := scope.cursorOwner()
		saved := owner.cursor
		owner.cursor = end
		proceed, err := scope.truthy(t.While)
		owner.cursor = saved
		if err != nil {
			value.fail(err)
			return
		}
		if !proceed {
			break
		}
		scope.arrayIndex = count
		elementValue := d.decode("", t.Element, end, scope)
		if elementValue.ending != flowContinue {
			if count < maxDecodedElements {
				value.Elements = append(value.Elements, elementValue)
			}
			count++
		}
		if elementValue.Truncated {
			value.Truncated = true
		}
		if elementValue.Size == nil {
			return
		}
		end += *elementValue.Size
		if elementValue.ending == flowBreak {
			break
		}
	}
	size := end - offset
	value.Size = &size
	value.Count = &count
}

func (d *decoder) decodeString(value *DecodedValue, t *Array, offset int, count int) {
	kind := characterKind(t.Element)
	unit := kind.Size()
	var raw []byte
	var units []uint16
	i := 0
	for count < 0 || i < count {
		bytes, available := d.bytes(offset+i*unit, unit)
		if !available {
			value.Truncated = true
			return
		}
		i++
		if kind == Char16 {
			code := d.byteOrder(Unalias(t.Element).(*Primitive).Order).Uint16(bytes)
			if code == 0 {
				break
			}
			units = append(units, code)
		} else {
			if bytes[0] == 0 && count < 0 {
				break
			}
			raw = append(raw, bytes[0])
		}
	}
	if kind == Char16 {
		value.Value = string(utf16.Decode(units))
		value.raw = value.Value
	} else {
		value.Value = displayedCharacters(raw)
		value.raw = string(raw)
	}
	value.ValueKind = "string"
	if count < 0 {
		size := i * unit
		value.Size = &size
	}
}

func displayedCharacters(raw []byte) string {
	runes := make([]rune, 0, len(raw))
	for _, b := range raw {
		if b == 0 {
			break
		}
		runes = append(runes, rune(b))
	}
	return string(runes)
}

func (d *decoder) addressOf(offset int) string {
	if d.active.id != 0 {
		return fmt.Sprintf("0x%x", offset)
	}
	return fmt.Sprintf("0x%x", d.base+uint64(offset))
}

func (d *decoder) bytes(offset int, size int) ([]byte, bool) {
	if offset < 0 || offset+size > len(d.active.data) {
		return nil, false
	}
	return d.active.data[offset : offset+size], true
}

func (d *decoder) encode(t *Primitive, value runtimeValue) ([]byte, error) {
	bytes := make([]byte, t.Kind.Size())
	order := d.byteOrder(t.Order)
	switch {
	case t.Kind == Bool:
		if truthy, isBool := value.(bool); isBool && truthy {
			bytes[0] = 1
		}
	case t.Kind == Float:
		number, err := toFloat(value)
		if err != nil {
			return nil, err
		}
		order.PutUint32(bytes, math.Float32bits(float32(number)))
	case t.Kind == Double:
		number, err := toFloat(value)
		if err != nil {
			return nil, err
		}
		order.PutUint64(bytes, math.Float64bits(number))
	case t.Kind == Char || t.Kind == Char16:
		text, isString := value.(string)
		var code uint64
		if isString {
			for _, r := range text {
				code = uint64(r)
				break
			}
		} else if number, err := toInt(value); err == nil {
			code = uint64(number)
		}
		putInteger(bytes, code, order == binary.LittleEndian)
	case t.Kind.Size() > 8:
		number, err := toBig(value)
		if err != nil {
			return nil, err
		}
		modulus := new(big.Int).Lsh(big.NewInt(1), uint(len(bytes)*8))
		new(big.Int).Mod(number, modulus).FillBytes(bytes)
		if order == binary.LittleEndian {
			slices.Reverse(bytes)
		}
	default:
		number, err := toInt(value)
		if err != nil {
			return nil, err
		}
		putInteger(bytes, uint64(number), order == binary.LittleEndian)
	}
	return bytes, nil
}

func putInteger(bytes []byte, value uint64, littleEndian bool) {
	for i := range bytes {
		index := len(bytes) - 1 - i
		if littleEndian {
			index = i
		}
		bytes[index] = byte(value)
		value >>= 8
	}
}

func (v *DecodedValue) String() string {
	var sb strings.Builder
	v.write(&sb, "")
	return sb.String()
}

func (v *DecodedValue) write(sb *strings.Builder, indent string) {
	fmt.Fprintf(sb, "%s%s %s @ %s", indent, v.Type, v.Name, v.Address)
	if v.Value != nil {
		fmt.Fprintf(sb, " = %v", v.Value)
	}
	if v.Label != "" {
		fmt.Fprintf(sb, " (%s)", v.Label)
	}
	if v.Truncated {
		sb.WriteString(" [truncated]")
	}
	sb.WriteString("\n")
	for _, child := range v.Fields {
		child.write(sb, indent+"  ")
	}
	for _, child := range v.Elements {
		child.write(sb, indent+"  ")
	}
}

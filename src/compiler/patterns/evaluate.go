package patterns

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

type runtimeValue = any

type flow int

const (
	flowNext flow = iota
	flowBreak
	flowContinue
	flowReturn
)

const (
	maxEvaluationSteps = 1 << 22
	maxCallDepth       = 64
)

var errTruncated = fmt.Errorf("the data ended before the runtimeValue could be read")

func (f *frame) execute(statements []Statement) (flow, runtimeValue, error) {
	for _, statement := range statements {
		if err := f.decoder.step(); err != nil {
			return flowNext, nil, err
		}
		control, result, err := f.executeOne(statement)
		if err != nil || control != flowNext {
			return control, result, err
		}
	}
	return flowNext, nil, nil
}

func (d *decoder) step() error {
	d.steps++
	if d.steps > maxEvaluationSteps {
		return fmt.Errorf("evaluation limit exceeded")
	}
	return nil
}

func (f *frame) executeOne(statement Statement) (flow, runtimeValue, error) {
	switch s := statement.(type) {
	case *Field:
		return flowNext, nil, f.place(s)
	case *BitfieldMember:
		return flowNext, nil, f.placeBits(s)
	case *Local:
		if provided, isProvided := f.decoder.inputs[s.Name]; isProvided && s.Input {
			f.setLocal(s, provided)
			break
		}
		initial, err := f.initialValue(s)
		if err != nil {
			return flowNext, nil, err
		}
		f.setLocal(s, initial)
	case *Assignment:
		return flowNext, nil, f.assign(s)
	case *Conditional:
		condition, err := f.truthy(s.Condition)
		if err != nil {
			return flowNext, nil, err
		}
		if condition {
			return f.execute(s.Then)
		}
		return f.execute(s.Else)
	case *Match:
		body, err := f.matchingCase(s)
		if err != nil {
			return flowNext, nil, err
		}
		return f.execute(body)
	case *Return:
		var result runtimeValue
		if s.Value != nil {
			var err error
			if result, err = f.eval(s.Value); err != nil {
				return flowNext, nil, err
			}
		}
		return flowReturn, result, nil
	case *Loop:
		return f.loop(s)
	case *Break:
		return flowBreak, nil, nil
	case *Continue:
		return flowContinue, nil, nil
	case *Try:
		return f.try(s)
	case *Evaluation:
		_, err := f.eval(s.Value)
		return flowNext, nil, err
	case *Failure:
		return flowNext, nil, errors.New(s.Message)
	}
	return flowNext, nil, nil
}

func (d *decoder) store(node *DecodedValue, value runtimeValue) error {
	var primitive *Primitive
	switch t := Unalias(node.typ).(type) {
	case *Primitive:
		primitive = t
	case *Enum:
		if t.Encoding != nil {
			return d.copyPattern(node, value)
		}
		primitive = t.Underlying
	default:
		return d.copyPattern(node, value)
	}
	if node.storage == valueStorage {
		node.raw, node.Value = value, jsonValue(value)
		return nil
	}
	bytes, err := d.encode(primitive, value)
	if err != nil {
		return err
	}
	d.write(d.sections[node.Section], node.Offset, bytes)
	return nil
}

func (f *frame) initialValue(local *Local) (runtimeValue, error) {
	if local.StringCount != nil {
		count, err := f.evalInt(local.StringCount)
		if err != nil {
			return nil, err
		}
		strings := make([]runtimeValue, max(0, count))
		for i := range strings {
			strings[i] = ""
		}
		return strings, nil
	}
	if local.Type == nil {
		value, err := f.eval(local.Init)
		if err != nil {
			return nil, err
		}
		if node, isPattern := value.(*DecodedValue); isPattern && node.Size != nil && node.typ != nil {
			return f.decoder.cloneLocal(local.Name, node, f)
		}
		return value, nil
	}
	_, isDefault := local.Init.(*Constant)
	if array, isArray := Unalias(local.Type).(*Array); isArray && !isHeapBacked(array.Element) && isDefault && array.Length != nil {
		length, err := f.evalInt(array.Length)
		if err != nil {
			return nil, err
		}
		if length < 0 {
			return nil, fmt.Errorf("array length must not be negative")
		}
		elements := make([]runtimeValue, length)
		for i := range elements {
			elements[i] = int64(0)
		}
		return elements, nil
	}
	if !isHeapBacked(local.Type) {
		value, err := f.eval(local.Init)
		if err != nil {
			return nil, err
		}
		return f.padArray(local.Type, value)
	}
	node := f.decoder.allocateLocal(local, f)
	if isDefault {
		return node, nil
	}
	source, err := f.eval(local.Init)
	if err != nil {
		return nil, err
	}
	return node, f.decoder.copyPattern(node, source)
}

func (d *decoder) copyPattern(node *DecodedValue, source runtimeValue) error {
	original, isPattern := source.(*DecodedValue)
	if !isPattern || original.Size == nil {
		return fmt.Errorf("%s can only be assigned a pattern", node.Name)
	}
	bytes := d.sections[original.Section].data
	if original.Offset+*original.Size > len(bytes) {
		return errTruncated
	}
	d.write(d.sections[node.Section], node.Offset, append([]byte{}, bytes[original.Offset:original.Offset+*original.Size]...))
	return nil
}

func (f *frame) padArray(t Type, value runtimeValue) (runtimeValue, error) {
	array, isArray := Unalias(t).(*Array)
	elements, isSlice := value.([]runtimeValue)
	if !isArray || !isSlice || array.Length == nil {
		return value, nil
	}
	length, err := f.evalInt(array.Length)
	if err != nil {
		return nil, err
	}
	for int64(len(elements)) < length {
		elements = append(elements, int64(0))
	}
	return elements, nil
}

func isHeapBacked(t Type) bool {
	if array, isArray := Unalias(t).(*Array); isArray {
		return isHeapBacked(array.Element)
	}
	return isComposite(t)
}

type charValue int64

type enumValue struct {
	enum  *Enum
	value int64
}

func isComposite(t Type) bool {
	switch Unalias(t).(type) {
	case *Struct, *Union, *Bitfield:
		return true
	}
	return false
}

func (f *frame) assign(s *Assignment) error {
	result, err := f.eval(s.Value)
	if err != nil {
		return err
	}
	switch target := s.Target.(type) {
	case *Cursor:
		offset, err := toInt(result)
		if err != nil {
			return err
		}
		owner := f.cursorOwner()
		owner.cursor = owner.base + int(offset)
	case *LocalRef:
		if node, isPattern := f.locals[target.Local].(*DecodedValue); isPattern && node.Section != 0 && isHeapBacked(target.Local.Type) {
			return f.decoder.copyPattern(node, result)
		}
		f.setLocal(target.Local, result)
	case *GlobalRef:
		if target.Local != nil && len(target.Rest) == 0 {
			f.root().setLocal(target.Local, result)
			return nil
		}
		return f.overwrite(target, result)
	case *Index:
		object, err := f.eval(target.Object)
		if err != nil {
			return err
		}
		if elements, isSlice := object.([]runtimeValue); isSlice {
			index, err := f.evalInt(target.Index)
			if err != nil {
				return err
			}
			if index < 0 || index >= int64(len(elements)) {
				return fmt.Errorf("index %d is out of range", index)
			}
			elements[index] = scalarOf(result)
			return nil
		}
		return f.overwrite(target, result)
	default:
		return f.overwrite(target, result)
	}
	return nil
}

func (f *frame) overwrite(target Value, result runtimeValue) error {
	if member, isMember := target.(*MemberOf); isMember {
		return f.overwriteMember(member, result)
	}
	node, err := f.target(target)
	if err != nil {
		return err
	}
	return f.overwriteNode(node, result)
}

func (f *frame) overwriteMember(v *MemberOf, result runtimeValue) error {
	owner, err := f.memberOwner(v)
	if err != nil {
		return err
	}
	if owner.frame != nil && owner.frame.nodeNamed(v.Name) == nil {
		if local := owner.frame.scalarLocalNamed(v.Name); local != nil {
			owner.frame.locals[local] = result
			return nil
		}
	}
	node, err := owner.member(v.Name)
	if err != nil {
		return err
	}
	return f.overwriteNode(node, result)
}

func (f *frame) overwriteNode(node *DecodedValue, result runtimeValue) error {
	if node.Section != 0 {
		return f.decoder.store(node, result)
	}
	node.raw = result
	switch result := result.(type) {
	case int64:
		node.Value = integerJSON(uint64(result), true)
	case uint64:
		node.Value = integerJSON(result, false)
	case float64, bool, string:
		node.Value = result
	}
	return nil
}

func (f *frame) element(v *Index) (*DecodedValue, error) {
	object, err := f.eval(v.Object)
	if err != nil {
		return nil, err
	}
	index, err := f.evalInt(v.Index)
	if err != nil {
		return nil, err
	}
	switch object := object.(type) {
	case []runtimeValue:
		if index < 0 || index >= int64(len(object)) {
			return nil, fmt.Errorf("index %d is out of range", index)
		}
		return &DecodedValue{raw: object[index]}, nil
	case *DecodedValue:
		if index < 0 || index >= int64(len(object.Elements)) {
			return nil, fmt.Errorf("index %d is out of range", index)
		}
		return object.Elements[index], nil
	case string:
		runes := []rune(object)
		if index < 0 || index >= int64(len(runes)) {
			return nil, fmt.Errorf("index %d is out of range", index)
		}
		return &DecodedValue{raw: string(runes[index])}, nil
	}
	return nil, fmt.Errorf("value cannot be indexed")
}

func (v *DecodedValue) runtimeValue() runtimeValue {
	if v.typ == nil {
		return v.raw
	}
	enum, isEnum := Unalias(v.typ).(*Enum)
	if !isEnum {
		return v.raw
	}
	number, err := toInt(v.raw)
	if err != nil {
		return v.raw
	}
	return enumValue{enum: enum, value: number}
}

func (f *frame) memberOf(v *MemberOf) (*DecodedValue, error) {
	owner, err := f.memberOwner(v)
	if err != nil {
		return nil, err
	}
	return owner.member(v.Name)
}

func (f *frame) memberOwner(v *MemberOf) (*DecodedValue, error) {
	var object runtimeValue
	var err error
	if isReference(v.Object) {
		object, err = f.target(v.Object)
	} else {
		object, err = f.eval(v.Object)
	}
	if err != nil {
		return nil, err
	}
	node, isPattern := object.(*DecodedValue)
	if !isPattern {
		return nil, fmt.Errorf("%s is not a struct", v.Name)
	}
	return node, nil
}

func (v *DecodedValue) member(name string) (*DecodedValue, error) {
	if v.frame != nil {
		if member := v.frame.nodeNamed(name); member != nil {
			return member, nil
		}
		if local := v.frame.localNamed(name); local != nil {
			return local, nil
		}
	}
	for _, field := range v.Fields {
		if field.Name == name {
			return field, nil
		}
	}
	return nil, fmt.Errorf("%s is not available", name)
}

func (f *frame) scalarLocalNamed(name string) *Local {
	for local, value := range f.locals {
		if _, isPattern := value.(*DecodedValue); local.Name == name && !isPattern {
			return local
		}
	}
	return nil
}

func (f *frame) localNamed(name string) *DecodedValue {
	for local, value := range f.locals {
		if local.Name == name {
			if node, isPattern := value.(*DecodedValue); isPattern {
				return node
			}
			return &DecodedValue{Name: name, raw: value}
		}
	}
	return nil
}

func (f *frame) root() *frame {
	scope := f
	for !scope.originOwner && (scope.caller != nil || scope.parent != nil) {
		if scope.caller != nil {
			scope = scope.caller
		} else {
			scope = scope.parent
		}
	}
	return scope
}

func (f *frame) lookupLocal(local *Local) (runtimeValue, error) {
	for scope := f; scope != nil; scope = scope.parent {
		if value, isBound := scope.locals[local]; isBound {
			return value, nil
		}
	}
	for scope := f; scope != nil; scope = scope.parent {
		for bound, value := range scope.locals {
			if bound.Name == local.Name {
				return value, nil
			}
		}
	}
	return nil, fmt.Errorf("%s is not available", local.Name)
}

func (f *frame) global(ref *GlobalRef) (runtimeValue, error) {
	root := f.root()
	var current runtimeValue
	if ref.Local == nil && ref.Field == nil {
		return nil, fmt.Errorf("unknown identifier %s", strings.Join(ref.Path, "."))
	}
	if ref.Local != nil {
		current = root.locals[ref.Local]
	} else {
		node, isDecoded := root.nodes[ref.Field]
		if !isDecoded {
			return nil, fmt.Errorf("%s is not available", ref.Field.Name)
		}
		current = node.raw
	}
	for _, name := range ref.Rest {
		node, isPattern := current.(*DecodedValue)
		if !isPattern || node.frame == nil {
			return nil, fmt.Errorf("%s has no fields", strings.Join(ref.Path, "."))
		}
		child := node.frame.nodeNamed(name)
		if child == nil {
			return nil, fmt.Errorf("%s is not available", strings.Join(ref.Path, "."))
		}
		current = child.raw
	}
	return current, nil
}

func (f *frame) matchingCase(s *Match) ([]Statement, error) {
	matched := -1
	for i, matchCase := range s.Cases {
		applies, err := f.truthy(matchCase.Condition)
		if err != nil {
			return nil, err
		}
		if !applies {
			continue
		}
		if matched != -1 {
			return nil, fmt.Errorf("ambiguous match: several cases apply")
		}
		matched = i
	}
	if matched == -1 {
		return s.Default, nil
	}
	return s.Cases[matched].Then, nil
}

func (f *frame) loop(s *Loop) (flow, runtimeValue, error) {
	if control, result, err := f.execute(s.Init); err != nil || control == flowReturn {
		return control, result, err
	}
	for {
		proceed, err := f.truthy(s.Condition)
		if err != nil {
			return flowNext, nil, err
		}
		if !proceed {
			return flowNext, nil, nil
		}
		control, result, err := f.execute(s.Body)
		if err != nil {
			return flowNext, nil, err
		}
		switch control {
		case flowBreak:
			return flowNext, nil, nil
		case flowReturn:
			return control, result, nil
		}
		if control, result, err := f.execute(s.Step); err != nil || control == flowReturn {
			return control, result, err
		}
	}
}

func (f *frame) try(s *Try) (flow, runtimeValue, error) {
	owner := f.cursorOwner()
	cursor := owner.cursor
	fields := len(f.value.Fields)
	control, result, err := f.execute(s.Body)
	if err == nil {
		return control, result, nil
	}
	owner.cursor = cursor
	f.discardFieldsFrom(fields)
	return f.execute(s.Catch)
}

func (f *frame) discardFieldsFrom(index int) {
	discarded := f.value.Fields[index:]
	f.value.Fields = f.value.Fields[:index]
	for field, node := range f.nodes {
		for _, gone := range discarded {
			if node == gone {
				delete(f.nodes, field)
			}
		}
	}
}

func (f *frame) cursorOwner() *frame {
	if f.caller != nil {
		return f.caller.cursorOwner()
	}
	return f
}

func (f *frame) eval(v Value) (runtimeValue, error) {
	switch v := v.(type) {
	case *Constant:
		if v.Char {
			return charValue(v.Value), nil
		}
		if v.Wide != nil {
			return new(big.Int).Set(v.Wide), nil
		}
		if v.Unsigned {
			return uint64(v.Value), nil
		}
		return v.Value, nil
	case *StringConstant:
		return v.Value, nil
	case *FloatConstant:
		return v.Value, nil
	case *EnumMemberRef:
		if v.Member.Wide != nil {
			return new(big.Int).Set(v.Member.Wide), nil
		}
		return v.Member.Value, nil
	case *FieldRef:
		node, err := f.node(v.Path)
		if err != nil {
			return nil, err
		}
		return node.runtimeValue(), nil
	case *ParentFieldRef:
		node, err := f.parentNode(v.Depth, v.Path)
		if err != nil {
			return nil, err
		}
		return node.runtimeValue(), nil
	case *LocalRef:
		return f.lookupLocal(v.Local)
	case *BitRef:
		node, isDecoded := f.bitNodes[v.Member]
		if !isDecoded {
			return nil, fmt.Errorf("%s is not available", v.Member.Name)
		}
		return node.runtimeValue(), nil
	case *GlobalRef:
		return f.global(v)
	case *ArrayValue:
		elements := make([]runtimeValue, len(v.Elements))
		for i, element := range v.Elements {
			result, err := f.eval(element)
			if err != nil {
				return nil, err
			}
			elements[i] = result
		}
		return elements, nil
	case *Index:
		element, err := f.element(v)
		if err != nil {
			return nil, err
		}
		return element.runtimeValue(), nil
	case *MemberOf:
		member, err := f.memberOf(v)
		if err != nil {
			return nil, err
		}
		return member.runtimeValue(), nil
	case *Cursor:
		owner := f.cursorOwner()
		return int64(owner.cursor - owner.base), nil
	case *AddressOf:
		node, err := f.target(v.Target)
		if err != nil {
			return nil, err
		}
		return int64(node.Offset - f.cursorOwner().base), nil
	case *SizeOfValue:
		if local, isLocal := v.Target.(*LocalRef); isLocal {
			if text, isString := f.locals[local.Local].(string); isString {
				return int64(len(text)), nil
			}
		}
		node, err := f.target(v.Target)
		if err != nil {
			return nil, err
		}
		if node.Size == nil {
			return nil, fmt.Errorf("size is not available")
		}
		return int64(*node.Size), nil
	case *SizeOf:
		layout := f.decoder.layout.Of(v.Type)
		if layout.Dynamic {
			return nil, fmt.Errorf("sizeof a dynamically sized type")
		}
		return int64(layout.Size), nil
	case *ThisRef:
		scope, err := f.ancestor(v.Depth)
		if err != nil {
			return nil, err
		}
		return scope.value, nil
	case *Builtin:
		return f.builtin(v)
	case *FunctionCall:
		return f.call(v)
	case *Labelled:
		inner, err := f.eval(v.Value)
		if err != nil {
			return nil, err
		}
		number, err := toInt(scalarOf(inner))
		if err != nil {
			return nil, err
		}
		return enumValue{enum: v.Enum, value: number}, nil
	case *Cast:
		operand, err := f.eval(v.Operand)
		if err != nil {
			return nil, err
		}
		result, err := cast(operand, v.Kind)
		if err != nil || v.Order == NativeOrder || v.Order == f.decoder.defaultOrderFor(v) || v.Kind.IsFloatingPoint() {
			return result, err
		}
		return f.byteSwapped(result, v.Kind)
	case *TemplateArgument:
		argument, err := f.eval(v.Value)
		if err != nil {
			return nil, err
		}
		return templateArgumentText(argument), nil
	case *PatternTypeName:
		target, err := f.eval(v.Target)
		if err != nil {
			return nil, err
		}
		node, isPattern := target.(*DecodedValue)
		if !isPattern {
			return nil, fmt.Errorf("typenameof needs a pattern")
		}
		return node.Type, nil
	case *UnaryOp:
		operand, err := f.eval(v.Operand)
		if err != nil {
			return nil, err
		}
		return unary(v.Operator, operand)
	case *BinaryOp:
		return f.binary(v)
	case *Select:
		condition, err := f.truthy(v.Condition)
		if err != nil {
			return nil, err
		}
		if condition {
			return f.eval(v.Then)
		}
		return f.eval(v.Else)
	}
	panic("unreachable")
}

func (f *frame) evalInt(v Value) (int64, error) {
	result, err := f.eval(v)
	if err != nil {
		return 0, err
	}
	return toInt(result)
}

func (f *frame) truthy(v Value) (bool, error) {
	result, err := f.eval(v)
	if err != nil {
		return false, err
	}
	return truthyValue(result)
}

func (d *decoder) defaultOrderFor(v *Cast) ByteOrder {
	for _, order := range []ByteOrder{d.defaultOrder, v.DefaultOrder} {
		if order != NativeOrder {
			return order
		}
	}
	return LittleEndian
}

func (f *frame) byteSwapped(v runtimeValue, kind PrimitiveKind) (runtimeValue, error) {
	number, err := toUint(v)
	if err != nil {
		return nil, err
	}
	swapped := uint64(0)
	for i := 0; i != kind.Size(); i++ {
		swapped = swapped<<8 | number&0xff
		number >>= 8
	}
	return cast(swapped, kind)
}

func truthyValue(result runtimeValue) (bool, error) {
	switch result := result.(type) {
	case bool:
		return result, nil
	case string:
		return result != "", nil
	case *DecodedValue:
		if number := patternNumber(result); number != runtimeValue(result) {
			return truthyValue(number)
		}
		return true, nil
	case *big.Int:
		return result.Sign() != 0, nil
	}
	number, err := toFloat(result)
	if err != nil {
		return false, err
	}
	return number != 0, nil
}

func (f *frame) binary(v *BinaryOp) (runtimeValue, error) {
	if v.Operator == "&&" || v.Operator == "||" {
		left, err := f.truthy(v.Left)
		if err != nil {
			return nil, err
		}
		if left != (v.Operator == "&&") {
			return left, nil
		}
		return f.truthy(v.Right)
	}
	left, err := f.eval(v.Left)
	if err != nil {
		return nil, err
	}
	right, err := f.eval(v.Right)
	if err != nil {
		return nil, err
	}
	return combine(v.Operator, left, right)
}

func combine(operator string, left runtimeValue, right runtimeValue) (runtimeValue, error) {
	left, right = patternNumber(left), patternNumber(right)
	if leftText, isString := left.(string); isString {
		return stringBinary(operator, leftText, right)
	}
	if needsWide(operator, left, right) {
		l, err := toBig(left)
		if err != nil {
			return nil, err
		}
		r, err := toBig(right)
		if err != nil {
			return nil, err
		}
		return wideBinary(operator, l, r)
	}
	if character, isChar := left.(charValue); isChar {
		if _, isString := right.(string); isString {
			return stringBinary(operator, string(rune(character)), right)
		}
	}
	if _, isString := right.(string); isString {
		return nil, fmt.Errorf("cannot apply %s to a number and a string", operator)
	}
	if isFloating(left) || isFloating(right) {
		l, err := toFloat(left)
		if err != nil {
			return nil, err
		}
		r, err := toFloat(right)
		if err != nil {
			return nil, err
		}
		return floatBinary(operator, l, r)
	}
	if isUnsigned(left) || isUnsigned(right) {
		l, err := toUint(left)
		if err != nil {
			return nil, err
		}
		r, err := toUint(right)
		if err != nil {
			return nil, err
		}
		return unsignedBinary(operator, l, r)
	}
	l, err := toInt(left)
	if err != nil {
		return nil, err
	}
	r, err := toInt(right)
	if err != nil {
		return nil, err
	}
	return signedBinary(operator, l, r)
}

func isWide(v runtimeValue) bool {
	_, isWide := v.(*big.Int)
	return isWide
}

func needsWide(operator string, left runtimeValue, right runtimeValue) bool {
	if isWide(left) || isWide(right) {
		_, leftString := left.(string)
		_, rightString := right.(string)
		return !leftString && !rightString
	}
	switch operator {
	case "+", "-", "*", "<<":
		return isUnsigned(left) || isUnsigned(right)
	}
	return false
}

func toBig(v runtimeValue) (*big.Int, error) {
	switch v := v.(type) {
	case *big.Int:
		return v, nil
	case uint64:
		return new(big.Int).SetUint64(v), nil
	case float64:
		result, _ := big.NewFloat(v).Int(nil)
		return result, nil
	}
	number, err := toInt(v)
	if err != nil {
		return nil, err
	}
	return big.NewInt(number), nil
}

var wideMask = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))

func narrow(v *big.Int) runtimeValue {
	if v.IsInt64() {
		return v.Int64()
	}
	if v.IsUint64() {
		return v.Uint64()
	}
	return v
}

func wideBinary(operator string, left *big.Int, right *big.Int) (runtimeValue, error) {
	result := new(big.Int)
	switch operator {
	case "+":
		result.Add(left, right)
	case "-":
		result.Sub(left, right)
	case "*":
		result.Mul(left, right)
	case "/", "%":
		if right.Sign() == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		if operator == "/" {
			result.Quo(left, right)
		} else {
			result.Rem(left, right)
		}
	case "<<", ">>":
		if !right.IsUint64() || right.Uint64() > 256 {
			return nil, fmt.Errorf("shift count is out of range")
		}
		if operator == "<<" {
			result.Lsh(left, uint(right.Uint64()))
		} else {
			result.Rsh(left, uint(right.Uint64()))
		}
	case "&":
		result.And(left, right)
	case "|":
		result.Or(left, right)
	case "^":
		result.Xor(left, right)
	case "==":
		return left.Cmp(right) == 0, nil
	case "!=":
		return left.Cmp(right) != 0, nil
	case "<":
		return left.Cmp(right) < 0, nil
	case ">":
		return left.Cmp(right) > 0, nil
	case "<=":
		return left.Cmp(right) <= 0, nil
	case ">=":
		return left.Cmp(right) >= 0, nil
	case "&&":
		return left.Sign() != 0 && right.Sign() != 0, nil
	case "||":
		return left.Sign() != 0 || right.Sign() != 0, nil
	case "^^":
		return (left.Sign() != 0) != (right.Sign() != 0), nil
	default:
		return nil, fmt.Errorf("unknown operator %s", operator)
	}
	return narrow(result), nil
}

func stringBinary(operator string, left string, right runtimeValue) (runtimeValue, error) {
	if character, isChar := right.(charValue); isChar {
		right = string(rune(character))
	}
	text, isString := right.(string)
	switch operator {
	case "*":
		count, err := toInt(right)
		if err != nil {
			return nil, err
		}
		if count < 0 {
			return nil, fmt.Errorf("a string cannot be repeated a negative number of times")
		}
		return strings.Repeat(left, int(count)), nil
	case "+":
		if !isString {
			text = format("{}", []runtimeValue{right})
		}
		return left + text, nil
	case "==":
		return isString && left == text, nil
	case "!=":
		return !isString || left != text, nil
	case "<", ">", "<=", ">=":
		if !isString {
			return nil, fmt.Errorf("cannot compare a string with a number")
		}
		return signedBinary(operator, int64(strings.Compare(left, text)), 0)
	}
	return nil, fmt.Errorf("cannot apply %s to strings", operator)
}

func floatBinary(operator string, l float64, r float64) (runtimeValue, error) {
	switch operator {
	case "+":
		return l + r, nil
	case "-":
		return l - r, nil
	case "*":
		return l * r, nil
	case "/":
		if r == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return l / r, nil
	case "%":
		if r == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return math.Mod(l, r), nil
	case "==":
		return l == r, nil
	case "!=":
		return l != r, nil
	case "<":
		return l < r, nil
	case ">":
		return l > r, nil
	case "<=":
		return l <= r, nil
	case ">=":
		return l >= r, nil
	case "^^":
		return (l != 0) != (r != 0), nil
	}
	return nil, fmt.Errorf("cannot apply %s to floating point numbers", operator)
}

func unsignedBinary(operator string, l uint64, r uint64) (runtimeValue, error) {
	switch operator {
	case "+":
		return l + r, nil
	case "-":
		return l - r, nil
	case "*":
		return l * r, nil
	case "/":
		if r == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return l / r, nil
	case "%":
		if r == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return l % r, nil
	case "<<":
		return l << r, nil
	case ">>":
		return l >> r, nil
	case "&":
		return l & r, nil
	case "|":
		return l | r, nil
	case "^":
		return l ^ r, nil
	case "==":
		return l == r, nil
	case "!=":
		return l != r, nil
	case "<":
		return l < r, nil
	case ">":
		return l > r, nil
	case "<=":
		return l <= r, nil
	case ">=":
		return l >= r, nil
	case "^^":
		return (l != 0) != (r != 0), nil
	}
	panic("unreachable")
}

func signedBinary(operator string, l int64, r int64) (runtimeValue, error) {
	switch operator {
	case "/", "%":
		if r == 0 {
			return nil, fmt.Errorf("division by zero")
		}
	case "==", "!=", "<", ">", "<=", ">=", "^^":
		return applyBinary(operator, l, r) != 0, nil
	}
	return applyBinary(operator, l, r), nil
}

func unary(operator string, operand runtimeValue) (runtimeValue, error) {
	switch operator {
	case "!":
		switch operand := operand.(type) {
		case bool:
			return !operand, nil
		case string:
			return operand == "", nil
		}
		number, err := toFloat(operand)
		if err != nil {
			return nil, err
		}
		return number == 0, nil
	case "-":
		switch operand := operand.(type) {
		case float64:
			return -operand, nil
		case uint64:
			return narrow(new(big.Int).Neg(new(big.Int).SetUint64(operand))), nil
		case *big.Int:
			return narrow(new(big.Int).Neg(operand)), nil
		}
		number, err := toInt(operand)
		if err != nil {
			return nil, err
		}
		return -number, nil
	case "~":
		if isUnsigned(operand) || isWide(operand) {
			wide, err := toBig(operand)
			if err != nil {
				return nil, err
			}
			return narrow(new(big.Int).Xor(wide, wideMask)), nil
		}
		number, err := toInt(operand)
		if err != nil {
			return nil, err
		}
		return ^number, nil
	}
	return operand, nil
}

func cast(operand runtimeValue, kind PrimitiveKind) (runtimeValue, error) {
	switch {
	case kind == Bool:
		if text, isString := operand.(string); isString {
			return text != "", nil
		}
		number, err := toFloat(operand)
		if err != nil {
			return nil, err
		}
		return number != 0, nil
	case kind.IsFloatingPoint():
		if text, isString := operand.(string); isString {
			return strconv.ParseFloat(text, 64)
		}
		number, err := toFloat(operand)
		if err != nil {
			return nil, err
		}
		if kind == Float {
			return float64(float32(number)), nil
		}
		return number, nil
	case kind == Char || kind == Char16:
		number, err := toInt(operand)
		if err != nil {
			return nil, err
		}
		return string(rune(number)), nil
	}
	if text, isString := operand.(string); isString {
		if len(text) > 16 {
			return nil, fmt.Errorf("a string of %d bytes does not fit the integer", len(text))
		}
		packed := new(big.Int)
		for i := len(text) - 1; i >= 0; i-- {
			packed.Lsh(packed, 8)
			packed.Or(packed, big.NewInt(int64(text[i])))
		}
		operand = narrow(packed)
	}
	bits := uint(kind.Size() * 8)
	if bits > 64 || isWide(operand) {
		wide, err := toBig(operand)
		if err != nil {
			return nil, err
		}
		if bits > 64 {
			masked := new(big.Int).And(wide, wideMask)
			if kind.IsSigned() && masked.Bit(127) == 1 {
				masked.Sub(masked, new(big.Int).Lsh(big.NewInt(1), 128))
			}
			return narrow(masked), nil
		}
		operand = new(big.Int).And(wide, new(big.Int).SetUint64(^uint64(0))).Uint64()
	}
	if kind.IsSigned() {
		number, err := toInt(operand)
		if err != nil {
			return nil, err
		}
		if bits >= 64 {
			return number, nil
		}
		return signExtend(uint64(number)&(1<<bits-1), int(bits)), nil
	}
	number, err := toUint(operand)
	if err != nil {
		return nil, err
	}
	if bits >= 64 {
		return number, nil
	}
	return number & (1<<bits - 1), nil
}

func isFloating(v runtimeValue) bool {
	_, isFloat := v.(float64)
	return isFloat
}

func isUnsigned(v runtimeValue) bool {
	_, isUnsigned := v.(uint64)
	return isUnsigned
}

func toInt(v runtimeValue) (int64, error) {
	switch v := v.(type) {
	case *big.Int:
		if v.IsInt64() {
			return v.Int64(), nil
		}
		if v.IsUint64() {
			return int64(v.Uint64()), nil
		}
		return 0, fmt.Errorf("the value does not fit 64 bits")
	case charValue:
		return int64(v), nil
	case enumValue:
		return v.value, nil
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case bool:
		return boolToInt(v), nil
	case int:
		return int64(v), nil
	case *DecodedValue:
		if number := patternNumber(v); number != runtimeValue(v) {
			return toInt(number)
		}
	case nil:
		return 0, fmt.Errorf("runtimeValue is not available")
	}
	return 0, fmt.Errorf("expected a number")
}

func toUint(v runtimeValue) (uint64, error) {
	if node, isPattern := v.(*DecodedValue); isPattern {
		v = patternNumber(node)
	}
	if unsigned, isUnsigned := v.(uint64); isUnsigned {
		return unsigned, nil
	}
	if wide, isWide := v.(*big.Int); isWide {
		if wide.IsUint64() {
			return wide.Uint64(), nil
		}
		return 0, fmt.Errorf("the value does not fit 64 bits")
	}
	number, err := toInt(v)
	return uint64(number), err
}

func toFloat(v runtimeValue) (float64, error) {
	if node, isPattern := v.(*DecodedValue); isPattern {
		v = patternNumber(node)
	}
	switch v := v.(type) {
	case float64:
		return v, nil
	case uint64:
		return float64(v), nil
	case *big.Int:
		number, _ := new(big.Float).SetInt(v).Float64()
		return number, nil
	}
	number, err := toInt(v)
	return float64(number), err
}

func (f *frame) call(c *FunctionCall) (runtimeValue, error) {
	arguments, err := f.evalArguments(c.Arguments)
	if err != nil {
		return nil, err
	}
	for i, param := range c.Function.Params {
		if i < len(c.Arguments) && isComposite(param.Type) && denotesPattern(c.Arguments[i]) {
			if arguments[i], err = f.target(c.Arguments[i]); err != nil {
				return nil, err
			}
		}
	}
	if c.Function.Variadic {
		fixed := len(c.Function.Params) - 1
		if len(arguments) < fixed {
			return nil, fmt.Errorf("%s expects at least %d arguments", c.Function.Name, fixed)
		}
		pack := append([]runtimeValue{}, arguments[fixed:]...)
		arguments = append(arguments[:fixed], pack)
	}
	callee, result, err := f.invokeWith(c.Function, arguments)
	if err != nil {
		return nil, err
	}
	for i, param := range c.Function.Params {
		if i >= len(c.Arguments) {
			break
		}
		if ref, isLocal := c.Arguments[i].(*LocalRef); param.Ref && isLocal {
			f.setLocal(ref.Local, callee.locals[param])
		}
	}
	return result, nil
}

func (f *frame) evalArguments(values []Value) ([]runtimeValue, error) {
	var arguments []runtimeValue
	for _, argument := range values {
		result, err := f.eval(argument)
		if err != nil {
			return nil, err
		}
		if elements, isSlice := result.([]runtimeValue); isSlice && isPack(argument) {
			arguments = append(arguments, elements...)
			continue
		}
		arguments = append(arguments, result)
	}
	return arguments, nil
}

func (f *frame) invoke(function *Function, arguments []runtimeValue) (runtimeValue, error) {
	_, result, err := f.invokeWith(function, arguments)
	return result, err
}

func (f *frame) invokeWith(function *Function, arguments []runtimeValue) (*frame, runtimeValue, error) {
	if f.depth >= maxCallDepth {
		return nil, nil, fmt.Errorf("call depth exceeded")
	}
	callee := &frame{
		decoder:  f.decoder,
		value:    &DecodedValue{},
		caller:   f,
		parent:   f.cursorOwner(),
		depth:    f.depth + 1,
		nodes:    map[*Field]*DecodedValue{},
		locals:   map[*Local]runtimeValue{},
		exports:  map[*Local]*DecodedValue{},
		bitNodes: map[*BitfieldMember]*DecodedValue{},
	}
	for i, param := range function.Params {
		if i >= len(arguments) {
			break
		}
		if param.Ref || param.Type == nil || isComposite(param.Type) {
			callee.locals[param] = arguments[i]
		} else {
			callee.locals[param] = scalarOf(arguments[i])
		}
	}
	_, result, err := callee.execute(function.Body)
	if err != nil {
		return nil, nil, err
	}
	return callee, result, nil
}

func integerKindOfSize(size int, signed bool) PrimitiveKind {
	for kind := U8; kind <= U128; kind++ {
		if kind.Size() == size {
			if signed {
				return kind + (S8 - U8)
			}
			return kind
		}
	}
	return U8
}

func extremum(wantMax bool, a runtimeValue, b runtimeValue) (runtimeValue, error) {
	if isFloating(a) || isFloating(b) {
		l, err := toFloat(a)
		if err != nil {
			return nil, err
		}
		r, err := toFloat(b)
		if err != nil {
			return nil, err
		}
		if (l > r) == wantMax {
			return l, nil
		}
		return r, nil
	}
	l, err := toInt(a)
	if err != nil {
		return nil, err
	}
	r, err := toInt(b)
	if err != nil {
		return nil, err
	}
	if (l > r) == wantMax {
		return l, nil
	}
	return r, nil
}

func patternNumber(v runtimeValue) runtimeValue {
	node, isPattern := v.(*DecodedValue)
	if !isPattern {
		return v
	}
	if scalar := scalarOf(node); scalar != v {
		return scalar
	}
	if node.frame == nil || node.Size == nil || *node.Size > 16 {
		return v
	}
	data := node.frame.decoder.sections[node.Section].data
	if node.Offset+*node.Size > len(data) {
		return v
	}
	number := new(big.Int)
	for i := *node.Size - 1; i >= 0; i-- {
		number.Lsh(number, 8)
		number.Or(number, big.NewInt(int64(data[node.Offset+i])))
	}
	return narrow(number)
}

func scalarOf(v runtimeValue) runtimeValue {
	if node, isPattern := v.(*DecodedValue); isPattern {
		if _, isComposite := node.raw.(*DecodedValue); !isComposite && node.raw != nil {
			return node.raw
		}
	}
	return v
}

func display(v runtimeValue) string {
	if node, isPattern := v.(*DecodedValue); isPattern {
		if scalar := scalarOf(node); scalar != v {
			return display(scalar)
		}
	}
	switch v := v.(type) {
	case string:
		return v
	case *big.Int:
		return v.String()
	case charValue:
		return string(rune(v))
	case enumValue:
		return v.enum.Name + "::" + enumLabel(v.enum, v.value)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case *DecodedValue:
		return v.Type
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func format(text string, arguments []runtimeValue) string {
	var out strings.Builder
	next := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '{' && i+1 < len(text) && text[i+1] == '{':
			out.WriteByte('{')
			i++
		case c == '}' && i+1 < len(text) && text[i+1] == '}':
			out.WriteByte('}')
			i++
		case c == '{':
			end := strings.IndexByte(text[i:], '}')
			if end == -1 {
				out.WriteString(text[i:])
				return out.String()
			}
			out.WriteString(formatPlaceholder(text[i+1:i+end], arguments, &next))
			i += end
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

func formatPlaceholder(placeholder string, arguments []runtimeValue, next *int) string {
	index, spec, _ := strings.Cut(placeholder, ":")
	position := *next
	if index != "" {
		if parsed, err := strconv.Atoi(index); err == nil {
			position = parsed
		}
	} else {
		*next++
	}
	if position >= len(arguments) {
		return "{" + placeholder + "}"
	}
	return formatValue(arguments[position], spec)
}

func formatValue(v runtimeValue, spec string) string {
	alternate := false
	zero := false
	width := 0
	precision := -1
	verb := byte(0)
	i := 0
	if i < len(spec) && spec[i] == '#' {
		alternate = true
		i++
	}
	if i < len(spec) && spec[i] == '0' {
		zero = true
		i++
	}
	for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
		width = width*10 + int(spec[i]-'0')
		i++
	}
	if i < len(spec) && spec[i] == '.' {
		i++
		precision = 0
		for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
			precision = precision*10 + int(spec[i]-'0')
			i++
		}
	}
	if i < len(spec) {
		verb = spec[i]
	}

	var text string
	switch verb {
	case 'x', 'X', 'b', 'o':
		base := map[byte]int{'x': 16, 'X': 16, 'b': 2, 'o': 8}[verb]
		if wide, isWide := v.(*big.Int); isWide {
			text = wide.Text(base)
			if verb == 'X' {
				text = strings.ToUpper(text)
			}
			break
		}
		number, err := toUint(v)
		if err != nil {
			text = display(v)
			break
		}
		text = strconv.FormatUint(number, base)
		if verb == 'X' {
			text = strings.ToUpper(text)
		}
		if alternate {
			text = map[byte]string{'x': "0x", 'X': "0x", 'b': "0b", 'o': "0o"}[verb] + text
		}
	case 'c':
		number, err := toInt(v)
		if err != nil {
			text = display(v)
			break
		}
		text = string(rune(number))
	default:
		if number, isFloat := v.(float64); isFloat && precision >= 0 {
			text = strconv.FormatFloat(number, 'f', precision, 64)
		} else {
			text = display(v)
		}
	}
	if len(text) < width {
		padding := strings.Repeat(" ", width-len(text))
		if zero {
			padding = strings.Repeat("0", width-len(text))
			if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0b") || strings.HasPrefix(text, "0o") {
				return text[:2] + padding + text[2:]
			}
			if strings.HasPrefix(text, "-") {
				return "-" + padding + text[1:]
			}
		}
		return padding + text
	}
	return text
}

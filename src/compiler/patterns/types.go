package patterns

import (
	"fmt"
	"math/big"
	"strings"
)

type Module struct {
	Types             []NamedType
	Functions         []*Function
	Root              *Struct
	Files             []string
	DynamicEndian     bool
	DynamicAttributes bool
	Warnings          []Diagnostic
}

type ByteOrder int

const (
	NativeOrder ByteOrder = iota
	LittleEndian
	BigEndian
)

type ABI int

const (
	PackedABI ABI = iota
	NativeABI
)

type NamedType interface {
	Type
	TypeName() string
}

type Type interface {
	typeNode()
}

type Primitive struct {
	Kind  PrimitiveKind
	Order ByteOrder
}

type PrimitiveKind int

const (
	U8 PrimitiveKind = iota
	U16
	U24
	U32
	U48
	U64
	U96
	U128
	S8
	S16
	S24
	S32
	S48
	S64
	S96
	S128
	Float
	Double
	Bool
	Char
	Char16
)

var primitiveNames = [...]string{
	"u8", "u16", "u24", "u32", "u48", "u64", "u96", "u128",
	"s8", "s16", "s24", "s32", "s48", "s64", "s96", "s128",
	"float", "double", "bool", "char", "char16",
}

var primitiveSizes = [...]int{1, 2, 3, 4, 6, 8, 12, 16, 1, 2, 3, 4, 6, 8, 12, 16, 4, 8, 1, 1, 2}

var primitiveKindsByName = func() map[string]PrimitiveKind {
	kinds := map[string]PrimitiveKind{}
	for kind, name := range primitiveNames {
		kinds[name] = PrimitiveKind(kind)
	}
	return kinds
}()

func (k PrimitiveKind) Name() string {
	return primitiveNames[k]
}

func (k PrimitiveKind) Size() int {
	return primitiveSizes[k]
}

func (k PrimitiveKind) IsInteger() bool {
	return k <= S128
}

func (k PrimitiveKind) IsSigned() bool {
	return k >= S8 && k <= S128
}

func (k PrimitiveKind) IsFloatingPoint() bool {
	return k == Float || k == Double
}

type Struct struct {
	Name       string
	Doc        string
	ABI        ABI
	Global     bool
	Base       *Struct
	Params     []*Local
	Args       []Value
	Naming     []NamePart
	Body       []Statement
	Fields     []*Field
	Simple     bool
	Attributes []*AttributeUse
	Position   Position
}

type Union struct {
	Name       string
	Doc        string
	ABI        ABI
	Params     []*Local
	Args       []Value
	Naming     []NamePart
	Body       []Statement
	Fields     []*Field
	Simple     bool
	Attributes []*AttributeUse
	Position   Position
}

type NamePart struct {
	Text  string
	Param *Local
}

type Statement interface {
	statementNode()
}

type Field struct {
	Name            string
	Type            Type
	Order           ByteOrder
	Doc             string
	Hidden          bool
	NoUniqueAddress bool
	Address         Value
	Section         Value
	Guard           Value
	Attributes      []*AttributeUse
	PointerBase     *Function
	Position        Position
}

type AttributeUse struct {
	Name      string
	Arguments []Value
	Function  *Function
	Builtin   string
	Dynamic   Value
}

type Local struct {
	Name        string
	Type        Type
	Init        Value
	Ref         bool
	Export      bool
	Global      bool
	Member      bool
	Const       bool
	Pack        bool
	Input       bool
	StringCount Value
}

type Function struct {
	Name     string
	Doc      string
	Params   []*Local
	Defaults []Value
	Variadic bool
	Body     []Statement
	Position Position
}

type Return struct {
	Value Value
}

type Loop struct {
	Init      []Statement
	Condition Value
	Step      []Statement
	Body      []Statement
}

type Break struct{}

type Continue struct{}

type Try struct {
	Body  []Statement
	Catch []Statement
}

type Evaluation struct {
	Value Value
}

type Failure struct {
	Message string
}

type Assignment struct {
	Target   Value
	Operator string
	Value    Value
}

type Conditional struct {
	Condition Value
	Then      []Statement
	Else      []Statement
}

type Match struct {
	Cases   []MatchCase
	Default []Statement
}

type MatchCase struct {
	Condition Value
	Then      []Statement
}

func (*Field) statementNode()       {}
func (*Local) statementNode()       {}
func (*Assignment) statementNode()  {}
func (*Conditional) statementNode() {}
func (*Match) statementNode()       {}
func (*Return) statementNode()      {}
func (*Loop) statementNode()        {}
func (*Break) statementNode()       {}
func (*Continue) statementNode()    {}
func (*Try) statementNode()         {}
func (*Evaluation) statementNode()  {}
func (*Failure) statementNode()     {}

type Padding struct {
	Size  Value
	While Value
}

type Enum struct {
	Name       string
	Doc        string
	Underlying *Primitive
	Encoding   Type
	Members    []*EnumMember
	Attributes []*AttributeUse
	Position   Position
}

type EnumMember struct {
	Name     string
	Value    int64
	Last     int64
	Wide     *big.Int
	WideLast *big.Int
	Doc      string

	expr Value
	last Value
}

type Bitfield struct {
	Name       string
	Doc        string
	Order      ByteOrder
	Params     []*Local
	Args       []Value
	Body       []Statement
	Members    []*BitfieldMember
	TotalBits  int
	FixedBits  int
	Direction  BitOrder
	Simple     bool
	Attributes []*AttributeUse
	Position   Position

	direction Value
	fixedBits Value
}

type BitOrder int

const (
	NaturalBitOrder BitOrder = iota
	MostToLeastSignificant
	LeastToMostSignificant
)

func (t *Bitfield) Reversed(bigEndian bool) bool {
	return (t.Direction == MostToLeastSignificant && !bigEndian) || (t.Direction == LeastToMostSignificant && bigEndian)
}

func (t *Bitfield) BitPosition(offset int, width int, bigEndian bool) int {
	if t.Reversed(bigEndian) {
		return t.FixedBits - offset - width
	}
	return offset
}

type BitfieldMember struct {
	Name   string
	Offset int
	Bits   int
	Signed bool
	Bool   bool
	Enum   *Enum
	Doc    string

	bits Value
}

func (*BitfieldMember) statementNode() {}

type Array struct {
	Element Type
	Length  Value
	While   Value
}

type Pointer struct {
	Target Type
	Width  *Primitive
}

type Alias struct {
	Name       string
	Doc        string
	Target     Type
	Attributes []*AttributeUse
	Position   Position
}

func (*Primitive) typeNode() {}
func (*Struct) typeNode()    {}
func (*Union) typeNode()     {}
func (*Padding) typeNode()   {}
func (*Enum) typeNode()      {}
func (*Bitfield) typeNode()  {}
func (*Array) typeNode()     {}
func (*Pointer) typeNode()   {}
func (*Alias) typeNode()     {}

func (t *Struct) TypeName() string   { return t.Name }
func (t *Union) TypeName() string    { return t.Name }
func (t *Enum) TypeName() string     { return t.Name }
func (t *Bitfield) TypeName() string { return t.Name }
func (t *Alias) TypeName() string    { return t.Name }

func (m *Module) TypesWithAliasesLast() []NamedType {
	used := m.usedTypes()
	var ordered []NamedType
	for _, t := range m.Types {
		if _, isAlias := t.(*Alias); !isAlias && used[t] {
			ordered = append(ordered, t)
		}
	}
	for _, t := range m.Types {
		if _, isAlias := t.(*Alias); isAlias && used[t] {
			ordered = append(ordered, t)
		}
	}
	return namespaceOwnersFirst(ordered)
}

func namespaceOwnersFirst(types []NamedType) []NamedType {
	byName := map[string]NamedType{}
	for _, t := range types {
		byName[t.TypeName()] = t
	}
	placed := map[NamedType]bool{}
	var ordered []NamedType
	var place func(t NamedType)
	place = func(t NamedType) {
		if placed[t] {
			return
		}
		placed[t] = true
		segments := strings.Split(t.TypeName(), "::")
		for depth := 1; depth < len(segments); depth++ {
			if owner, isType := byName[strings.Join(segments[:depth], "::")]; isType {
				place(owner)
			}
		}
		ordered = append(ordered, t)
	}
	for _, t := range types {
		place(t)
	}
	return ordered
}

func (m *Module) function(name string) *Function {
	for _, function := range m.Functions {
		if function.Name == name {
			return function
		}
	}
	return nil
}

func (m *Module) usedTypes() map[Type]bool {
	used := map[Type]bool{}
	var visit func(t Type)
	visit = func(t Type) {
		if t == nil || used[t] {
			return
		}
		switch t := t.(type) {
		case *Struct:
			used[t] = true
			if t.Base != nil {
				visit(t.Base)
			}
			for _, field := range allFields(t) {
				visit(field.Type)
			}
			visitLocalTypes(t.Body, visit)
		case *Union:
			used[t] = true
			for _, field := range t.Fields {
				visit(field.Type)
			}
			visitLocalTypes(t.Body, visit)
		case *Enum, *Bitfield:
			used[t] = true
		case *Alias:
			used[t] = true
			visit(t.Target)
		case *Array:
			visit(t.Element)
		case *Pointer:
			visit(t.Target)
			if t.Width != nil {
				visit(t.Width)
			}
		}
	}
	for _, t := range m.Types {
		if !strings.HasPrefix(t.TypeName(), "std::") {
			visit(t)
		}
	}
	for _, f := range m.Functions {
		visitLocalTypes(f.Body, visit)
	}
	return used
}

func visitLocalTypes(statements []Statement, visit func(Type)) {
	for _, statement := range statements {
		switch s := statement.(type) {
		case *Local:
			visit(s.Type)
		case *Conditional:
			visitLocalTypes(s.Then, visit)
			visitLocalTypes(s.Else, visit)
		case *Match:
			for _, matchCase := range s.Cases {
				visitLocalTypes(matchCase.Then, visit)
			}
			visitLocalTypes(s.Default, visit)
		case *Loop:
			visitLocalTypes(s.Init, visit)
			visitLocalTypes(s.Step, visit)
			visitLocalTypes(s.Body, visit)
		case *Try:
			visitLocalTypes(s.Body, visit)
			visitLocalTypes(s.Catch, visit)
		}
	}
}

func DescribeType(t Type) string {
	switch t := t.(type) {
	case *Primitive:
		switch t.Order {
		case LittleEndian:
			return "le " + t.Kind.Name()
		case BigEndian:
			return "be " + t.Kind.Name()
		}
		return t.Kind.Name()
	case NamedType:
		return t.TypeName()
	case *Padding:
		return "padding"
	case *Array:
		if t.While != nil {
			return DescribeType(t.Element) + "[while]"
		}
		if t.Length == nil {
			return DescribeType(t.Element) + "[]"
		}
		if length, isConstant := t.Length.(*Constant); isConstant {
			return fmt.Sprintf("%s[%d]", DescribeType(t.Element), length.Value)
		}
		return DescribeType(t.Element) + "[...]"
	case *Pointer:
		if t.Width == nil {
			return DescribeType(t.Target) + "*"
		}
		return fmt.Sprintf("%s* : %s", DescribeType(t.Target), DescribeType(t.Width))
	}
	panic("unreachable")
}

func Unalias(t Type) Type {
	for {
		alias, isAlias := t.(*Alias)
		if !isAlias {
			return t
		}
		t = alias.Target
	}
}

type Value interface {
	valueNode()
}

type Constant struct {
	Value    int64
	Wide     *big.Int
	Unsigned bool
	Char     bool
}

type Labelled struct {
	Enum  *Enum
	Value Value
}

type TemplateArgument struct {
	Value Value
}

type PatternTypeName struct {
	Target Value
}

type StringConstant struct {
	Value string
}

type FloatConstant struct {
	Value float64
}

type Cast struct {
	Kind         PrimitiveKind
	Order        ByteOrder
	DefaultOrder ByteOrder
	Operand      Value
}

type FunctionCall struct {
	Function  *Function
	Arguments []Value
}

type FieldRef struct {
	Path []*Field
}

type BitRef struct {
	Member *BitfieldMember
}

type Index struct {
	Object Value
	Index  Value
}

type ArrayValue struct {
	Elements []Value
}

type MemberOf struct {
	Object Value
	Name   string
	Field  *Field
}

type ParentFieldRef struct {
	Depth int
	Path  []string
}

type ThisRef struct {
	Depth int
}

type LocalRef struct {
	Local *Local
}

type GlobalRef struct {
	Path     []string
	Position Position
	Field    *Field
	Local    *Local
	Rest     []string
	Deferred bool
}

type Cursor struct{}

type AddressOf struct {
	Target Value
}

type SizeOfValue struct {
	Target Value
}

type Builtin struct {
	Name      string
	Arguments []Value
}

type EnumMemberRef struct {
	Enum   *Enum
	Member *EnumMember
}

type SizeOf struct {
	Type Type
}

type UnaryOp struct {
	Operator string
	Operand  Value
}

type BinaryOp struct {
	Operator string
	Left     Value
	Right    Value
}

type Select struct {
	Condition Value
	Then      Value
	Else      Value
}

func (*Constant) valueNode()         {}
func (*StringConstant) valueNode()   {}
func (*FloatConstant) valueNode()    {}
func (*Cast) valueNode()             {}
func (*FunctionCall) valueNode()     {}
func (*FieldRef) valueNode()         {}
func (*BitRef) valueNode()           {}
func (*Index) valueNode()            {}
func (*ArrayValue) valueNode()       {}
func (*MemberOf) valueNode()         {}
func (*ParentFieldRef) valueNode()   {}
func (*EnumMemberRef) valueNode()    {}
func (*SizeOf) valueNode()           {}
func (*UnaryOp) valueNode()          {}
func (*BinaryOp) valueNode()         {}
func (*Select) valueNode()           {}
func (*ThisRef) valueNode()          {}
func (*LocalRef) valueNode()         {}
func (*GlobalRef) valueNode()        {}
func (*Cursor) valueNode()           {}
func (*AddressOf) valueNode()        {}
func (*SizeOfValue) valueNode()      {}
func (*Builtin) valueNode()          {}
func (*Labelled) valueNode()         {}
func (*TemplateArgument) valueNode() {}
func (*PatternTypeName) valueNode()  {}

package patterns

import "math/big"

type File struct {
	Path           string
	Pragmas        []Pragma
	Includes       []Include
	Imports        []Import
	AutoNamespaces []string
	Declarations   []Declaration
	Body           []Member
}

type Pragma struct {
	Name     string
	Value    string
	Position Position
}

type Include struct {
	Path     string
	Position Position
	macros   macros
}

type Import struct {
	Path     string
	Alias    string
	AsType   bool
	Position Position
	macros   macros
}

type Declaration interface {
	declaredName() string
}

type StructDecl struct {
	Name       string
	Scope      string
	Global     bool
	Params     []TypeParamDecl
	Base       *TypeRef
	Members    []Member
	Attributes []Attribute
	Doc        string
	Position   Position
}

type UnionDecl struct {
	Name       string
	Scope      string
	Params     []TypeParamDecl
	Members    []Member
	Attributes []Attribute
	Doc        string
	Position   Position
}

type TypeParamDecl struct {
	Name string
	Auto bool
}

type ConditionalDecl struct {
	Condition Expr
	Then      []Member
	Else      []Member
	Position  Position
}

type MatchDecl struct {
	Cases    []MatchCaseDecl
	Default  []Member
	Position Position
}

type MatchCaseDecl struct {
	Condition Expr
	Body      []Member
	Position  Position
}

type EnumDecl struct {
	Name       string
	Scope      string
	Underlying TypeRef
	Members    []EnumMemberDecl
	Attributes []Attribute
	Doc        string
	Position   Position
}

type EnumMemberDecl struct {
	Name     string
	Value    Expr
	Last     Expr
	Doc      string
	Position Position
}

type BitfieldDecl struct {
	Name       string
	Scope      string
	Params     []TypeParamDecl
	Members    []Member
	Attributes []Attribute
	Doc        string
	Position   Position
}

type FunctionDecl struct {
	Name     string
	Scope    string
	Params   []ParamDecl
	Body     []Member
	Doc      string
	Position Position
}

type ParamDecl struct {
	Name     string
	Type     *TypeRef
	Ref      bool
	Variadic bool
	Default  Expr
	Position Position
}

type UsingDecl struct {
	Name       string
	Scope      string
	Params     []TypeParamDecl
	Target     *TypeRef
	Attributes []Attribute
	Doc        string
	Position   Position
}

func (d *StructDecl) declaredName() string   { return d.Name }
func (d *UnionDecl) declaredName() string    { return d.Name }
func (d *EnumDecl) declaredName() string     { return d.Name }
func (d *BitfieldDecl) declaredName() string { return d.Name }
func (d *UsingDecl) declaredName() string    { return d.Name }
func (d *FunctionDecl) declaredName() string { return d.Name }

func scopeOf(decl Declaration) string {
	switch d := decl.(type) {
	case *StructDecl:
		return d.Scope
	case *UnionDecl:
		return d.Scope
	case *EnumDecl:
		return d.Scope
	case *BitfieldDecl:
		return d.Scope
	case *UsingDecl:
		return d.Scope
	case *FunctionDecl:
		return d.Scope
	}
	return ""
}

func renamedDeclaration(decl Declaration, name string, scope string) Declaration {
	switch d := decl.(type) {
	case *StructDecl:
		renamed := *d
		renamed.Name, renamed.Scope = name, scope
		return &renamed
	case *UnionDecl:
		renamed := *d
		renamed.Name, renamed.Scope = name, scope
		return &renamed
	case *EnumDecl:
		renamed := *d
		renamed.Name, renamed.Scope = name, scope
		return &renamed
	case *BitfieldDecl:
		renamed := *d
		renamed.Name, renamed.Scope = name, scope
		return &renamed
	case *UsingDecl:
		renamed := *d
		renamed.Name, renamed.Scope = name, scope
		return &renamed
	case *FunctionDecl:
		renamed := *d
		renamed.Name, renamed.Scope = name, scope
		return &renamed
	}
	return decl
}

type MemberKind int

const (
	FieldMember MemberKind = iota
	PaddingMember
	BitMember
	ConditionalMember
	MatchMember
	LocalMember
	AssignmentMember
	ReturnMember
	WhileMember
	ForMember
	BreakMember
	ContinueMember
	TryMember
	CallMember
)

type Member struct {
	Kind         MemberKind
	Name         string
	Type         TypeRef
	Pointer      bool
	PointerWidth *TypeRef
	Array        bool
	Length       Expr
	While        Expr
	Address      Expr
	Section      Expr
	Initializer  Expr
	Assignment   *AssignmentDecl
	Setting      string
	Const        bool
	Bits         Expr
	Signed       bool
	Attributes   []Attribute
	Doc          string
	Conditional  *ConditionalDecl
	Match        *MatchDecl
	Loop         *LoopDecl
	Try          *TryDecl
	Value        Expr
	Scope        string
	Position     Position
}

func walkMembers(members []Member, visit func(*Member)) {
	for i := range members {
		member := &members[i]
		visit(member)
		if member.Conditional != nil {
			walkMembers(member.Conditional.Then, visit)
			walkMembers(member.Conditional.Else, visit)
		}
		if member.Match != nil {
			for _, matchCase := range member.Match.Cases {
				walkMembers(matchCase.Body, visit)
			}
			walkMembers(member.Match.Default, visit)
		}
		if member.Loop != nil {
			walkMembers(member.Loop.Init, visit)
			walkMembers(member.Loop.Step, visit)
			walkMembers(member.Loop.Body, visit)
		}
		if member.Try != nil {
			walkMembers(member.Try.Body, visit)
			walkMembers(member.Try.Catch, visit)
		}
	}
}

func rescopedMembers(members []Member, rescope func(string) string) []Member {
	rescoped := make([]Member, len(members))
	for i, member := range members {
		member.Scope = rescope(member.Scope)
		if member.Conditional != nil {
			conditional := *member.Conditional
			conditional.Then = rescopedMembers(conditional.Then, rescope)
			conditional.Else = rescopedMembers(conditional.Else, rescope)
			member.Conditional = &conditional
		}
		if member.Match != nil {
			match := *member.Match
			match.Cases = make([]MatchCaseDecl, len(member.Match.Cases))
			for i, matchCase := range member.Match.Cases {
				matchCase.Body = rescopedMembers(matchCase.Body, rescope)
				match.Cases[i] = matchCase
			}
			match.Default = rescopedMembers(match.Default, rescope)
			member.Match = &match
		}
		if member.Loop != nil {
			loop := *member.Loop
			loop.Init = rescopedMembers(loop.Init, rescope)
			loop.Step = rescopedMembers(loop.Step, rescope)
			loop.Body = rescopedMembers(loop.Body, rescope)
			member.Loop = &loop
		}
		if member.Try != nil {
			try := *member.Try
			try.Body = rescopedMembers(try.Body, rescope)
			try.Catch = rescopedMembers(try.Catch, rescope)
			member.Try = &try
		}
		rescoped[i] = member
	}
	return rescoped
}

type LoopDecl struct {
	Init      []Member
	Condition Expr
	Step      []Member
	Body      []Member
}

type TryDecl struct {
	Body  []Member
	Catch []Member
}

type AssignmentDecl struct {
	Target   Expr
	Operator string
	Value    Expr
}

type EndianSpec int

const (
	EndianUnspecified EndianSpec = iota
	EndianLittle
	EndianBig
)

type TypeRef struct {
	Name     string
	Endian   EndianSpec
	Args     []TypeArg
	Position Position
}

type TypeArg struct {
	Type *TypeRef
	Expr Expr
}

type Attribute struct {
	Name      string
	Arguments []Expr
	Position  Position
}

type Expr interface {
	exprPosition() Position
}

type IntegerLiteral struct {
	Value    uint64
	Wide     *big.Int
	Unsigned bool
	Char     bool
	Position Position
}

type FloatLiteral struct {
	Text     string
	Position Position
}

type StringLiteral struct {
	Value    string
	Position Position
}

type BoolLiteral struct {
	Value    bool
	Position Position
}

type Identifier struct {
	Name     string
	Position Position
}

type ScopedIdentifier struct {
	Scope    string
	Name     string
	Position Position
}

type MemberAccess struct {
	Object   Expr
	Name     string
	Position Position
}

type IndexExpr struct {
	Object   Expr
	Index    Expr
	Position Position
}

type ArrayLiteral struct {
	Elements []Expr
	Position Position
}

type ParentRef struct {
	Depth    int
	Name     string
	Position Position
}

type ThisExpr struct {
	Position Position
}

type Dollar struct {
	Position Position
}

type Call struct {
	Name      string
	Arguments []Expr
	TypeArg   *TypeRef
	Order     ByteOrder
	Position  Position
}

type Unary struct {
	Operator string
	Operand  Expr
	Position Position
}

type Binary struct {
	Operator string
	Left     Expr
	Right    Expr
	Position Position
}

type Ternary struct {
	Condition Expr
	Then      Expr
	Else      Expr
	Position  Position
}

func (e *IntegerLiteral) exprPosition() Position   { return e.Position }
func (e *FloatLiteral) exprPosition() Position     { return e.Position }
func (e *StringLiteral) exprPosition() Position    { return e.Position }
func (e *BoolLiteral) exprPosition() Position      { return e.Position }
func (e *Identifier) exprPosition() Position       { return e.Position }
func (e *ScopedIdentifier) exprPosition() Position { return e.Position }
func (e *MemberAccess) exprPosition() Position     { return e.Position }
func (e *IndexExpr) exprPosition() Position        { return e.Position }
func (e *ArrayLiteral) exprPosition() Position     { return e.Position }
func (e *ParentRef) exprPosition() Position        { return e.Position }
func (e *ThisExpr) exprPosition() Position         { return e.Position }
func (e *Dollar) exprPosition() Position           { return e.Position }
func (e *Call) exprPosition() Position             { return e.Position }
func (e *Unary) exprPosition() Position            { return e.Position }
func (e *Binary) exprPosition() Position           { return e.Position }
func (e *Ternary) exprPosition() Position          { return e.Position }

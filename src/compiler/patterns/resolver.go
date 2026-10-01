package patterns

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func analyze(units []*unit) (*Module, []Diagnostic) {
	r := &resolver{
		module:    &Module{},
		shells:    map[string]NamedType{},
		functions: map[string]*Function{},
		templates: map[string]Declaration{},
		decls:     map[string]Declaration{},
		units:     map[Declaration]*unit{},
	}
	var declarations []Declaration
	for _, u := range units {
		if u.file.Path != "" {
			r.module.Files = append(r.module.Files, u.file.Path)
		}
		for _, decl := range u.file.Declarations {
			r.units[decl] = u
			declarations = append(declarations, decl)
		}
	}
	r.declareTypes(declarations)
	r.defineTypes(declarations)
	r.defineRoot(units[len(units)-1])
	r.bindGlobals()
	if len(r.diagnostics) > 0 {
		return nil, r.diagnostics
	}
	r.module.Warnings = r.warnings
	if diagnostics := classifyStructs(r.module); len(diagnostics) > 0 {
		return nil, diagnostics
	}
	diagnostics := r.module.validate()
	if len(diagnostics) > 0 {
		return nil, diagnostics
	}
	return r.module, nil
}

type resolver struct {
	module         *Module
	shells         map[string]NamedType
	functions      map[string]*Function
	templates      map[string]Declaration
	decls          map[string]Declaration
	units          map[Declaration]*unit
	scope          string
	order          ByteOrder
	subst          *substitution
	instantiations int
	globals        []*GlobalRef
	rootScope      *fieldScope
	globalScopes   []*fieldScope
	pendingAliases []pendingAlias
	definingTypes  bool
	deferring      int
	deferred       []Diagnostic
	warnings       []Diagnostic
	diagnostics    []Diagnostic
}

type pendingAlias struct {
	decl  *UsingDecl
	alias *Alias
}

type substitution struct {
	types   map[string]Type
	values  map[string]Value
	namings map[string][]NamePart
	outer   *substitution
}

func (s *substitution) lookupType(name string) (Type, bool) {
	for current := s; current != nil; current = current.outer {
		if t, isBound := current.types[name]; isBound {
			return t, true
		}
	}
	return nil, false
}

func (s *substitution) lookupNaming(name string) ([]NamePart, bool) {
	for current := s; current != nil; current = current.outer {
		if naming, isBound := current.namings[name]; isBound {
			return naming, true
		}
	}
	return nil, false
}

func (s *substitution) lookupValue(name string) (Value, bool) {
	for current := s; current != nil; current = current.outer {
		if v, isBound := current.values[name]; isBound {
			return v, true
		}
	}
	return nil, false
}

func (r *resolver) declareTypes(declarations []Declaration) {
	for _, decl := range declarations {
		name := decl.declaredName()
		if name == "" {
			continue
		}
		if _, isPrimitive := primitiveKindsByName[name]; isPrimitive {
			r.report(declarationPosition(decl), fmt.Sprintf("%s is a built-in type", name))
			continue
		}
		if using, isUsing := decl.(*UsingDecl); isUsing && using.Target == nil {
			continue
		}
		if function, isFunction := decl.(*FunctionDecl); isFunction {
			if existing, exists := r.functions[name]; exists {
				r.report(function.Position, fmt.Sprintf("%s is already declared at %s", name, describePosition(existing.Position)))
				continue
			}
			r.functions[name] = &Function{Name: name, Doc: function.Doc, Position: function.Position}
			r.module.Functions = append(r.module.Functions, r.functions[name])
			continue
		}
		if existing, exists := r.decls[name]; exists {
			r.report(declarationPosition(decl), fmt.Sprintf("%s is already declared at %s", name, describePosition(declarationPosition(existing))))
			continue
		}
		r.decls[name] = decl
		if params := templateParams(decl); len(params) > 0 {
			if duplicate := duplicateParam(params); duplicate != "" {
				r.report(declarationPosition(decl), fmt.Sprintf("template parameter %s is declared twice", duplicate))
				continue
			}
			r.templates[name] = decl
			continue
		}
		shell := r.makeShell(decl)
		r.shells[name] = shell
		r.module.Types = append(r.module.Types, shell)
	}
}

func describePosition(position Position) string {
	if position.Path != "" {
		return fmt.Sprintf("%s:%d", position.Path, position.Line+1)
	}
	return fmt.Sprintf("line %d", position.Line+1)
}

func (r *resolver) makeShell(decl Declaration) NamedType {
	u := r.units[decl]
	switch d := decl.(type) {
	case *StructDecl:
		return &Struct{Name: d.Name, Doc: d.Doc, ABI: u.abi, Global: d.Global, Position: d.Position}
	case *UnionDecl:
		return &Union{Name: d.Name, Doc: d.Doc, ABI: u.abi, Position: d.Position}
	case *EnumDecl:
		return &Enum{Name: d.Name, Doc: d.Doc, Position: d.Position}
	case *BitfieldDecl:
		return &Bitfield{Name: d.Name, Doc: d.Doc, Order: u.order, Position: d.Position}
	case *UsingDecl:
		return &Alias{Name: d.Name, Doc: d.Doc, Position: d.Position}
	}
	panic("unreachable")
}

func (r *resolver) defineTypes(declarations []Declaration) {
	r.definingTypes = true
	r.defineDeclarations(declarations)
	r.definingTypes = false
	for _, pending := range r.pendingAliases {
		r.enter(pending.decl)
		pending.alias.Attributes = r.resolveTypeAttributes(pending.decl.Attributes, memberScope(pending.alias.Target))
	}
	r.pendingAliases = nil
}

func (r *resolver) defineDeclarations(declarations []Declaration) {
	for _, decl := range declarations {
		if function, isFunction := decl.(*FunctionDecl); isFunction && r.owns(function) {
			r.enter(decl)
			r.declareParams(function, r.functions[function.Name])
		}
	}
	for _, decl := range declarations {
		if using, isUsing := decl.(*UsingDecl); isUsing && using.Target == nil {
			continue
		}
		if function, isFunction := decl.(*FunctionDecl); isFunction {
			if r.owns(function) {
				r.enter(decl)
				r.defineFunction(function, r.functions[function.Name])
			}
			continue
		}
		if r.decls[decl.declaredName()] != decl || len(templateParams(decl)) > 0 {
			continue
		}
		r.enter(decl)
		switch d := decl.(type) {
		case *StructDecl:
			r.defineStruct(d, r.shells[d.Name].(*Struct))
		case *UnionDecl:
			r.defineUnion(d, r.shells[d.Name].(*Union))
		case *EnumDecl:
			r.defineEnum(d, r.shells[d.Name].(*Enum))
		case *BitfieldDecl:
			r.defineBitfield(d, r.shells[d.Name].(*Bitfield))
		case *UsingDecl:
			r.defineAlias(d, r.shells[d.Name].(*Alias))
		}
	}
}

func (r *resolver) owns(function *FunctionDecl) bool {
	return r.functions[function.Name].Position == function.Position
}

func (r *resolver) enter(decl Declaration) {
	r.scope = scopeOf(decl)
	r.order = r.units[decl].order
}

func duplicateParam(params []TypeParamDecl) string {
	seen := map[string]bool{}
	for _, param := range params {
		if seen[param.Name] {
			return param.Name
		}
		seen[param.Name] = true
	}
	return ""
}

func templateParams(decl Declaration) []TypeParamDecl {
	switch d := decl.(type) {
	case *StructDecl:
		return d.Params
	case *UnionDecl:
		return d.Params
	case *BitfieldDecl:
		return d.Params
	case *UsingDecl:
		return d.Params
	}
	return nil
}

func (r *resolver) defineStruct(decl *StructDecl, t *Struct) {
	scope := &fieldScope{locals: map[string]*Local{}, global: t.Global}
	if t.Global {
		r.globalScopes = append(r.globalScopes, scope)
	}
	for _, param := range t.Params {
		scope.locals[param.Name] = param
	}
	if decl.Base != nil {
		base, isStruct := r.resolveTypeRef(*decl.Base).(*Struct)
		if !isStruct {
			r.report(decl.Position, fmt.Sprintf("%s is not a struct", decl.Base.Name))
		} else {
			t.Base = base
			scope.fields = append(scope.fields, allFields(base)...)
			for _, local := range structLocals(base) {
				scope.locals[local.Name] = local
			}
		}
	}
	t.Body = r.resolveStatements(decl.Members, scope)
	t.Fields = flattenFields(t.Body, nil)
	t.Attributes = r.resolveTypeAttributes(decl.Attributes, scope)
}

func structLocals(t *Struct) []*Local {
	var locals []*Local
	for _, statement := range structBody(t) {
		if local, isLocal := statement.(*Local); isLocal {
			locals = append(locals, local)
		}
	}
	return locals
}

func (r *resolver) instantiate(ref TypeRef, scope *fieldScope) Type {
	decl, isTemplate := r.lookupTemplate(ref.Name)
	if !isTemplate {
		if len(ref.Args) > 0 {
			r.report(ref.Position, fmt.Sprintf("%s is not a template", ref.Name))
			return nil
		}
		return r.lookupType(ref.Name, ref.Position)
	}
	params := templateParams(decl)
	if len(ref.Args) != len(params) {
		r.report(ref.Position, fmt.Sprintf("%s takes %d template arguments", ref.Name, len(params)))
		return nil
	}

	subst := &substitution{types: map[string]Type{}, values: map[string]Value{}, namings: map[string][]NamePart{}, outer: r.subst}
	keys := make([]string, len(params))
	naming := []NamePart{{Text: decl.declaredName() + "<"}}
	var locals []*Local
	var args []Value
	for i, param := range params {
		if i > 0 {
			naming = append(naming, NamePart{Text: ", "})
		}
		arg := ref.Args[i]
		if !param.Auto {
			if arg.Type == nil {
				r.report(ref.Position, fmt.Sprintf("%s expects a type for %s", ref.Name, param.Name))
				return nil
			}
			t := r.resolveTypeRefIn(*arg.Type, scope)
			if t == nil {
				return nil
			}
			subst.types[param.Name] = t
			keys[i] = DescribeType(t)
			var captured []NamePart
			for _, piece := range r.namePieces(t, *arg.Type) {
				if piece.value == nil {
					captured = append(captured, NamePart{Text: piece.text})
					continue
				}
				hidden := &Local{Name: fmt.Sprintf("$typeArgument%d", len(locals))}
				locals = append(locals, hidden)
				args = append(args, piece.value)
				captured = append(captured, NamePart{Param: hidden})
			}
			subst.namings[param.Name] = captured
			naming = append(naming, captured...)
			continue
		}
		if arg.Expr == nil || r.namesType(arg.Expr, scope) {
			t := r.resolveTypeRefIn(*arg.Type, scope)
			if t == nil {
				return nil
			}
			subst.values[param.Name] = &StringConstant{Value: DescribeType(t)}
			keys[i] = DescribeType(t)
			naming = append(naming, NamePart{Text: keys[i]})
			continue
		}
		v := r.resolveValue(arg.Expr, scope)
		if v == nil {
			return nil
		}
		switch constant := v.(type) {
		case *Constant:
			subst.values[param.Name] = constant
			keys[i] = fmt.Sprintf("%d", constant.Value)
			naming = append(naming, NamePart{Text: keys[i]})
			continue
		case *StringConstant:
			subst.values[param.Name] = constant
			keys[i] = templateStringText(constant.Value)
			naming = append(naming, NamePart{Text: keys[i]})
			continue
		}
		keys[i] = "?" + valueKey(v)
		if _, isAlias := decl.(*UsingDecl); isAlias {
			subst.values[param.Name] = v
			naming = append(naming, NamePart{Text: keys[i]})
			continue
		}
		local := &Local{Name: param.Name}
		subst.values[param.Name] = &LocalRef{Local: local}
		locals = append(locals, local)
		args = append(args, v)
		naming = append(naming, NamePart{Param: local})
	}
	naming = append(naming, NamePart{Text: ">"})

	name := decl.declaredName() + "<" + strings.Join(keys, ", ") + ">"
	if existing, cached := r.shells[name]; cached {
		return existing
	}

	saved := *r
	r.enter(decl)
	r.subst = subst
	defer func() { r.scope, r.order, r.subst = saved.scope, saved.order, saved.subst }()

	var instance NamedType
	switch d := decl.(type) {
	case *StructDecl:
		t := &Struct{Name: name, Doc: d.Doc, ABI: r.units[decl].abi, Params: locals, Args: args, Naming: dynamicNaming(naming), Position: d.Position}
		instance = t
		r.shells[name] = t
		r.module.Types = append(r.module.Types, t)
		r.defineStruct(d, t)
	case *UnionDecl:
		t := &Union{Name: name, Doc: d.Doc, ABI: r.units[decl].abi, Params: locals, Args: args, Naming: dynamicNaming(naming), Position: d.Position}
		instance = t
		r.shells[name] = t
		r.module.Types = append(r.module.Types, t)
		r.defineUnion(d, t)
	case *UsingDecl:
		t := &Alias{Name: name, Doc: d.Doc, Position: d.Position}
		instance = t
		r.shells[name] = t
		r.module.Types = append(r.module.Types, t)
		r.defineAlias(d, t)
	case *BitfieldDecl:
		t := &Bitfield{Name: name, Doc: d.Doc, Order: r.units[decl].order, Params: locals, Args: args, Position: d.Position}
		instance = t
		r.shells[name] = t
		r.module.Types = append(r.module.Types, t)
		r.defineBitfield(d, t)
	}
	return instance
}

func valueKey(v Value) string {
	switch v := v.(type) {
	case *Constant:
		if v.Wide != nil {
			return v.Wide.String()
		}
		return fmt.Sprintf("%d", v.Value)
	case *StringConstant:
		return strconv.Quote(v.Value)
	case *FloatConstant:
		return fmt.Sprintf("%g", v.Value)
	case *LocalRef:
		return "local " + v.Local.Name
	case *FieldRef:
		return "field " + fieldPathKey(v.Path)
	case *ParentFieldRef:
		return fmt.Sprintf("parent%d %s", v.Depth, strings.Join(v.Path, "."))
	case *GlobalRef:
		return "global " + strings.Join(v.Path, ".")
	case *ThisRef:
		return fmt.Sprintf("this%d", v.Depth)
	case *BitRef:
		return "bit " + v.Member.Name
	case *EnumMemberRef:
		return v.Enum.Name + "::" + v.Member.Name
	case *Cursor:
		return "$"
	case *SizeOf:
		return "sizeof " + DescribeType(v.Type)
	case *SizeOfValue:
		return "sizeof(" + valueKey(v.Target) + ")"
	case *AddressOf:
		return "addressof(" + valueKey(v.Target) + ")"
	case *MemberOf:
		return valueKey(v.Object) + "." + v.Name
	case *Index:
		return valueKey(v.Object) + "[" + valueKey(v.Index) + "]"
	case *Cast:
		return v.Kind.Name() + "(" + valueKey(v.Operand) + ")"
	case *UnaryOp:
		return v.Operator + valueKey(v.Operand)
	case *BinaryOp:
		return "(" + valueKey(v.Left) + " " + v.Operator + " " + valueKey(v.Right) + ")"
	case *Select:
		return "(" + valueKey(v.Condition) + " ? " + valueKey(v.Then) + " : " + valueKey(v.Else) + ")"
	case *Builtin:
		return v.Name + "(" + valueKeys(v.Arguments) + ")"
	case *FunctionCall:
		return v.Function.Name + "(" + valueKeys(v.Arguments) + ")"
	case *ArrayValue:
		return "{" + valueKeys(v.Elements) + "}"
	case *Labelled:
		return valueKey(v.Value)
	case *TemplateArgument:
		return "template(" + valueKey(v.Value) + ")"
	case *PatternTypeName:
		return "typenameof(" + valueKey(v.Target) + ")"
	}
	panic("unreachable")
}

func valueKeys(values []Value) string {
	keys := make([]string, len(values))
	for i, v := range values {
		keys[i] = valueKey(v)
	}
	return strings.Join(keys, ", ")
}

func fieldPathKey(path []*Field) string {
	names := make([]string, len(path))
	for i, field := range path {
		names[i] = field.Name
	}
	return strings.Join(names, ".")
}

func (r *resolver) namesType(e Expr, scope *fieldScope) bool {
	identifier, isIdentifier := e.(*Identifier)
	if !isIdentifier {
		return false
	}
	if _, isParam := r.subst.lookupValue(identifier.Name); isParam {
		return false
	}
	if scope != nil {
		if _, isLocal := scope.locals[identifier.Name]; isLocal || scope.lookup(identifier.Name) != nil {
			return false
		}
	}
	return r.findType(identifier.Name) != nil
}

func (r *resolver) lookupTemplate(name string) (Declaration, bool) {
	scope := r.scope
	for {
		qualified := name
		if scope != "" {
			qualified = scope + "::" + name
		}
		if decl, isTemplate := r.templates[qualified]; isTemplate {
			return decl, true
		}
		if scope == "" {
			return nil, false
		}
		separator := strings.LastIndex(scope, "::")
		if separator == -1 {
			scope = ""
		} else {
			scope = scope[:separator]
		}
	}
}

func (r *resolver) declareParams(decl *FunctionDecl, f *Function) {
	names := map[string]bool{}
	for _, param := range decl.Params {
		if param.Name != "" && names[param.Name] {
			r.report(param.Position, fmt.Sprintf("%s is already declared", param.Name))
		}
		names[param.Name] = true
		local := &Local{Name: param.Name, Ref: param.Ref, Pack: param.Variadic}
		f.Variadic = f.Variadic || param.Variadic
		if param.Type != nil && !isDynamicTypeName(param.Type.Name) {
			local.Type = r.resolveTypeRef(*param.Type)
		}
		var fallback Value
		if param.Default != nil {
			fallback = r.resolveValue(param.Default, nil)
		}
		f.Params = append(f.Params, local)
		f.Defaults = append(f.Defaults, fallback)
	}
}

func (r *resolver) defineFunction(decl *FunctionDecl, f *Function) {
	scope := &fieldScope{locals: map[string]*Local{}, function: true}
	for _, param := range f.Params {
		scope.locals[param.Name] = param
		scope.declare(param.Name)
	}
	f.Body = r.resolveStatements(decl.Body, scope)
}

func (r *resolver) defineRoot(main *unit) {
	if len(main.file.Body) == 0 {
		return
	}
	r.scope = ""
	r.order = main.order
	root := &Struct{Name: rootTypeName(main.file.Path), ABI: main.abi, Global: true}
	if _, taken := r.shells[root.Name]; taken {
		root.Name += "Root"
	}
	scope := &fieldScope{locals: map[string]*Local{}, global: true}
	root.Body = r.resolveStatements(main.file.Body, scope)
	root.Fields = flattenFields(root.Body, nil)
	r.rootScope = scope
	r.globalScopes = append([]*fieldScope{scope}, r.globalScopes...)
	r.module.Types = append(r.module.Types, root)
	r.module.Root = root
}

func (r *resolver) bindGlobals() {
	for _, ref := range r.globals {
		if !r.bindGlobal(ref) && !ref.Deferred {
			r.warn(ref.Position, fmt.Sprintf("unknown identifier %s", strings.Join(ref.Path, ".")))
		}
	}
}

func (r *resolver) bindGlobal(ref *GlobalRef) bool {
	for _, scope := range r.globalScopes {
		if local, isLocal := scope.locals[ref.Path[0]]; isLocal {
			ref.Local = local
			ref.Rest = ref.Path[1:]
			return true
		}
		if field := scope.lookup(ref.Path[0]); field != nil {
			ref.Field = field
			ref.Rest = ref.Path[1:]
			return true
		}
	}
	return false
}

func rootTypeName(path string) string {
	base := path[strings.LastIndexAny(path, "/\\")+1:]
	if dot := strings.IndexByte(base, '.'); dot != -1 {
		base = base[:dot]
	}
	var name strings.Builder
	upper := true
	for _, c := range base {
		if !isIdentifierPart(byte(c)) || c > 127 {
			upper = true
			continue
		}
		if upper {
			name.WriteString(strings.ToUpper(string(c)))
			upper = false
		} else {
			name.WriteRune(c)
		}
	}
	if name.Len() == 0 || isDigit(name.String()[0]) {
		return "Root"
	}
	return name.String()
}

func (r *resolver) resolveStatements(members []Member, scope *fieldScope) []Statement {
	var statements []Statement
	for i := range members {
		member := &members[i]
		if scope.global {
			r.scope = member.Scope
		}
		deferredBefore, statementsBefore := len(r.deferred), len(statements)
		r.deferring++
		statements = r.resolveStatement(member, scope, statements)
		r.deferring--
		if len(r.deferred) > deferredBefore {
			statements = append(statements[:statementsBefore], r.failureSince(deferredBefore))
		}
	}
	return statements
}

func (r *resolver) resolveStatement(member *Member, scope *fieldScope, statements []Statement) []Statement {
	switch member.Kind {
	case ConditionalMember:
		if conditional := r.resolveConditional(member.Conditional, scope); conditional != nil {
			statements = append(statements, conditional)
		}
	case MatchMember:
		if match := r.resolveMatch(member.Match, scope); match != nil {
			statements = append(statements, match)
		}
	case LocalMember:
		if local := r.resolveLocal(member, scope); local != nil {
			statements = append(statements, local)
		}
	case AssignmentMember:
		if assignment := r.resolveAssignment(member, scope); assignment != nil {
			statements = append(statements, assignment)
		}
	case ReturnMember:
		statement := &Return{}
		if member.Value != nil {
			statement.Value = r.resolveValue(member.Value, scope)
			if statement.Value == nil {
				return statements
			}
		}
		statements = append(statements, statement)
	case WhileMember, ForMember:
		if loop := r.resolveLoop(member.Loop, scope); loop != nil {
			statements = append(statements, loop)
		}
	case BreakMember, ContinueMember:
		keyword := "break"
		if member.Kind == ContinueMember {
			keyword = "continue"
		}
		if scope.loops == 0 && (scope.function || scope.global) {
			r.report(member.Position, fmt.Sprintf("%s is only allowed inside a loop", keyword))
			return statements
		}
		if member.Kind == BreakMember {
			statements = append(statements, &Break{})
		} else {
			statements = append(statements, &Continue{})
		}
	case TryMember:
		scope.tries++
		body := r.resolveBlock(member.Try.Body, scope)
		scope.tries--
		statements = append(statements, &Try{Body: body, Catch: r.resolveBlock(member.Try.Catch, scope)})
	case CallMember:
		if value := r.resolveValue(member.Value, scope); value != nil {
			statements = append(statements, &Evaluation{Value: value})
		}
	case BitMember:
		if bit := r.resolveBitMember(member, scope); bit != nil {
			statements = append(statements, bit)
			if bit.Name != "" {
				scope.bits[bit.Name] = bit
			}
		}
	default:
		if member.Kind == FieldMember && member.Address == nil && (scope.global || scope.function || isDynamicTypeName(member.Type.Name)) {
			if local := r.resolveGlobalVariable(member, scope); local != nil {
				statements = append(statements, local)
			}
			return statements
		}
		if field := r.resolveMember(member, scope); field != nil {
			statements = append(statements, field)
			scope.fields = append(scope.fields, field)
		}
	}
	return statements
}

func (r *resolver) failureSince(index int) *Failure {
	failure := &Failure{Message: r.deferred[index].Message}
	r.warnings = append(r.warnings, r.deferred[index:]...)
	r.deferred = r.deferred[:index]
	return failure
}

func (r *resolver) resolveGlobalVariable(member *Member, scope *fieldScope) *Local {
	t := r.resolveLocalType(member, scope)
	if t == nil && !isDynamicTypeName(member.Type.Name) {
		return nil
	}
	local := &Local{Name: member.Name, Type: t, Init: defaultValue(t), Global: scope.global}
	if member.Type.Name == "str" {
		local.Init = &StringConstant{}
		if member.Array && member.Length != nil {
			local.StringCount = r.resolveValue(member.Length, scope)
		}
	}
	if !r.declareName(member.Name, member.Position, scope) {
		return nil
	}
	scope.locals[member.Name] = local
	return local
}

func defaultValue(t Type) Value {
	if t == nil {
		return &Constant{}
	}
	if isCharacter(t) {
		return &StringConstant{}
	}
	if array, isArray := Unalias(t).(*Array); isArray && isCharacter(array.Element) {
		return &StringConstant{}
	}
	return &Constant{}
}

func (r *resolver) resolveConditional(decl *ConditionalDecl, scope *fieldScope) *Conditional {
	condition := r.resolveValue(decl.Condition, scope)
	if condition == nil {
		return nil
	}
	scope.branches++
	defer func() { scope.branches-- }()
	conditional := &Conditional{Condition: condition}
	live, isKnown := condition.(*Constant)
	if !isKnown || live.Value != 0 {
		conditional.Then = r.resolveBlock(decl.Then, scope)
	}
	if len(decl.Else) > 0 && (!isKnown || live.Value == 0) {
		conditional.Else = r.resolveBlock(decl.Else, scope)
	}
	return conditional
}

func (r *resolver) resolveMatch(decl *MatchDecl, scope *fieldScope) *Match {
	match := &Match{Cases: make([]MatchCase, len(decl.Cases))}
	for i, matchCase := range decl.Cases {
		condition := r.resolveValue(matchCase.Condition, scope)
		if condition == nil {
			return nil
		}
		match.Cases[i].Condition = condition
	}
	scope.branches++
	defer func() { scope.branches-- }()
	for i, matchCase := range decl.Cases {
		match.Cases[i].Then = r.resolveBlock(matchCase.Body, scope)
	}
	match.Default = r.resolveBlock(decl.Default, scope)
	return match
}

func (r *resolver) resolveLoop(decl *LoopDecl, scope *fieldScope) *Loop {
	scope.blocks = append(scope.blocks, map[string]bool{})
	defer func() { scope.blocks = scope.blocks[:len(scope.blocks)-1] }()
	loop := &Loop{Init: r.resolveStatements(decl.Init, scope)}
	loop.Condition = r.resolveValue(decl.Condition, scope)
	if loop.Condition == nil {
		return nil
	}
	scope.loops++
	defer func() { scope.loops-- }()
	loop.Step = r.resolveStatements(decl.Step, scope)
	loop.Body = r.resolveStatements(decl.Body, scope)
	return loop
}

func isDynamicTypeName(name string) bool {
	return name == "auto" || name == "str"
}

func (r *resolver) resolveLocalType(member *Member, scope *fieldScope) Type {
	if isDynamicTypeName(member.Type.Name) {
		return nil
	}
	t := r.resolveTypeRefIn(member.Type, scope)
	if t == nil {
		return nil
	}
	if member.Pointer {
		t = &Pointer{Target: t, Width: r.resolvePointerWidth(member)}
	}
	if member.Array {
		t = r.resolveArray(t, member, scope)
	}
	return t
}

func (r *resolver) resolveLocal(member *Member, scope *fieldScope) *Local {
	t := r.resolveLocalType(member, scope)
	if t == nil && !isDynamicTypeName(member.Type.Name) {
		return nil
	}
	local := &Local{Name: member.Name, Type: t, Global: scope.global, Export: member.Setting == "out", Input: member.Setting == "in",
		Const: member.Const, Member: !scope.global && !scope.function}
	if member.Initializer != nil {
		local.Init = r.resolveValue(member.Initializer, scope)
		if local.Init == nil {
			return nil
		}
	} else {
		local.Init = defaultValue(t)
	}
	for _, attribute := range member.Attributes {
		if attribute.Name == "export" {
			local.Export = true
		}
	}
	if !r.declareName(member.Name, member.Position, scope) {
		return nil
	}
	scope.locals[member.Name] = local
	return local
}

func (r *resolver) resolveAssignment(member *Member, scope *fieldScope) *Assignment {
	decl := member.Assignment
	var target Value
	switch e := decl.Target.(type) {
	case *Dollar:
		target = &Cursor{}
	case *Identifier:
		if local, isLocal := scope.locals[e.Name]; isLocal {
			if local.Const {
				r.report(e.Position, fmt.Sprintf("%s is a constant", e.Name))
				return nil
			}
			target = &LocalRef{Local: local}
		} else if scope.lookup(e.Name) != nil {
			target = r.resolveValue(e, scope)
		} else {
			target = r.globalRef([]string{e.Name}, e.Position)
		}
	default:
		target = r.resolveValue(e, scope)
	}
	if target == nil {
		return nil
	}
	value := r.resolveValue(decl.Value, scope)
	if value == nil {
		return nil
	}
	if decl.Operator != "=" {
		value = fold(&BinaryOp{Operator: strings.TrimSuffix(decl.Operator, "="), Left: target, Right: value})
	}
	return &Assignment{Target: target, Value: value}
}

func flattenFields(statements []Statement, guard Value) []*Field {
	var fields []*Field
	for _, statement := range statements {
		switch s := statement.(type) {
		case *Field:
			s.Guard = guard
			fields = append(fields, s)
		case *Conditional:
			fields = append(fields, flattenFields(s.Then, conjoinValues(guard, s.Condition))...)
			fields = append(fields, flattenFields(s.Else, conjoinValues(guard, fold(&UnaryOp{Operator: "!", Operand: s.Condition})))...)
		case *Match:
			for _, matchCase := range s.Cases {
				fields = append(fields, flattenFields(matchCase.Then, conjoinValues(guard, matchCase.Condition))...)
			}
			if len(s.Default) > 0 {
				fields = append(fields, flattenFields(s.Default, conjoinValues(guard, unmatched(s)))...)
			}
		}
	}
	return fields
}

func unmatched(match *Match) Value {
	var anyMatched Value
	for _, matchCase := range match.Cases {
		if anyMatched == nil {
			anyMatched = matchCase.Condition
		} else {
			anyMatched = &BinaryOp{Operator: "||", Left: anyMatched, Right: matchCase.Condition}
		}
	}
	if anyMatched == nil {
		return nil
	}
	return fold(&UnaryOp{Operator: "!", Operand: anyMatched})
}

func conjoinValues(guard Value, condition Value) Value {
	if guard == nil {
		return condition
	}
	return fold(&BinaryOp{Operator: "&&", Left: guard, Right: condition})
}

func allFields(t *Struct) []*Field {
	if t.Base == nil {
		return t.Fields
	}
	return append(allFields(t.Base), t.Fields...)
}

func (r *resolver) defineUnion(decl *UnionDecl, t *Union) {
	scope := &fieldScope{locals: map[string]*Local{}}
	for _, param := range t.Params {
		scope.locals[param.Name] = param
	}
	t.Body = r.resolveStatements(decl.Members, scope)
	t.Fields = flattenFields(t.Body, nil)
	t.Simple = plainFields(t.Body)
	t.Attributes = r.resolveTypeAttributes(decl.Attributes, scope)
}

func plainFields(statements []Statement) bool {
	for _, statement := range statements {
		if _, isField := statement.(*Field); !isField {
			return false
		}
	}
	return true
}

type fieldScope struct {
	fields   []*Field
	locals   map[string]*Local
	bits     map[string]*BitfieldMember
	blocks   []map[string]bool
	global   bool
	function bool
	bitfield bool
	branches int
	loops    int
	tries    int
}

func (s *fieldScope) declare(name string) bool {
	if len(s.blocks) == 0 {
		s.blocks = append(s.blocks, map[string]bool{})
	}
	block := s.blocks[len(s.blocks)-1]
	if block[name] {
		return false
	}
	block[name] = true
	return true
}

func (r *resolver) declareName(name string, position Position, scope *fieldScope) bool {
	if name == "" || scope == nil || scope.declare(name) {
		return true
	}
	r.report(position, fmt.Sprintf("%s is already declared", name))
	return false
}

func (r *resolver) resolveBlock(members []Member, scope *fieldScope) []Statement {
	scope.blocks = append(scope.blocks, map[string]bool{})
	defer func() { scope.blocks = scope.blocks[:len(scope.blocks)-1] }()
	return r.resolveStatements(members, scope)
}

func (s *fieldScope) lookup(name string) *Field {
	for i := len(s.fields) - 1; i >= 0; i-- {
		if s.fields[i].Name == name {
			return s.fields[i]
		}
	}
	return nil
}

func (r *resolver) resolveMember(member *Member, scope *fieldScope) *Field {
	if member.Kind == PaddingMember {
		if member.While != nil {
			condition := r.resolveValue(member.While, scope)
			if condition == nil {
				return nil
			}
			return &Field{Type: &Padding{While: condition}, Position: member.Position}
		}
		size := r.resolveValue(member.Length, scope)
		if size == nil {
			return nil
		}
		return &Field{Type: &Padding{Size: size}, Position: member.Position}
	}

	t, order := r.resolveOrderedTypeRef(member.Type, scope)
	if t == nil {
		return nil
	}
	if order != NativeOrder {
		r.module.DynamicEndian = true
	}

	if member.Array {
		t = r.resolveArray(t, member, scope)
		if t == nil {
			return nil
		}
	}

	if member.Pointer {
		t = &Pointer{Target: t, Width: r.resolvePointerWidth(member)}
	}

	if !r.declareName(member.Name, member.Position, scope) {
		return nil
	}
	field := &Field{Name: member.Name, Type: t, Order: order, Doc: member.Doc, Position: member.Position}
	if member.Address != nil {
		field.Address = r.resolveValue(member.Address, scope)
		if field.Address == nil {
			return nil
		}
	}
	if member.Section != nil {
		field.Section = r.resolveValue(member.Section, scope)
		if field.Section == nil {
			return nil
		}
	}
	r.applyFieldAttributes(field, member.Attributes, scope)
	return field
}

func (r *resolver) resolvePointerWidth(member *Member) *Primitive {
	if member.PointerWidth == nil {
		return nil
	}
	width, isPrimitive := r.resolveTypeRef(*member.PointerWidth).(*Primitive)
	if !isPrimitive || !width.Kind.IsInteger() {
		r.report(member.PointerWidth.Position, "pointer width must be an integer type")
		return nil
	}
	return width
}

func (r *resolver) resolveArray(element Type, member *Member, scope *fieldScope) Type {
	if member.While != nil {
		condition := r.resolveValue(member.While, scope)
		if condition == nil {
			return nil
		}
		return &Array{Element: element, While: condition}
	}
	if member.Length == nil {
		if !isCharacter(element) {
			return &Array{Element: element, While: &UnaryOp{Operator: "!", Operand: &Builtin{Name: "std::mem::eof"}}}
		}
		return &Array{Element: element}
	}
	length := r.resolveValue(member.Length, scope)
	if length == nil {
		return nil
	}
	return &Array{Element: element, Length: length}
}

func isCharacter(t Type) bool {
	primitive, isPrimitive := Unalias(t).(*Primitive)
	return isPrimitive && (primitive.Kind == Char || primitive.Kind == Char16)
}

func (r *resolver) applyFieldAttributes(field *Field, attributes []Attribute, scope *fieldScope) {
	for _, attribute := range attributes {
		switch attribute.Name {
		case "hidden":
			field.Hidden = true
		case "no_unique_address":
			field.NoUniqueAddress = true
		case "comment":
			if len(attribute.Arguments) == 1 {
				if text, isString := attribute.Arguments[0].(*StringLiteral); isString {
					field.Doc = joinDoc(field.Doc, text.Value)
					continue
				}
			}
		case "pointer_base":
			if len(attribute.Arguments) == 1 {
				if text, isString := attribute.Arguments[0].(*StringLiteral); isString {
					if function, isFunction := r.lookupFunction(text.Value); isFunction {
						field.PointerBase = function
						continue
					}
				}
			}
			r.report(attribute.Position, "pointer_base expects a function name")
			continue
		}
		if use := r.resolveAttribute(attribute, scope); use != nil {
			field.Attributes = append(field.Attributes, use)
		}
	}
}

var evaluatedAttributes = map[string]bool{
	"name": true, "comment": true, "color": true, "format": true, "format_read": true, "format_entries": true,
	"format_read_entries": true, "transform": true, "transform_entries": true, "pointer_base": true, "fixed_size": true,
	"inline": true, "sealed": true, "hidden": true, "highlight_hidden": true, "tree_hidden": true,
	"hex::visualize": true, "hex::inline_visualize": true,
}

var functionAttributes = map[string]bool{
	"format": true, "format_read": true, "format_entries": true, "format_read_entries": true,
	"transform": true, "transform_entries": true, "pointer_base": true,
}

func (r *resolver) resolveAttribute(attribute Attribute, scope *fieldScope) *AttributeUse {
	if !evaluatedAttributes[attribute.Name] {
		return nil
	}
	use := &AttributeUse{Name: attribute.Name}
	if _, isVisualizer := visualizerPresentations[attribute.Name]; isVisualizer && len(attribute.Arguments) == 0 {
		r.report(attribute.Position, fmt.Sprintf("%s expects a visualizer name", attribute.Name))
		return nil
	}
	if functionAttributes[attribute.Name] {
		if len(attribute.Arguments) != 1 {
			r.report(attribute.Position, fmt.Sprintf("%s expects a function name", attribute.Name))
			return nil
		}
		name, isString := attribute.Arguments[0].(*StringLiteral)
		if !isString {
			use.Dynamic = r.resolveValue(attribute.Arguments[0], scope)
			if use.Dynamic == nil {
				return nil
			}
			r.module.DynamicAttributes = true
			return use
		}
		if function, isFunction := r.lookupFunction(name.Value); isFunction {
			use.Function = function
		} else if _, isBuiltin := builtins[name.Value]; isBuiltin {
			use.Builtin = name.Value
		} else {
			r.report(attribute.Position, fmt.Sprintf("unknown function %s", name.Value))
			return nil
		}
		return use
	}
	for _, argument := range attribute.Arguments {
		value := r.resolveValue(argument, scope)
		if value == nil {
			return nil
		}
		use.Arguments = append(use.Arguments, value)
	}
	return use
}

func (r *resolver) resolveTypeAttributes(attributes []Attribute, scope *fieldScope) []*AttributeUse {
	var uses []*AttributeUse
	for _, attribute := range attributes {
		if use := r.resolveAttribute(attribute, scope); use != nil {
			uses = append(uses, use)
		}
	}
	return uses
}

func joinDoc(existing, extra string) string {
	if existing == "" {
		return extra
	}
	return existing + "\n" + extra
}

func (r *resolver) defineEnum(decl *EnumDecl, t *Enum) {
	declared := r.resolveTypeRef(decl.Underlying)
	if declared == nil {
		return
	}
	underlying := enumUnderlying(declared)
	if underlying == nil {
		if !isComposite(declared) {
			r.report(decl.Underlying.Position, "enum underlying type must be an integer type or a type with a value")
			return
		}
		t.Encoding = declared
		underlying = &Primitive{Kind: U128}
	}
	t.Underlying = underlying
	t.Attributes = r.resolveTypeAttributes(decl.Attributes, nil)
	for i, member := range decl.Members {
		m := enumMemberAt(t, i)
		m.Name = member.Name
		m.Doc = member.Doc
		if member.Value != nil {
			m.expr = r.resolveValue(member.Value, nil)
		}
		if member.Last != nil {
			m.last = r.resolveValue(member.Last, nil)
		}
	}
}

func enumUnderlying(t Type) *Primitive {
	switch t := Unalias(t).(type) {
	case *Primitive:
		if t.Kind.IsInteger() || t.Kind == Bool || t.Kind == Char || t.Kind.IsFloatingPoint() {
			return t
		}
	case *Enum:
		return t.Underlying
	}
	return nil
}

func (r *resolver) defineBitfield(decl *BitfieldDecl, t *Bitfield) {
	scope := &fieldScope{locals: map[string]*Local{}, bits: map[string]*BitfieldMember{}, bitfield: true}
	for _, param := range t.Params {
		scope.locals[param.Name] = param
	}
	t.Body = r.resolveStatements(decl.Members, scope)
	t.Simple = true
	for _, statement := range t.Body {
		member, isBit := statement.(*BitfieldMember)
		if !isBit || !isStaticValue(member.bits) {
			t.Simple = false
			break
		}
		t.Members = append(t.Members, member)
	}
	if !t.Simple {
		t.Members = nil
	}
	var attributes []Attribute
	for _, attribute := range decl.Attributes {
		if attribute.Name == "bitfield_order" {
			r.applyBitfieldOrder(t, attribute)
			continue
		}
		attributes = append(attributes, attribute)
	}
	t.Attributes = r.resolveTypeAttributes(attributes, scope)
}

func (r *resolver) applyBitfieldOrder(t *Bitfield, attribute Attribute) {
	if len(attribute.Arguments) != 2 {
		r.report(attribute.Position, "bitfield_order expects a direction and a size")
		return
	}
	t.direction = r.resolveValue(attribute.Arguments[0], nil)
	t.fixedBits = r.resolveValue(attribute.Arguments[1], nil)
}

func (r *resolver) resolveBitMember(member *Member, scope *fieldScope) *BitfieldMember {
	m := &BitfieldMember{Name: member.Name, Signed: member.Signed, Doc: member.Doc, bits: r.resolveValue(member.Bits, scope)}
	if m.bits == nil || !r.declareName(member.Name, member.Position, scope) {
		return nil
	}
	if member.Type.Name != "" {
		switch memberType := r.resolveTypeRefIn(member.Type, scope).(type) {
		case *Primitive:
			switch {
			case memberType.Kind == Bool:
				m.Bool = true
			case memberType.Kind.IsSigned():
				m.Signed = true
			case !memberType.Kind.IsInteger():
				r.report(member.Type.Position, "bitfield members may only be typed as integers, bool or an enum")
			}
		case *Enum:
			m.Enum = memberType
		case nil:
			return nil
		default:
			r.report(member.Type.Position, "bitfield members may only be typed as integers, bool or an enum")
		}
	}
	return m
}

func (r *resolver) defineAlias(decl *UsingDecl, t *Alias) {
	t.Target = r.resolveTypeRef(*decl.Target)
	if r.definingTypes {
		r.pendingAliases = append(r.pendingAliases, pendingAlias{decl: decl, alias: t})
		return
	}
	t.Attributes = r.resolveTypeAttributes(decl.Attributes, memberScope(t.Target))
}

func memberScope(t Type) *fieldScope {
	switch target := Unalias(t).(type) {
	case *Struct:
		return &fieldScope{fields: target.Fields, locals: map[string]*Local{}}
	case *Union:
		return &fieldScope{fields: target.Fields, locals: map[string]*Local{}}
	case *Bitfield:
		scope := &fieldScope{locals: map[string]*Local{}, bits: map[string]*BitfieldMember{}, bitfield: true}
		for _, member := range target.Members {
			scope.bits[member.Name] = member
		}
		for _, statement := range flattenBitfield(target.Body) {
			if member, isMember := statement.(*BitfieldMember); isMember && member.Name != "" {
				scope.bits[member.Name] = member
			}
		}
		return scope
	}
	return nil
}

func (r *resolver) resolveTypeRef(ref TypeRef) Type {
	return r.resolveTypeRefIn(ref, nil)
}

func (r *resolver) resolveTypeRefIn(ref TypeRef, scope *fieldScope) Type {
	t, order := r.resolveOrderedTypeRef(ref, scope)
	if order != NativeOrder {
		r.report(ref.Position, "endianness can only be specified for built-in types here")
		return nil
	}
	return t
}

func (r *resolver) resolveOrderedTypeRef(ref TypeRef, scope *fieldScope) (Type, ByteOrder) {
	var t Type
	if bound, isParam := r.subst.lookupType(ref.Name); isParam {
		t = bound
	} else if _, isTemplate := r.lookupTemplate(ref.Name); isTemplate || len(ref.Args) > 0 {
		t = r.instantiate(ref, scope)
	} else {
		t = r.lookupType(ref.Name, ref.Position)
	}
	if t == nil || ref.Endian == EndianUnspecified {
		return t, NativeOrder
	}
	order := LittleEndian
	if ref.Endian == EndianBig {
		order = BigEndian
	}
	if primitive, isPrimitive := Unalias(t).(*Primitive); isPrimitive {
		return &Primitive{Kind: primitive.Kind, Order: order}, NativeOrder
	}
	return t, order
}

var unsupportedPrimitives = map[string]bool{
	"str": true, "auto": true,
}

func (r *resolver) lookupType(name string, position Position) Type {
	if t := r.findType(name); t != nil {
		return t
	}
	if unsupportedPrimitives[name] {
		r.report(position, fmt.Sprintf("%s is not supported", name))
	} else {
		r.report(position, fmt.Sprintf("unknown type %s", name))
	}
	return nil
}

func (r *resolver) findType(name string) Type {
	if bound, isParam := r.subst.lookupType(name); isParam {
		return bound
	}
	if kind, isPrimitive := primitiveKindsByName[name]; isPrimitive {
		return &Primitive{Kind: kind, Order: r.order}
	}
	if t, isDeclared := r.lookupDeclared(name); isDeclared {
		return t
	}
	return nil
}

func (r *resolver) lookupDeclared(name string) (NamedType, bool) {
	scope := r.scope
	for {
		qualified := name
		if scope != "" {
			qualified = scope + "::" + name
		}
		if t, isDeclared := r.shells[qualified]; isDeclared {
			return t, true
		}
		if scope == "" {
			return nil, false
		}
		separator := strings.LastIndex(scope, "::")
		if separator == -1 {
			scope = ""
		} else {
			scope = scope[:separator]
		}
	}
}

func (r *resolver) resolveValue(e Expr, scope *fieldScope) Value {
	switch e := e.(type) {
	case *IntegerLiteral:
		return &Constant{Value: int64(e.Value), Wide: e.Wide, Unsigned: e.Unsigned || e.Value > math.MaxInt64, Char: e.Char}
	case *BoolLiteral:
		if e.Value {
			return &Constant{Value: 1}
		}
		return &Constant{Value: 0}
	case *FloatLiteral:
		number, err := strconv.ParseFloat(strings.TrimRight(e.Text, "fFdD"), 64)
		if err != nil {
			r.report(e.Position, "malformed number")
			return nil
		}
		return &FloatConstant{Value: number}
	case *StringLiteral:
		return &StringConstant{Value: e.Value}
	case *Identifier:
		if bound, isParam := r.subst.lookupValue(e.Name); isParam {
			return bound
		}
		if scope != nil {
			if local, isLocal := scope.locals[e.Name]; isLocal {
				return &LocalRef{Local: local}
			}
			if bit, isBit := scope.bits[e.Name]; isBit {
				return &BitRef{Member: bit}
			}
		}
		return r.resolveFieldRef(e, scope)
	case *MemberAccess:
		if parent := parentAccess(e); parent != nil {
			if scope == nil {
				r.report(e.Position, "parent can only be referenced from a struct")
				return nil
			}
			return parent
		}
		if _, isIndexed := indexedObject(e.Object); isIndexed {
			object := r.resolveValue(e.Object, scope)
			if object == nil {
				return nil
			}
			return &MemberOf{Object: object, Name: e.Name, Field: lookupField(staticTypeOf(object), e.Name)}
		}
		if local := r.localBase(e, scope); local != nil {
			return r.resolveMemberChain(e, local, scope)
		}
		if object, isAccess := thisless(e).(*MemberAccess); isAccess {
			if path := r.tryFieldPath(object.Object, scope); path != nil && isBitfield(path[len(path)-1].Type) {
				return &MemberOf{Object: &FieldRef{Path: path}, Name: object.Name}
			}
		}
		return r.resolveFieldRef(thisless(e), scope)
	case *IndexExpr:
		if _, isDollar := e.Object.(*Dollar); isDollar {
			address := r.resolveValue(e.Index, scope)
			if address == nil {
				return nil
			}
			return &Builtin{Name: "std::mem::read_unsigned", Arguments: []Value{address, &Constant{Value: 1}}}
		}
		object := r.resolveValue(e.Object, scope)
		index := r.resolveValue(e.Index, scope)
		if object == nil || index == nil {
			return nil
		}
		return &Index{Object: object, Index: index}
	case *ArrayLiteral:
		literal := &ArrayValue{}
		for _, element := range e.Elements {
			value := r.resolveValue(element, scope)
			if value == nil {
				return nil
			}
			literal.Elements = append(literal.Elements, value)
		}
		return literal
	case *ScopedIdentifier:
		return r.resolveEnumMember(e)
	case *ParentRef:
		if scope == nil {
			r.report(e.Position, "parent can only be referenced from a struct")
			return nil
		}
		if e.Name == "" {
			r.report(e.Position, "parent can only be used on its own with addressof or sizeof")
			return nil
		}
		return &ParentFieldRef{Depth: e.Depth, Path: []string{e.Name}}
	case *ThisExpr:
		if scope == nil {
			r.report(e.Position, "this can only be used inside a struct")
			return nil
		}
		return &ThisRef{}
	case *Dollar:
		if scope == nil {
			r.report(e.Position, "$ can only be used inside a struct")
			return nil
		}
		return &Cursor{}
	case *Call:
		return r.resolveCall(e, scope)
	case *Unary:
		operand := r.resolveValue(e.Operand, scope)
		if operand == nil {
			return nil
		}
		return fold(&UnaryOp{Operator: e.Operator, Operand: operand})
	case *Binary:
		left := r.resolveValue(e.Left, scope)
		right := r.resolveValue(e.Right, scope)
		if left == nil || right == nil {
			return nil
		}
		if (e.Operator == "/" || e.Operator == "%") && isZero(right) {
			r.warn(e.Position, "division by zero")
			return &BinaryOp{Operator: e.Operator, Left: left, Right: right}
		}
		return fold(&BinaryOp{Operator: e.Operator, Left: left, Right: right})
	case *Ternary:
		condition := r.resolveValue(e.Condition, scope)
		then := r.resolveValue(e.Then, scope)
		otherwise := r.resolveValue(e.Else, scope)
		if condition == nil || then == nil || otherwise == nil {
			return nil
		}
		return fold(&Select{Condition: condition, Then: then, Else: otherwise})
	}
	panic("unreachable")
}

func parentAccess(e *MemberAccess) *ParentFieldRef {
	switch object := e.Object.(type) {
	case *ParentRef:
		if object.Name == "" {
			return &ParentFieldRef{Depth: object.Depth, Path: []string{e.Name}}
		}
		return &ParentFieldRef{Depth: object.Depth, Path: []string{object.Name, e.Name}}
	case *MemberAccess:
		if parent := parentAccess(object); parent != nil {
			parent.Path = append(parent.Path, e.Name)
			return parent
		}
	}
	return nil
}

func (r *resolver) localBase(e *MemberAccess, scope *fieldScope) *Local {
	if scope == nil {
		return nil
	}
	switch object := e.Object.(type) {
	case *Identifier:
		return scope.locals[object.Name]
	case *MemberAccess:
		return r.localBase(object, scope)
	}
	return nil
}

func (r *resolver) resolveMemberChain(e *MemberAccess, local *Local, scope *fieldScope) Value {
	var object Value
	switch inner := e.Object.(type) {
	case *Identifier:
		object = &LocalRef{Local: local}
	case *MemberAccess:
		object = r.resolveMemberChain(inner, local, scope)
	}
	if object == nil {
		return nil
	}
	return &MemberOf{Object: object, Name: e.Name, Field: lookupField(staticTypeOf(object), e.Name)}
}

func indexedObject(e Expr) (*IndexExpr, bool) {
	switch e := e.(type) {
	case *IndexExpr:
		return e, true
	case *MemberAccess:
		return indexedObject(e.Object)
	}
	return nil, false
}

func (r *resolver) tryFieldPath(e Expr, scope *fieldScope) []*Field {
	diagnostics, deferred := len(r.diagnostics), len(r.deferred)
	path := r.resolveFieldPath(e, scope)
	if path == nil {
		r.diagnostics, r.deferred = r.diagnostics[:diagnostics], r.deferred[:deferred]
	}
	return path
}

func isBitfield(t Type) bool {
	_, isBitfield := Unalias(t).(*Bitfield)
	return isBitfield
}

func thisless(e *MemberAccess) Expr {
	if _, isThis := e.Object.(*ThisExpr); isThis {
		return &Identifier{Name: e.Name, Position: e.Position}
	}
	if object, isAccess := e.Object.(*MemberAccess); isAccess {
		return &MemberAccess{Object: thisless(object), Name: e.Name, Position: e.Position}
	}
	return e
}

func (r *resolver) resolveFieldRef(e Expr, scope *fieldScope) Value {
	if scope == nil && r.rootScope == nil {
		if path := fieldPathNames(e); path != nil {
			return r.globalRef(path, e.exprPosition())
		}
	}
	if scope != nil && !scope.global && r.rootScope == nil {
		if path := fieldPathNames(e); path != nil && scope.lookup(path[0]) == nil {
			if _, isLocal := scope.locals[path[0]]; !isLocal {
				ref := r.globalRef(path, e.exprPosition())
				ref.Deferred = scope.tries > 0
				return ref
			}
		}
	}
	return r.resolveMemberPath(e, scope)
}

func (r *resolver) resolveMemberPath(e Expr, scope *fieldScope) Value {
	access, isAccess := e.(*MemberAccess)
	if !isAccess {
		path := r.resolveFieldPath(e, scope)
		if path == nil {
			return nil
		}
		return &FieldRef{Path: path}
	}
	object := r.resolveMemberPath(access.Object, scope)
	if object == nil {
		return nil
	}
	if ref, isFieldRef := object.(*FieldRef); isFieldRef {
		parent := ref.Path[len(ref.Path)-1]
		matches := lookupFields(parent.Type, access.Name)
		if len(matches) > 0 && uniformlyTyped(matches) {
			return &FieldRef{Path: append(append([]*Field{}, ref.Path...), matches[0])}
		}
		if len(matches) == 0 && !hasMembers(parent.Type) {
			r.unresolved(access.Position, fmt.Sprintf("%s has no field %s", parent.Name, access.Name))
			return nil
		}
	}
	return &MemberOf{Object: object, Name: access.Name}
}

func uniformlyTyped(fields []*Field) bool {
	for _, field := range fields[1:] {
		if DescribeType(field.Type) != DescribeType(fields[0].Type) {
			return false
		}
	}
	return true
}

func hasMembers(t Type) bool {
	switch t := Unalias(t).(type) {
	case *Struct, *Union, *Bitfield:
		return true
	case *Pointer:
		return hasMembers(t.Target)
	}
	return false
}

func fieldPathNames(e Expr) []string {
	switch e := e.(type) {
	case *Identifier:
		return []string{e.Name}
	case *MemberAccess:
		if object := fieldPathNames(e.Object); object != nil {
			return append(object, e.Name)
		}
	}
	return nil
}

func (r *resolver) globalRef(path []string, position Position) *GlobalRef {
	ref := &GlobalRef{Path: path, Position: position}
	r.globals = append(r.globals, ref)
	return ref
}

func (r *resolver) resolveFieldPath(e Expr, scope *fieldScope) []*Field {
	switch e := e.(type) {
	case *Identifier:
		if scope == nil {
			r.report(e.Position, fmt.Sprintf("%s is not a constant", e.Name))
			return nil
		}
		field := scope.lookup(e.Name)
		if field == nil {
			r.unresolved(e.Position, fmt.Sprintf("unknown field %s; only fields declared earlier in the same type can be referenced", e.Name))
			return nil
		}
		return []*Field{field}
	case *MemberAccess:
		path := r.resolveFieldPath(e.Object, scope)
		if path == nil {
			return nil
		}
		parent := path[len(path)-1]
		field := lookupField(parent.Type, e.Name)
		if field == nil {
			r.unresolved(e.Position, fmt.Sprintf("%s has no field %s", parent.Name, e.Name))
			return nil
		}
		return append(path, field)
	}
	r.report(e.exprPosition(), "expected a field reference")
	return nil
}

func lookupField(t Type, name string) *Field {
	matches := lookupFields(t, name)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

func lookupFields(t Type, name string) []*Field {
	var fields []*Field
	switch t := Unalias(t).(type) {
	case *Struct:
		fields = allFields(t)
	case *Union:
		fields = t.Fields
	case *Pointer:
		return lookupFields(t.Target, name)
	}
	var matches []*Field
	for _, field := range fields {
		if field.Name == name {
			matches = append(matches, field)
		}
	}
	return matches
}

func isIntegral(t Type) bool {
	switch t := Unalias(t).(type) {
	case *Primitive:
		return t.Kind.IsInteger() || t.Kind == Bool
	case *Enum:
		return true
	}
	return false
}

func (r *resolver) resolveEnumMember(e *ScopedIdentifier) Value {
	declared, isDeclared := r.lookupDeclared(e.Scope)
	var enum *Enum
	isEnum := false
	if isDeclared {
		enum, isEnum = Unalias(declared).(*Enum)
	}
	if !isEnum {
		r.report(e.Position, fmt.Sprintf("%s is not an enum", e.Scope))
		return nil
	}
	decl := r.decls[enum.Name].(*EnumDecl)
	for i, member := range decl.Members {
		if member.Name == e.Name {
			return &EnumMemberRef{Enum: enum, Member: enumMemberAt(enum, i)}
		}
	}
	r.report(e.Position, fmt.Sprintf("%s has no member %s", e.Scope, e.Name))
	return nil
}

func enumMemberAt(enum *Enum, index int) *EnumMember {
	for len(enum.Members) <= index {
		enum.Members = append(enum.Members, &EnumMember{})
	}
	return enum.Members[index]
}

func (r *resolver) resolveCall(e *Call, scope *fieldScope) Value {
	switch e.Name {
	case "sizeof":
		return r.resolveSizeOf(e, scope)
	case "addressof":
		return r.resolveAddressOf(e, scope)
	case "typenameof":
		return r.resolveTypeName(e, scope)
	case "str":
		e = &Call{Name: "std::string::to_string", Arguments: e.Arguments, Position: e.Position}
	}
	name, explicitlyBuiltin := strings.CutPrefix(e.Name, "builtin::")
	if explicitlyBuiltin {
		e = &Call{Name: name, Arguments: e.Arguments, Position: e.Position}
	}
	if kind, isPrimitive := primitiveKindsByName[e.Name]; isPrimitive && len(e.Arguments) == 1 {
		operand := r.resolveValue(e.Arguments[0], scope)
		if operand == nil {
			return nil
		}
		return castValue(operand, kind)
	}
	if function, isFunction := r.lookupFunction(e.Name); isFunction && !explicitlyBuiltin {
		return r.resolveFunctionCall(e, function, scope)
	}
	if definition, isBuiltin := builtins[e.Name]; isBuiltin {
		call := &Builtin{Name: e.Name}
		if e.Name == "std::core::set_endian" {
			r.module.DynamicEndian = true
		}
		spreads := false
		for _, argument := range e.Arguments {
			value := r.resolveValue(argument, scope)
			if value == nil {
				return nil
			}
			spreads = spreads || isPack(value)
			call.Arguments = append(call.Arguments, r.labelled(value))
		}
		if definition.arity >= 0 && len(e.Arguments) != definition.arity && !spreads {
			r.unresolved(e.Position, fmt.Sprintf("%s takes %d arguments", e.Name, definition.arity))
			return nil
		}
		return call
	}
	r.unresolved(e.Position, fmt.Sprintf("unknown function %s", e.Name))
	return nil
}

func (r *resolver) lookupFunction(name string) (*Function, bool) {
	scope := r.scope
	for {
		qualified := name
		if scope != "" {
			qualified = scope + "::" + name
		}
		if f, isDeclared := r.functions[qualified]; isDeclared {
			return f, true
		}
		if scope == "" {
			return nil, false
		}
		separator := strings.LastIndex(scope, "::")
		if separator == -1 {
			scope = ""
		} else {
			scope = scope[:separator]
		}
	}
}

func (r *resolver) resolveFunctionCall(e *Call, function *Function, scope *fieldScope) Value {
	fixed := len(function.Params)
	if function.Variadic {
		fixed--
	}
	required := fixed
	for required > 0 && function.Defaults[required-1] != nil {
		required--
	}
	call := &FunctionCall{Function: function}
	spreads := false
	for _, argument := range e.Arguments {
		value := r.resolveValue(argument, scope)
		if value == nil {
			return nil
		}
		spreads = spreads || isPack(value)
		call.Arguments = append(call.Arguments, r.labelled(value))
	}
	if !spreads && (len(e.Arguments) < required || (!function.Variadic && len(e.Arguments) > fixed)) {
		r.unresolved(e.Position, fmt.Sprintf("%s takes %d arguments", function.Name, len(function.Params)))
		return nil
	}
	for i := len(e.Arguments); i < fixed; i++ {
		call.Arguments = append(call.Arguments, function.Defaults[i])
	}
	return call
}

func isPack(v Value) bool {
	local, isLocal := v.(*LocalRef)
	return isLocal && local.Local.Pack
}

func (r *resolver) labelled(v Value) Value {
	if enum, isEnum := Unalias(staticTypeOf(v)).(*Enum); isEnum {
		return &Labelled{Enum: enum, Value: v}
	}
	return v
}

func staticTypeOf(v Value) Type {
	switch v := v.(type) {
	case *LocalRef:
		return v.Local.Type
	case *FieldRef:
		return v.Path[len(v.Path)-1].Type
	case *MemberOf:
		if v.Field != nil {
			return v.Field.Type
		}
	case *Index:
		if array, isArray := Unalias(staticTypeOf(v.Object)).(*Array); isArray {
			return array.Element
		}
	}
	return nil
}

func (r *resolver) resolveTypeName(e *Call, scope *fieldScope) Value {
	if e.TypeArg != nil {
		t := r.resolveTypeRefIn(*e.TypeArg, scope)
		if t == nil {
			return nil
		}
		return r.typeNameValue(r.namePieces(t, *e.TypeArg))
	}
	if len(e.Arguments) != 1 {
		r.report(e.Position, "typenameof takes one argument")
		return nil
	}
	if name, isIdentifier := e.Arguments[0].(*Identifier); isIdentifier {
		if t := r.findType(name.Name); t != nil {
			return r.typeNameValue(r.namePieces(t, TypeRef{Name: name.Name}))
		}
	}
	target := r.resolvePatternRef(e.Arguments[0], scope)
	if target == nil {
		return nil
	}
	if t := staticTypeOf(target); t != nil {
		if hasDynamicNaming(t) {
			return &PatternTypeName{Target: target}
		}
		return &StringConstant{Value: DescribeType(t)}
	}
	r.report(e.Position, "typenameof needs a typed value")
	return nil
}

func isReference(v Value) bool {
	switch v.(type) {
	case *LocalRef, *FieldRef, *ParentFieldRef, *GlobalRef, *MemberOf, *Index, *ThisRef:
		return true
	}
	return false
}

func (r *resolver) resolveSizeOf(e *Call, scope *fieldScope) Value {
	if e.TypeArg != nil {
		t := r.resolveTypeRefIn(*e.TypeArg, scope)
		if t == nil {
			return nil
		}
		return &SizeOf{Type: t}
	}
	if len(e.Arguments) != 1 {
		r.report(e.Position, "sizeof takes one argument")
		return nil
	}
	if name, isIdentifier := e.Arguments[0].(*Identifier); isIdentifier {
		if scope != nil {
			if local, isLocal := scope.locals[name.Name]; isLocal {
				return &SizeOfValue{Target: &LocalRef{Local: local}}
			}
		}
		if scope == nil || scope.lookup(name.Name) == nil {
			if t := r.findType(name.Name); t != nil {
				return &SizeOf{Type: t}
			}
			if scope != nil && !scope.global && r.rootScope == nil {
				return &SizeOfValue{Target: r.globalRef([]string{name.Name}, name.Position)}
			}
			r.lookupType(name.Name, name.Position)
			return nil
		}
	}
	if _, isDollar := e.Arguments[0].(*Dollar); isDollar {
		return &Builtin{Name: "std::mem::size"}
	}
	target := r.resolvePatternRef(e.Arguments[0], scope)
	if target == nil {
		return nil
	}
	return &SizeOfValue{Target: target}
}

func (r *resolver) resolveAddressOf(e *Call, scope *fieldScope) Value {
	if len(e.Arguments) != 1 {
		r.report(e.Position, "addressof takes one argument")
		return nil
	}
	if _, isDollar := e.Arguments[0].(*Dollar); isDollar {
		return &Constant{}
	}
	target := r.resolvePatternRef(e.Arguments[0], scope)
	if target == nil {
		return nil
	}
	return &AddressOf{Target: target}
}

func (r *resolver) resolvePatternRef(e Expr, scope *fieldScope) Value {
	if scope == nil {
		r.report(e.exprPosition(), "expected a field reference")
		return nil
	}
	switch e := e.(type) {
	case *ThisExpr:
		return &ThisRef{}
	case *ParentRef:
		if e.Name == "" {
			return &ThisRef{Depth: e.Depth}
		}
		return &ParentFieldRef{Depth: e.Depth, Path: []string{e.Name}}
	case *MemberAccess:
		if parent := parentAccess(e); parent != nil {
			return parent
		}
		if _, isIndexed := indexedObject(e.Object); isIndexed {
			return r.resolveValue(e, scope)
		}
		if r.localBase(e, scope) != nil {
			return r.resolveValue(e, scope)
		}
		return r.resolveFieldRef(thisless(e), scope)
	case *IndexExpr:
		return r.resolveValue(e, scope)
	case *Identifier:
		if local, isLocal := scope.locals[e.Name]; isLocal {
			return &LocalRef{Local: local}
		}
		return r.resolveFieldRef(e, scope)
	}
	r.report(e.exprPosition(), "expected a field reference")
	return nil
}

func castValue(v Value, kind PrimitiveKind) Value {
	constant, isConstant := v.(*Constant)
	if !isConstant {
		return &Cast{Kind: kind, Operand: v}
	}
	value := constant.Value
	switch kind {
	case U8:
		value = int64(uint8(value))
	case U16:
		value = int64(uint16(value))
	case U24:
		value = value & 0xffffff
	case U32:
		value = int64(uint32(value))
	case U48:
		value = value & 0xffffffffffff
	case S8:
		value = int64(int8(value))
	case S16:
		value = int64(int16(value))
	case S24:
		value = int64(int32(value<<8)) >> 8
	case S32:
		value = int64(int32(value))
	case S48:
		value = (value << 16) >> 16
	case Bool:
		if value != 0 {
			value = 1
		}
	}
	return &Constant{Value: value}
}

func isZero(v Value) bool {
	constant, isConstant := v.(*Constant)
	return isConstant && constant.Value == 0
}

func fold(v Value) Value {
	switch v := v.(type) {
	case *UnaryOp:
		if operand, ok := v.Operand.(*Constant); ok && operand.Wide == nil && !(operand.Unsigned && v.Operator == "~") {
			return &Constant{Value: applyUnary(v.Operator, operand.Value)}
		}
	case *BinaryOp:
		left, leftOk := v.Left.(*Constant)
		right, rightOk := v.Right.(*Constant)
		if leftOk && rightOk && left.Wide == nil && right.Wide == nil && !left.Unsigned && !right.Unsigned {
			return &Constant{Value: applyBinary(v.Operator, left.Value, right.Value)}
		}
	case *Select:
		if condition, ok := v.Condition.(*Constant); ok {
			if condition.Value != 0 {
				return v.Then
			}
			return v.Else
		}
	}
	return v
}

func applyUnary(operator string, operand int64) int64 {
	switch operator {
	case "-":
		return -operand
	case "!":
		return boolToInt(operand == 0)
	case "~":
		return ^operand
	}
	return operand
}

func applyBinary(operator string, left, right int64) int64 {
	switch operator {
	case "+":
		return left + right
	case "-":
		return left - right
	case "*":
		return left * right
	case "/":
		if right == 0 {
			return 0
		}
		return left / right
	case "%":
		if right == 0 {
			return 0
		}
		return left % right
	case "<<":
		return left << uint64(right)
	case ">>":
		return left >> uint64(right)
	case "&":
		return left & right
	case "|":
		return left | right
	case "^":
		return left ^ right
	case "==":
		return boolToInt(left == right)
	case "!=":
		return boolToInt(left != right)
	case "<":
		return boolToInt(left < right)
	case ">":
		return boolToInt(left > right)
	case "<=":
		return boolToInt(left <= right)
	case ">=":
		return boolToInt(left >= right)
	case "&&":
		return boolToInt(left != 0 && right != 0)
	case "||":
		return boolToInt(left != 0 || right != 0)
	case "^^":
		return boolToInt((left != 0) != (right != 0))
	}
	panic("unreachable")
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func declarationPosition(decl Declaration) Position {
	switch d := decl.(type) {
	case *StructDecl:
		return d.Position
	case *UnionDecl:
		return d.Position
	case *EnumDecl:
		return d.Position
	case *BitfieldDecl:
		return d.Position
	case *UsingDecl:
		return d.Position
	}
	panic("unreachable")
}

func (r *resolver) report(position Position, message string) {
	r.diagnostics = append(r.diagnostics, Diagnostic{Position: position, Message: message})
}

func (r *resolver) unresolved(position Position, message string) {
	if r.deferring == 0 {
		r.report(position, message)
		return
	}
	r.deferred = append(r.deferred, Diagnostic{Position: position, Message: message})
}

func (r *resolver) warn(position Position, message string) {
	r.warnings = append(r.warnings, Diagnostic{Position: position, Message: message})
}

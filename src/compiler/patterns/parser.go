package patterns

import (
	"fmt"
	"slices"
	"strings"
)

type parsedSource struct {
	file         *File
	tokens       []token
	diagnostics  []Diagnostic
	macros       macros
	dependencies []macroDependency
}

type macroDependency struct {
	path     string
	incoming macros
	outgoing string
}

type parseKey struct {
	source Source
	macros string
}

var parsedSources = newCache[parseKey, *parsedSource](128)

func parseShared(source Source, incoming macros, resolver Resolver) *parsedSource {
	return parseWithin(source, incoming, resolver, nil)
}

func parseWithin(source Source, incoming macros, resolver Resolver, enclosing []string) *parsedSource {
	key := parseKey{source: source, macros: incoming.signature()}
	within := append(slices.Clip(enclosing), source.Path)
	if parsed, isCached := parsedSources.get(key); isCached && parsed.isCurrent(source.Path, resolver, within) {
		return parsed
	}
	parsed := &parsedSource{}
	include := func(path string, at macros) macros {
		dependency, err := resolveDependency(source.Path, path, resolver)
		if err != nil || slices.Contains(within, dependency.Path) {
			return nil
		}
		included := parseWithin(dependency, at, resolver, within)
		parsed.dependencies = append(parsed.dependencies, macroDependency{path: path, incoming: at, outgoing: included.macros.signature()})
		return included.macros
	}
	parsed.file, parsed.tokens, parsed.diagnostics, parsed.macros = parseSource(source.Path, source.Text, incoming, include)
	parsedSources.put(key, parsed)
	return parsed
}

func (p *parsedSource) isCurrent(importer string, resolver Resolver, within []string) bool {
	for _, dependency := range p.dependencies {
		source, err := resolveDependency(importer, dependency.path, resolver)
		if err != nil || slices.Contains(within, source.Path) {
			return false
		}
		if parseWithin(source, dependency.incoming, resolver, within).macros.signature() != dependency.outgoing {
			return false
		}
	}
	return true
}

func ParseFile(path string, source string) (*File, []Diagnostic) {
	file, _, diagnostics, _ := parseSource(path, source, nil, nil)
	return file, diagnostics
}

func parseSource(path string, source string, incoming macros, include includeHandler) (*File, []token, []Diagnostic, macros) {
	lexed, diagnostics := lex(path, source)
	tokens, diagnostics, outgoing := preprocess(lexed, diagnostics, incoming, include)
	p := &parser{tokens: slices.Clone(tokens), diagnostics: diagnostics}
	file := p.parseFile()
	file.Path = path
	return file, tokens, p.diagnostics, outgoing
}

type parser struct {
	tokens      []token
	index       int
	diagnostics []Diagnostic
	pendingDoc  string
	scope       string
	inBitfield  bool
	angleGuard  int
	alternative bool
	constant    bool
}

type parseError struct {
	diagnostic Diagnostic
}

func (p *parser) parseFile() *File {
	file := &File{}
	for !p.atEOF() {
		p.parseTopLevel(file)
	}
	return file
}

func (p *parser) parseTopLevel(file *File) {
	defer p.recoverFromError(func() { p.skipDeclaration() })

	t := p.peek()
	if t.is(tokenIdentifier, "namespace") {
		p.parseNamespace(file)
		return
	}
	if t.is(tokenIdentifier, "import") {
		p.parseImport(file)
		return
	}
	if t.is(tokenPunctuation, "}") && p.scope != "" {
		p.fail(t.position, "unexpected }")
	}
	if p.accept(";") {
		return
	}
	switch t.kind {
	case tokenDirective:
		p.advance()
		p.parseDirective(t, file)
	case tokenDocComment:
		p.advance()
		p.pendingDoc = t.text
	case tokenPunctuation:
		if t.text == "[[" {
			attributes := p.parseAttributes()
			decl := p.parseDeclaration()
			attachAttributes(decl, attributes)
			file.Declarations = append(file.Declarations, decl)
			return
		}
		if t.text == "$" {
			p.parseMember(&file.Body)
			return
		}
		p.fail(t.position, "expected a declaration")
	default:
		if isTypeKeyword(t.text) {
			file.Declarations = append(file.Declarations, p.parseDeclaration())
		} else {
			p.parseMember(&file.Body)
		}
	}
}

func (p *parser) parseTopLevelAttributes(file *File) {
	attributes := p.parseAttributes()
	decl := p.parseDeclaration()
	attachAttributes(decl, attributes)
	file.Declarations = append(file.Declarations, decl)
}

func isTypeKeyword(word string) bool {
	switch word {
	case "struct", "union", "enum", "bitfield", "using", "fn":
		return true
	}
	return false
}

func (p *parser) parseFunction(doc string) *FunctionDecl {
	position := p.expectKeyword("fn")
	decl := &FunctionDecl{Name: p.qualify(p.expectIdentifier()), Scope: p.scope, Doc: doc, Position: position}
	if p.check("<") {
		p.fail(p.peek().position, "function templates are not supported")
	}
	p.expect("(")
	for !p.check(")") {
		decl.Params = append(decl.Params, p.parseParam())
		if !p.accept(",") {
			break
		}
	}
	p.expect(")")
	decl.Body = p.parseBlock()
	p.accept(";")
	return decl
}

func (p *parser) parseParam() ParamDecl {
	param := ParamDecl{Position: p.peek().position}
	if p.peek().is(tokenIdentifier, "ref") {
		p.advance()
		param.Ref = true
	}
	if p.peek().is(tokenIdentifier, "auto") {
		p.advance()
		param.Variadic = p.accept("...")
	} else {
		t := p.parseTypeRef()
		param.Type = &t
	}
	if p.peek().kind == tokenIdentifier {
		param.Name = p.expectIdentifier()
	}
	if p.accept("=") {
		param.Default = p.parseExpr()
	}
	return param
}

func (p *parser) parseDirective(t token, file *File) {
	name, rest, _ := strings.Cut(t.text, " ")
	rest = strings.TrimSpace(rest)
	switch name {
	case "pragma":
		pragmaName, value, _ := strings.Cut(rest, " ")
		file.Pragmas = append(file.Pragmas, Pragma{Name: pragmaName, Value: strings.TrimSpace(value), Position: t.position})
	case "include":
		file.Includes = append(file.Includes, Include{Path: p.includePath(rest, t.position), Position: t.position, macros: t.macros})
	default:
		p.fail(t.position, fmt.Sprintf("unknown directive #%s", name))
	}
}

func (p *parser) includePath(spec string, position Position) string {
	path, isValid := includeTarget(spec)
	if !isValid {
		p.fail(position, "expected a quoted or bracketed path")
	}
	return path
}

func (p *parser) parseImport(file *File) {
	macros := p.peek().macros
	position := p.expectKeyword("import")
	statement := Import{Position: position, macros: macros}
	if p.accept("*") {
		p.expectKeyword("from")
		statement.AsType = true
	}
	if t := p.peek(); t.kind == tokenString {
		p.advance()
		statement.Path = t.text
	} else {
		statement.Path = p.expectIdentifier()
		for p.accept(".") {
			statement.Path += "/" + p.expectIdentifier()
		}
	}
	if p.peek().is(tokenIdentifier, "as") {
		p.advance()
		statement.Alias = p.expectIdentifier()
	} else if statement.AsType {
		p.fail(position, "import * requires an alias")
	}
	p.expect(";")
	file.Imports = append(file.Imports, statement)
}

func (p *parser) parseNamespace(file *File) {
	p.expectKeyword("namespace")
	outer := p.scope
	isAuto := p.peek().is(tokenIdentifier, "auto")
	if isAuto {
		p.advance()
	}
	p.scope = p.qualify(p.parseQualifiedName())
	if isAuto {
		file.AutoNamespaces = append(file.AutoNamespaces, p.scope)
	}
	p.expect("{")
	for !p.accept("}") {
		if p.atEOF() {
			p.fail(p.peek().position, "expected }")
		}
		p.parseTopLevel(file)
	}
	p.accept(";")
	p.scope = outer
}

func (p *parser) qualify(name string) string {
	if p.scope == "" {
		return name
	}
	return p.scope + "::" + name
}

func (p *parser) parseDeclaration() Declaration {
	doc := p.takeDoc()
	t := p.peek()
	if t.kind != tokenIdentifier {
		p.fail(t.position, "expected a declaration")
	}

	switch t.text {
	case "struct":
		return p.parseStruct(doc)
	case "union":
		return p.parseUnion(doc)
	case "enum":
		return p.parseEnum(doc)
	case "bitfield":
		return p.parseBitfield(doc)
	case "using":
		return p.parseUsing(doc)
	case "fn":
		return p.parseFunction(doc)
	}

	p.fail(t.position, "expected a declaration")
	return nil
}

func (p *parser) parseStruct(doc string) *StructDecl {
	position := p.expectKeyword("struct")
	decl := &StructDecl{Name: p.qualify(p.expectIdentifier()), Scope: p.scope, Doc: doc, Position: position}
	decl.Params = p.parseTypeParams()
	if p.accept(":") {
		base := p.parseTypeRef()
		decl.Base = &base
	}
	decl.Members = p.parseMembers()
	decl.Attributes = p.parseTrailingAttributes()
	p.expect(";")
	return decl
}

func (p *parser) parseUnion(doc string) *UnionDecl {
	position := p.expectKeyword("union")
	decl := &UnionDecl{Name: p.qualify(p.expectIdentifier()), Scope: p.scope, Doc: doc, Position: position}
	decl.Params = p.parseTypeParams()
	decl.Members = p.parseMembers()
	decl.Attributes = p.parseTrailingAttributes()
	p.expect(";")
	return decl
}

func (p *parser) parseMembers() []Member {
	p.expect("{")
	var members []Member
	for !p.accept("}") {
		if p.atEOF() {
			p.fail(p.peek().position, "expected }")
		}
		p.parseMember(&members)
	}
	return members
}

func (p *parser) parseMember(members *[]Member) {
	defer p.recoverFromError(func() { p.skipStatement() })
	before := len(*members)
	defer func() {
		for i := before; i < len(*members); i++ {
			(*members)[i].Scope = p.scope
			(*members)[i].Const = p.constant && (*members)[i].Kind == LocalMember
		}
		p.constant = false
	}()

	t := p.peek()
	if t.kind == tokenDocComment {
		p.advance()
		p.pendingDoc = t.text
		return
	}
	if t.kind == tokenDirective {
		p.advance()
		return
	}
	if p.accept(";") {
		return
	}

	var attributes []Attribute
	if t.is(tokenPunctuation, "[[") {
		attributes = p.parseAttributes()
		t = p.peek()
	}

	doc := p.takeDoc()

	if t.is(tokenIdentifier, "const") {
		p.advance()
		p.constant = true
		t = p.peek()
	}

	if p.inBitfield && !isControlKeyword(t.text) && p.parseBitMember(members, attributes, doc) {
		return
	}

	if t.is(tokenPunctuation, "$") {
		*members = append(*members, p.parseAssignment(&Dollar{Position: t.position}))
		return
	}

	if t.kind != tokenIdentifier {
		p.fail(t.position, "expected a member declaration")
	}

	if p.looksLikeAssignment() {
		target := p.parsePostfix(p.parseNamedPrimary())
		*members = append(*members, p.parseAssignment(target))
		return
	}

	if p.looksLikeCall() && !isStatementKeyword(t.text) {
		value := p.parseExpr()
		p.expect(";")
		*members = append(*members, Member{Kind: CallMember, Value: value, Position: t.position})
		return
	}

	switch t.text {
	case "padding":
		p.advance()
		member := Member{Kind: PaddingMember, Position: t.position}
		p.expect("[")
		if p.peek().is(tokenIdentifier, "while") {
			p.advance()
			p.expect("(")
			member.While = p.parseExpr()
			p.expect(")")
		} else {
			member.Length = p.parseExpr()
		}
		p.expect("]")
		p.parseTrailingAttributes()
		p.expect(";")
		*members = append(*members, member)
		return
	case "if":
		*members = append(*members, Member{Kind: ConditionalMember, Conditional: p.parseIf(), Position: t.position})
		return
	case "match":
		*members = append(*members, Member{Kind: MatchMember, Match: p.parseMatch(), Position: t.position})
		return
	case "return":
		p.advance()
		member := Member{Kind: ReturnMember, Position: t.position}
		if !p.check(";") {
			member.Value = p.parseExpr()
		}
		p.expect(";")
		*members = append(*members, member)
		return
	case "break", "continue":
		p.advance()
		p.expect(";")
		kind := BreakMember
		if t.text == "continue" {
			kind = ContinueMember
		}
		*members = append(*members, Member{Kind: kind, Position: t.position})
		return
	case "while":
		p.advance()
		p.expect("(")
		loop := &LoopDecl{Condition: p.parseExpr()}
		p.expect(")")
		loop.Body = p.parseBlock()
		*members = append(*members, Member{Kind: WhileMember, Loop: loop, Position: t.position})
		return
	case "for":
		*members = append(*members, Member{Kind: ForMember, Loop: p.parseFor(), Position: t.position})
		return
	case "try":
		p.advance()
		try := &TryDecl{Body: p.parseBlock()}
		if p.peek().is(tokenIdentifier, "catch") {
			p.advance()
			try.Catch = p.parseBlock()
		}
		*members = append(*members, Member{Kind: TryMember, Try: try, Position: t.position})
		return
	case "else", "catch":
		p.fail(t.position, fmt.Sprintf("unexpected %s", t.text))
	}

	member := Member{Kind: FieldMember, Type: p.parseTypeRef(), Doc: doc, Position: t.position}

	if p.accept("*") {
		member.Pointer = true
	}

	if p.peek().kind == tokenIdentifier {
		member.Name = p.expectIdentifier()
	}

	if p.accept("[") {
		member.Array = true
		if !p.check("]") {
			if p.peek().is(tokenIdentifier, "while") {
				p.advance()
				p.expect("(")
				member.While = p.parseExpr()
				p.expect(")")
			} else {
				member.Length = p.parseExpr()
			}
		}
		p.expect("]")
	}

	if member.Pointer && p.accept(":") {
		width := p.parseTypeRef()
		member.PointerWidth = &width
	}

	var siblings []Member
	for member.Name != "" && !member.Array && !member.Pointer && p.accept(",") {
		sibling := member
		sibling.Name = p.expectIdentifier()
		sibling.Position = p.tokens[p.index-1].position
		siblings = append(siblings, sibling)
	}

	if p.accept("@") {
		member.Address = p.parseExpr()
		if p.peek().is(tokenIdentifier, "in") {
			p.advance()
			member.Section = p.parseExpr()
		}
	} else if p.accept("=") {
		member.Kind = LocalMember
		member.Initializer = p.parseExpr()
	} else if p.peek().is(tokenIdentifier, "in") || p.peek().is(tokenIdentifier, "out") {
		member.Kind = LocalMember
		member.Setting = p.peek().text
		p.advance()
		if p.accept("=") {
			member.Initializer = p.parseExpr()
		}
	}

	member.Attributes = append(attributes, p.parseTrailingAttributes()...)
	p.expect(";")

	*members = append(*members, member)
	for i := range siblings {
		siblings[i].Attributes = member.Attributes
		*members = append(*members, siblings[i])
	}
}

func (p *parser) parseIf() *ConditionalDecl {
	position := p.expectKeyword("if")
	p.expect("(")
	decl := &ConditionalDecl{Condition: p.parseExpr(), Position: position}
	p.expect(")")
	decl.Then = p.parseBlock()
	if p.peek().is(tokenIdentifier, "else") {
		p.advance()
		if p.peek().is(tokenIdentifier, "if") {
			decl.Else = []Member{{Kind: ConditionalMember, Conditional: p.parseIf(), Position: p.peek().position}}
		} else {
			decl.Else = p.parseBlock()
		}
	}
	return decl
}

func (p *parser) parseBlock() []Member {
	var members []Member
	if !p.accept("{") {
		p.parseMember(&members)
		return members
	}
	for !p.accept("}") {
		if p.atEOF() {
			p.fail(p.peek().position, "expected }")
		}
		p.parseMember(&members)
	}
	return members
}

func (p *parser) parseMatch() *MatchDecl {
	match := &MatchDecl{Position: p.expectKeyword("match")}
	p.expect("(")
	var subjects []Expr
	for {
		subjects = append(subjects, p.parseExpr())
		if !p.accept(",") {
			break
		}
	}
	p.expect(")")
	p.expect("{")

	for !p.accept("}") {
		if p.atEOF() {
			p.fail(p.peek().position, "expected }")
		}
		casePosition := p.peek().position
		p.expect("(")
		var condition Expr
		catchAll := true
		for i, subject := range subjects {
			if i > 0 {
				p.expect(",")
			}
			pattern, isWildcard := p.parseMatchPattern(subject)
			catchAll = catchAll && isWildcard
			condition = conjoin(condition, pattern)
		}
		p.expect(")")
		p.expect(":")
		body := p.parseBlock()
		if catchAll {
			match.Default = body
		} else {
			match.Cases = append(match.Cases, MatchCaseDecl{Condition: condition, Body: body, Position: casePosition})
		}
	}
	return match
}

func (p *parser) parseMatchPattern(subject Expr) (Expr, bool) {
	if t := p.peek(); t.is(tokenIdentifier, "_") {
		p.advance()
		return &BoolLiteral{Value: true, Position: t.position}, true
	}
	var alternatives Expr
	for {
		alternatives = disjoin(alternatives, p.parseMatchAlternative(subject))
		if !p.accept("|") && !p.accept("||") {
			break
		}
	}
	return alternatives, false
}

func (p *parser) parseMatchAlternative(subject Expr) Expr {
	t := p.peek()
	if t.is(tokenIdentifier, "_") {
		p.advance()
		return &BoolLiteral{Value: true, Position: t.position}
	}
	first := p.parseAlternativeBound()
	if p.accept("...") {
		last := p.parseAlternativeBound()
		return &Binary{Operator: "&&", Position: t.position,
			Left:  &Binary{Operator: ">=", Left: subject, Right: first, Position: t.position},
			Right: &Binary{Operator: "<=", Left: subject, Right: last, Position: t.position}}
	}
	return &Binary{Operator: "==", Left: subject, Right: first, Position: t.position}
}

func conjoin(left Expr, right Expr) Expr {
	if left == nil {
		return right
	}
	return &Binary{Operator: "&&", Left: left, Right: right, Position: left.exprPosition()}
}

func disjoin(left Expr, right Expr) Expr {
	if left == nil {
		return right
	}
	return &Binary{Operator: "||", Left: left, Right: right, Position: left.exprPosition()}
}

func isControlKeyword(word string) bool {
	return word != "padding" && isStatementKeyword(word)
}

func isStatementKeyword(word string) bool {
	switch word {
	case "if", "else", "match", "while", "for", "return", "break", "continue", "try", "catch", "padding":
		return true
	}
	return false
}

func (p *parser) looksLikeAssignment() bool {
	i := 1
	for {
		next := p.peekAt(i)
		switch {
		case next.is(tokenPunctuation, ".") && p.peekAt(i+1).kind == tokenIdentifier:
			i += 2
		case next.is(tokenPunctuation, "["):
			depth := 0
			for {
				bracket := p.peekAt(i)
				if bracket.kind == tokenEOF {
					return false
				}
				if bracket.is(tokenPunctuation, "[") {
					depth++
				} else if bracket.is(tokenPunctuation, "]") {
					depth--
				}
				i++
				if depth == 0 {
					break
				}
			}
		default:
			return next.kind == tokenPunctuation && isAssignmentOperator(next.text)
		}
	}
}

func (p *parser) looksLikeCall() bool {
	i := 1
	for p.peekAt(i).is(tokenPunctuation, "::") && p.peekAt(i+1).kind == tokenIdentifier {
		i += 2
	}
	return p.peekAt(i).is(tokenPunctuation, "(")
}

func (p *parser) parseFor() *LoopDecl {
	p.expectKeyword("for")
	p.expect("(")
	loop := &LoopDecl{}
	if !p.check(",") {
		p.parseLoopInit(&loop.Init)
	}
	p.expect(",")
	loop.Condition = p.parseExpr()
	p.expect(",")
	p.parseLoopStep(&loop.Step)
	p.expect(")")
	loop.Body = p.parseBlock()
	return loop
}

func (p *parser) parseLoopInit(members *[]Member) {
	t := p.peek()
	if p.peekAt(1).kind == tokenPunctuation && isAssignmentOperator(p.peekAt(1).text) {
		name := p.expectIdentifier()
		*members = append(*members, p.parseAssignmentWithoutSemicolon(&Identifier{Name: name, Position: t.position}))
		return
	}
	member := Member{Kind: LocalMember, Type: p.parseTypeRef(), Position: t.position}
	member.Name = p.expectIdentifier()
	p.expect("=")
	member.Initializer = p.parseExpr()
	*members = append(*members, member)
}

func (p *parser) parseLoopStep(members *[]Member) {
	t := p.peek()
	if t.is(tokenPunctuation, "$") {
		*members = append(*members, p.parseAssignmentWithoutSemicolon(&Dollar{Position: t.position}))
		return
	}
	name := p.expectIdentifier()
	*members = append(*members, p.parseAssignmentWithoutSemicolon(&Identifier{Name: name, Position: t.position}))
}

func isAssignmentOperator(text string) bool {
	switch text {
	case "=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=":
		return true
	}
	return false
}

func (p *parser) parseAssignment(target Expr) Member {
	member := p.parseAssignmentWithoutSemicolon(target)
	p.expect(";")
	return member
}

func (p *parser) parseAssignmentWithoutSemicolon(target Expr) Member {
	if _, isDollar := target.(*Dollar); isDollar {
		p.advance()
	}
	operator := p.peek()
	if !isAssignmentOperator(operator.text) {
		p.fail(operator.position, "expected an assignment")
	}
	p.advance()
	value := p.parseExpr()
	return Member{Kind: AssignmentMember, Assignment: &AssignmentDecl{Target: target, Operator: operator.text, Value: value}, Position: target.exprPosition()}
}

func (p *parser) parseEnum(doc string) *EnumDecl {
	position := p.expectKeyword("enum")
	decl := &EnumDecl{Name: p.qualify(p.expectIdentifier()), Scope: p.scope, Doc: doc, Position: position}
	p.expect(":")
	decl.Underlying = p.parseTypeRef()
	p.expect("{")
	for !p.accept("}") {
		if p.atEOF() {
			p.fail(p.peek().position, "expected }")
		}
		if t := p.peek(); t.kind == tokenDocComment {
			p.advance()
			p.pendingDoc = t.text
			continue
		}
		member := EnumMemberDecl{Doc: p.takeDoc(), Position: p.peek().position}
		member.Name = p.expectIdentifier()
		if p.accept("=") {
			member.Value = p.parseExpr()
			if p.accept("...") {
				member.Last = p.parseExpr()
			}
		}
		decl.Members = append(decl.Members, member)
		if !p.accept(",") {
			p.expect("}")
			break
		}
	}
	decl.Attributes = p.parseTrailingAttributes()
	p.expect(";")
	return decl
}

func (p *parser) parseBitfield(doc string) *BitfieldDecl {
	position := p.expectKeyword("bitfield")
	decl := &BitfieldDecl{Name: p.qualify(p.expectIdentifier()), Scope: p.scope, Doc: doc, Position: position}
	decl.Params = p.parseTypeParams()
	outer := p.inBitfield
	p.inBitfield = true
	decl.Members = p.parseMembers()
	p.inBitfield = outer
	decl.Attributes = p.parseTrailingAttributes()
	p.expect(";")
	return decl
}

func (p *parser) parseBitMember(members *[]Member, attributes []Attribute, doc string) bool {
	t := p.peek()
	member := Member{Kind: BitMember, Doc: doc, Position: t.position}
	switch {
	case t.is(tokenIdentifier, "padding") && p.peekAt(1).is(tokenPunctuation, ":"):
		p.advance()
	case (t.is(tokenIdentifier, "signed") || t.is(tokenIdentifier, "unsigned")) && p.peekAt(2).is(tokenPunctuation, ":"):
		member.Signed = t.text == "signed"
		p.advance()
		member.Name = p.expectIdentifier()
	case t.kind == tokenIdentifier && p.peekAt(1).is(tokenPunctuation, ":"):
		member.Name = p.expectIdentifier()
	case t.kind == tokenIdentifier && p.qualifiedNameThen(":", 1):
		ref := p.parseTypeRef()
		member.Type = ref
		member.Name = p.expectIdentifier()
	default:
		return false
	}
	p.expect(":")
	member.Bits = p.parseExpr()
	member.Attributes = append(attributes, p.parseTrailingAttributes()...)
	p.expect(";")
	*members = append(*members, member)
	return true
}

func (p *parser) qualifiedNameThen(punctuation string, skip int) bool {
	i := 1
	for p.peekAt(i).is(tokenPunctuation, "::") && p.peekAt(i+1).kind == tokenIdentifier {
		i += 2
	}
	if p.peekAt(i).is(tokenPunctuation, "<") {
		depth := 0
		for {
			t := p.peekAt(i)
			if t.kind == tokenEOF {
				return false
			}
			if t.is(tokenPunctuation, "<") {
				depth++
			} else if t.is(tokenPunctuation, ">") || t.is(tokenPunctuation, ">>") {
				depth--
				if t.text == ">>" {
					depth--
				}
			}
			i++
			if depth <= 0 {
				break
			}
		}
	}
	for j := 0; j != skip; j++ {
		if p.peekAt(i).kind != tokenIdentifier {
			return false
		}
		i++
	}
	return p.peekAt(i).is(tokenPunctuation, punctuation)
}

func (p *parser) parseUsing(doc string) *UsingDecl {
	position := p.expectKeyword("using")
	decl := &UsingDecl{Name: p.qualify(p.expectIdentifier()), Scope: p.scope, Doc: doc, Position: position}
	decl.Params = p.parseTypeParams()
	if p.accept("=") {
		target := p.parseTypeRef()
		decl.Target = &target
	}
	decl.Attributes = p.parseTrailingAttributes()
	p.expect(";")
	return decl
}

func (p *parser) parseTypeRef() TypeRef {
	t := p.peek()
	ref := TypeRef{Position: t.position}
	if t.is(tokenIdentifier, "le") || t.is(tokenIdentifier, "be") {
		if t.text == "le" {
			ref.Endian = EndianLittle
		} else {
			ref.Endian = EndianBig
		}
		p.advance()
	}
	ref.Name = p.parseQualifiedName()
	if p.check("<") {
		ref.Args = p.parseTypeArgs()
	}
	return ref
}

func (p *parser) parseTypeParams() []TypeParamDecl {
	if !p.accept("<") {
		return nil
	}
	var params []TypeParamDecl
	for {
		param := TypeParamDecl{}
		if p.peek().is(tokenIdentifier, "auto") {
			p.advance()
			param.Auto = true
		}
		param.Name = p.expectIdentifier()
		params = append(params, param)
		if !p.accept(",") {
			break
		}
	}
	p.expectCloseAngle()
	return params
}

func (p *parser) parseTypeArgs() []TypeArg {
	p.expect("<")
	var args []TypeArg
	for {
		args = append(args, p.parseTypeArg())
		if !p.accept(",") {
			break
		}
	}
	p.expectCloseAngle()
	return args
}

func (p *parser) parseTypeArg() TypeArg {
	t := p.peek()
	if t.kind == tokenIdentifier && t.text != "true" && t.text != "false" && (t.text == "le" || t.text == "be" || p.qualifiedNameEnds()) {
		start := p.index
		ref := p.parseTypeRef()
		if p.check(",") || p.check(">") || p.check(">>") {
			arg := TypeArg{Type: &ref}
			if ref.Endian == EndianUnspecified && len(ref.Args) == 0 {
				if separator := strings.LastIndex(ref.Name, "::"); separator != -1 {
					arg.Expr = &ScopedIdentifier{Scope: ref.Name[:separator], Name: ref.Name[separator+2:], Position: ref.Position}
				} else {
					arg.Expr = &Identifier{Name: ref.Name, Position: ref.Position}
				}
			}
			return arg
		}
		p.index = start
	}
	return TypeArg{Expr: p.parseTypeArgExpr()}
}

func (p *parser) templateArgsFollow() bool {
	i := 1
	for p.peekAt(i).is(tokenPunctuation, "::") {
		i += 2
	}
	return p.peekAt(i).is(tokenPunctuation, "<")
}

func (p *parser) qualifiedNameEnds() bool {
	i := 1
	for p.peekAt(i).is(tokenPunctuation, "::") && p.peekAt(i+1).kind == tokenIdentifier {
		i += 2
	}
	next := p.peekAt(i)
	return next.is(tokenPunctuation, ",") || next.is(tokenPunctuation, ">") || next.is(tokenPunctuation, ">>") || next.is(tokenPunctuation, "<")
}

func (p *parser) parseTypeArgExpr() Expr {
	p.angleGuard++
	defer func() { p.angleGuard-- }()
	return p.parseTernary()
}

func (p *parser) parenthesised(parse func() Expr) Expr {
	guard, alternative := p.angleGuard, p.alternative
	p.angleGuard, p.alternative = 0, false
	defer func() { p.angleGuard, p.alternative = guard, alternative }()
	return parse()
}

func (p *parser) expectCloseAngle() {
	t := p.peek()
	if t.is(tokenPunctuation, ">>") {
		p.tokens[p.index].text = ">"
		return
	}
	p.expect(">")
}

func (p *parser) parseQualifiedName() string {
	name := p.expectIdentifier()
	for p.accept("::") {
		name += "::" + p.expectIdentifier()
	}
	return name
}

func (p *parser) parseTrailingAttributes() []Attribute {
	if p.check("[[") {
		return p.parseAttributes()
	}
	return nil
}

func (p *parser) peekAt(distance int) token {
	index := min(p.index+distance, len(p.tokens)-1)
	return p.tokens[index]
}

func (p *parser) parseAttributes() []Attribute {
	p.expect("[[")
	var attributes []Attribute
	for {
		attribute := Attribute{Position: p.peek().position}
		attribute.Name = p.parseQualifiedName()
		if p.accept("(") {
			for !p.check(")") {
				attribute.Arguments = append(attribute.Arguments, p.parseExpr())
				if !p.accept(",") {
					break
				}
			}
			p.expect(")")
		}
		attributes = append(attributes, attribute)
		if !p.accept(",") {
			break
		}
	}
	p.expect("]]")
	return attributes
}

func attachAttributes(decl Declaration, attributes []Attribute) {
	switch d := decl.(type) {
	case *StructDecl:
		d.Attributes = append(attributes, d.Attributes...)
	case *UnionDecl:
		d.Attributes = append(attributes, d.Attributes...)
	}
}

func (p *parser) parseExpr() Expr {
	return p.parseTernary()
}

func (p *parser) parseTernary() Expr {
	condition := p.parseBinary(0)
	if t := p.peek(); t.is(tokenPunctuation, "?") {
		p.advance()
		then := p.parseTernary()
		p.expect(":")
		otherwise := p.parseTernary()
		return &Ternary{Condition: condition, Then: then, Else: otherwise, Position: t.position}
	}
	return condition
}

func (p *parser) parseAlternativeBound() Expr {
	p.alternative = true
	defer func() { p.alternative = false }()
	return p.parseBinary(0)
}

var binaryPrecedence = map[string]int{
	"||": 1,
	"^^": 2,
	"&&": 3,
	"==": 4, "!=": 4,
	"<": 5, ">": 5, "<=": 5, ">=": 5,
	"|":  6,
	"^":  7,
	"&":  8,
	"<<": 9, ">>": 9,
	"+": 10, "-": 10,
	"*": 11, "/": 11, "%": 11,
}

func (p *parser) parseBinary(minPrecedence int) Expr {
	left := p.parseUnary()
	for {
		t := p.peek()
		if t.kind != tokenPunctuation {
			return left
		}
		precedence, isBinary := binaryPrecedence[t.text]
		if !isBinary || precedence < minPrecedence {
			return left
		}
		if p.angleGuard > 0 && (t.text == "<" || t.text == ">" || t.text == ">>") {
			return left
		}
		if p.alternative && t.text == "|" {
			return left
		}
		p.advance()
		right := p.parseBinary(precedence + 1)
		left = &Binary{Operator: t.text, Left: left, Right: right, Position: t.position}
	}
}

func (p *parser) parseUnary() Expr {
	t := p.peek()
	if t.kind == tokenPunctuation && (t.text == "-" || t.text == "+" || t.text == "!" || t.text == "~") {
		p.advance()
		return &Unary{Operator: t.text, Operand: p.parseUnary(), Position: t.position}
	}
	return p.parsePostfix(p.parsePrimary())
}

func (p *parser) parsePostfix(expr Expr) Expr {
	for {
		t := p.peek()
		switch {
		case t.is(tokenPunctuation, "."):
			p.advance()
			if _, isThis := expr.(*ThisExpr); isThis && p.peek().is(tokenIdentifier, "parent") {
				expr = p.parseParentRef()
				continue
			}
			expr = &MemberAccess{Object: expr, Name: p.expectIdentifier(), Position: t.position}
		case t.is(tokenPunctuation, "["):
			p.advance()
			index := p.parenthesised(p.parseExpr)
			p.expect("]")
			expr = &IndexExpr{Object: expr, Index: index, Position: t.position}
		default:
			return expr
		}
	}
}

func (p *parser) parsePrimary() Expr {
	t := p.peek()
	switch t.kind {
	case tokenInteger, tokenCharacter:
		p.advance()
		return &IntegerLiteral{Value: t.integer, Wide: t.wide, Unsigned: t.unsigned, Char: t.kind == tokenCharacter, Position: t.position}
	case tokenFloat:
		p.advance()
		return &FloatLiteral{Text: t.text, Position: t.position}
	case tokenString:
		p.advance()
		return &StringLiteral{Value: t.text, Position: t.position}
	case tokenIdentifier:
		return p.parseNamedPrimary()
	case tokenPunctuation:
		switch t.text {
		case "(":
			p.advance()
			expr := p.parenthesised(p.parseExpr)
			p.expect(")")
			return expr
		case "{":
			p.advance()
			literal := &ArrayLiteral{Position: t.position}
			for !p.check("}") {
				literal.Elements = append(literal.Elements, p.parseExpr())
				if !p.accept(",") {
					break
				}
			}
			p.expect("}")
			return literal
		case "$":
			p.advance()
			return &Dollar{Position: t.position}
		}
	}
	p.fail(t.position, "expected an expression")
	return nil
}

func (p *parser) parseNamedPrimary() Expr {
	t := p.peek()
	switch t.text {
	case "true", "false":
		p.advance()
		return &BoolLiteral{Value: t.text == "true", Position: t.position}
	case "parent":
		return p.parseParentRef()
	case "this":
		p.advance()
		return &ThisExpr{Position: t.position}
	case "le", "be":
		if p.peekAt(1).kind == tokenIdentifier && p.peekAt(2).is(tokenPunctuation, "(") {
			p.advance()
			return p.parseNamedPrimary()
		}
	case "null":
		p.advance()
		return &IntegerLiteral{Position: t.position}
	}

	name := p.parseQualifiedName()

	if p.accept("(") {
		call := &Call{Name: name, Position: t.position}
		if (name == "sizeof" || name == "typenameof") && p.peek().kind == tokenIdentifier && p.qualifiedNameEnds() && p.templateArgsFollow() {
			ref := p.parseTypeRef()
			call.TypeArg = &ref
		}
		for !p.check(")") {
			call.Arguments = append(call.Arguments, p.parenthesised(p.parseExpr))
			if !p.accept(",") {
				break
			}
		}
		p.expect(")")
		return call
	}

	if separator := strings.LastIndex(name, "::"); separator != -1 {
		return &ScopedIdentifier{Scope: name[:separator], Name: name[separator+2:], Position: t.position}
	}
	return &Identifier{Name: name, Position: t.position}
}

func (p *parser) parseParentRef() Expr {
	ref := &ParentRef{Position: p.peek().position}
	for p.peek().is(tokenIdentifier, "parent") {
		p.advance()
		ref.Depth++
		if !p.accept(".") {
			return ref
		}
	}
	ref.Name = p.expectIdentifier()
	return ref
}

func (p *parser) takeDoc() string {
	doc := p.pendingDoc
	p.pendingDoc = ""
	return doc
}

func (p *parser) expectKeyword(keyword string) Position {
	t := p.peek()
	if !t.is(tokenIdentifier, keyword) {
		p.fail(t.position, fmt.Sprintf("expected %s", keyword))
	}
	p.advance()
	return t.position
}

func (p *parser) expectIdentifier() string {
	t := p.peek()
	if t.kind != tokenIdentifier {
		p.fail(t.position, "expected an identifier")
	}
	p.advance()
	return t.text
}

func (p *parser) expect(punctuation string) {
	t := p.peek()
	if punctuation == "]" && t.is(tokenPunctuation, "]]") {
		p.tokens[p.index].text = "]"
		return
	}
	if punctuation == "]]" && t.is(tokenPunctuation, "]") && p.peekAt(1).is(tokenPunctuation, "]") {
		p.advance()
		p.advance()
		return
	}
	if !t.is(tokenPunctuation, punctuation) {
		p.fail(t.position, fmt.Sprintf("expected %s", punctuation))
	}
	p.advance()
}

func (p *parser) accept(punctuation string) bool {
	if p.check(punctuation) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) check(punctuation string) bool {
	if punctuation == "]" && p.peek().is(tokenPunctuation, "]]") {
		return true
	}
	return p.peek().is(tokenPunctuation, punctuation)
}

func (p *parser) fail(position Position, message string) {
	panic(parseError{Diagnostic{Position: position, Message: message}})
}

func (p *parser) recoverFromError(skip func()) {
	if r := recover(); r != nil {
		e, isParseError := r.(parseError)
		if !isParseError {
			panic(r)
		}
		p.diagnostics = append(p.diagnostics, e.diagnostic)
		skip()
	}
}

func (p *parser) skipDeclaration() {
	depth := 0
	for !p.atEOF() {
		t := p.peek()
		p.advance()
		if t.kind != tokenPunctuation {
			continue
		}
		switch t.text {
		case "{":
			depth++
		case "}":
			depth--
		case ";":
			if depth <= 0 {
				return
			}
		}
	}
}

func (p *parser) skipStatement() {
	for !p.atEOF() {
		t := p.peek()
		if t.is(tokenPunctuation, "}") {
			return
		}
		p.advance()
		if t.is(tokenPunctuation, ";") {
			return
		}
	}
}

func (p *parser) peek() token {
	return p.tokens[p.index]
}

func (p *parser) advance() {
	if p.index < len(p.tokens)-1 {
		p.index++
	}
}

func (p *parser) atEOF() bool {
	return p.peek().kind == tokenEOF
}

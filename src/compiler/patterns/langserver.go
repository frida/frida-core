package patterns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

type LanguageService struct {
	documents map[string]*serviceDocument
}

type serviceDocument struct {
	uri   string
	text  string
	lines []int
	file  *File
	diags []Diagnostic
	toks  []token
}

type TextPosition struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type TextRange struct {
	Start TextPosition `json:"start"`
	End   TextPosition `json:"end"`
}

type TextLocation struct {
	URI   string    `json:"uri"`
	Range TextRange `json:"range"`
}

type LSPDiagnostic struct {
	Range    TextRange          `json:"range"`
	Severity DiagnosticSeverity `json:"severity"`
	Source   string             `json:"source"`
	Message  string             `json:"message"`
}

type DiagnosticSeverity int

const (
	SeverityError   DiagnosticSeverity = 1
	SeverityWarning DiagnosticSeverity = 2
)

type DocumentSymbol struct {
	Name           string           `json:"name"`
	Detail         string           `json:"detail,omitempty"`
	Kind           int              `json:"kind"`
	Range          TextRange        `json:"range"`
	SelectionRange TextRange        `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

type FoldingRange struct {
	StartLine      int    `json:"startLine"`
	StartCharacter int    `json:"startCharacter"`
	EndLine        int    `json:"endLine"`
	EndCharacter   int    `json:"endCharacter"`
	Kind           string `json:"kind,omitempty"`
}

type ColorInformation struct {
	Range TextRange `json:"range"`
	Color Color     `json:"color"`
}

type Color struct {
	Red   float64 `json:"red"`
	Green float64 `json:"green"`
	Blue  float64 `json:"blue"`
	Alpha float64 `json:"alpha"`
}

type ColorPresentation struct {
	Label    string   `json:"label"`
	TextEdit TextEdit `json:"textEdit"`
}

type TextEdit struct {
	Range   TextRange `json:"range"`
	NewText string    `json:"newText"`
}

type SemanticTokenSpan struct {
	Line      int
	Character int
	Length    int
	Type      string
	Modifiers []string
}

type CompletionItem struct {
	Label  string `json:"label"`
	Kind   int    `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    TextRange     `json:"range"`
}

type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

const (
	symbolNamespace  = 3
	symbolClass      = 5
	symbolField      = 8
	symbolEnum       = 10
	symbolInterface  = 11
	symbolFunction   = 12
	symbolEnumMember = 22
	symbolStruct     = 23

	completionFunction   = 3
	completionVariable   = 6
	completionClass      = 7
	completionProperty   = 10
	completionValue      = 12
	completionEnum       = 13
	completionKeyword    = 14
	completionEnumMember = 20
	completionStruct     = 22
)

func NewLanguageService() *LanguageService {
	return &LanguageService{documents: map[string]*serviceDocument{}}
}

func (s *LanguageService) Handles(uri string) bool {
	return strings.HasSuffix(uri, ".hexpat") || strings.HasSuffix(uri, ".pat")
}

func (s *LanguageService) Open(uri string, text string) {
	s.documents[uri] = newServiceDocument(uri, text)
}

func (s *LanguageService) Change(uri string, text string) {
	s.documents[uri] = newServiceDocument(uri, text)
}

func (s *LanguageService) Close(uri string) {
	delete(s.documents, uri)
}

func newServiceDocument(uri string, text string) *serviceDocument {
	parsed := parseShared(Source{Text: text}, nil, nil)
	return &serviceDocument{uri: uri, text: text, lines: lineStarts(text), file: parsed.file, diags: parsed.diagnostics, toks: parsed.tokens}
}

func (s *LanguageService) Diagnostics(uri string) []LSPDiagnostic {
	d := s.documents[uri]
	if d == nil {
		return []LSPDiagnostic{}
	}
	module, errors := Compile(d.text)
	result := d.lspDiagnostics(errors, SeverityError)
	if module != nil {
		result = append(result, d.lspDiagnostics(module.Warnings, SeverityWarning)...)
	}
	return result
}

func (d *serviceDocument) lspDiagnostics(diagnostics []Diagnostic, severity DiagnosticSeverity) []LSPDiagnostic {
	result := []LSPDiagnostic{}
	for _, diagnostic := range diagnostics {
		if diagnostic.Position.Path != "" {
			continue
		}
		start := d.textPosition(diagnostic.Position)
		result = append(result, LSPDiagnostic{
			Range:    TextRange{Start: start, End: d.wordEnd(start)},
			Severity: severity,
			Source:   "pattern",
			Message:  diagnostic.Message,
		})
	}
	return result
}

func (s *LanguageService) Symbols(uri string) []DocumentSymbol {
	d := s.documents[uri]
	if d == nil {
		return []DocumentSymbol{}
	}
	scopes := map[string]*DocumentSymbol{}
	var roots []DocumentSymbol
	var order []string
	for _, decl := range d.file.Declarations {
		symbol := d.declarationSymbol(decl)
		scope := scopeOf(decl)
		if scope == "" {
			roots = append(roots, symbol)
			continue
		}
		if scopes[scope] == nil {
			scopes[scope] = &DocumentSymbol{Name: scope, Kind: symbolNamespace, Range: symbol.Range, SelectionRange: symbol.Range}
			order = append(order, scope)
		}
		namespace := scopes[scope]
		namespace.Range = union(namespace.Range, symbol.Range)
		namespace.Children = append(namespace.Children, symbol)
	}
	for _, scope := range order {
		roots = append(roots, *scopes[scope])
	}
	sort.SliceStable(roots, func(i, j int) bool { return less(roots[i].Range.Start, roots[j].Range.Start) })
	if roots == nil {
		roots = []DocumentSymbol{}
	}
	return roots
}

func (d *serviceDocument) declarationSymbol(decl Declaration) DocumentSymbol {
	switch decl := decl.(type) {
	case *StructDecl:
		symbol := d.namedSymbol(decl.Name, "struct", symbolStruct, decl.Position)
		symbol.Children = d.memberSymbols(decl.Members)
		return symbol
	case *UnionDecl:
		symbol := d.namedSymbol(decl.Name, "union", symbolStruct, decl.Position)
		symbol.Children = d.memberSymbols(decl.Members)
		return symbol
	case *EnumDecl:
		symbol := d.namedSymbol(decl.Name, "enum", symbolEnum, decl.Position)
		for _, member := range decl.Members {
			name := d.identifierRange(member.Name, member.Position)
			symbol.Children = append(symbol.Children, DocumentSymbol{Name: member.Name, Kind: symbolEnumMember, Range: name, SelectionRange: name})
		}
		return symbol
	case *BitfieldDecl:
		symbol := d.namedSymbol(decl.Name, "bitfield", symbolStruct, decl.Position)
		symbol.Children = d.memberSymbols(decl.Members)
		return symbol
	case *FunctionDecl:
		return d.namedSymbol(decl.Name, "fn", symbolFunction, decl.Position)
	case *UsingDecl:
		return d.namedSymbol(decl.Name, "using", symbolInterface, decl.Position)
	}
	panic("unreachable")
}

func (d *serviceDocument) memberSymbols(members []Member) []DocumentSymbol {
	var symbols []DocumentSymbol
	walkMembers(members, func(member *Member) {
		if (member.Kind != FieldMember && member.Kind != BitMember) || member.Name == "" {
			return
		}
		symbols = append(symbols, d.namedSymbol(member.Name, member.Type.Name, symbolField, member.Position))
	})
	return symbols
}

func (d *serviceDocument) namedSymbol(qualifiedName string, detail string, kind int, position Position) DocumentSymbol {
	name := unqualified(qualifiedName)
	selection := d.identifierRange(name, position)
	return DocumentSymbol{Name: name, Detail: detail, Kind: kind, Range: d.declarationRange(position), SelectionRange: selection}
}

func (d *serviceDocument) identifierRange(name string, from Position) TextRange {
	for _, t := range d.toks {
		if t.kind == tokenIdentifier && t.text == name && !less(d.textPosition(t.position), d.textPosition(from)) {
			start := d.textPosition(t.position)
			return TextRange{Start: start, End: TextPosition{Line: start.Line, Character: start.Character + len(utf16.Encode([]rune(name)))}}
		}
	}
	start := d.textPosition(from)
	return TextRange{Start: start, End: start}
}

func (d *serviceDocument) declarationRange(from Position) TextRange {
	start := d.textPosition(from)
	depth := 0
	for _, t := range d.toks {
		if t.kind != tokenPunctuation || less(d.textPosition(t.position), start) {
			continue
		}
		switch t.text {
		case "{":
			depth++
		case "}":
			depth--
			if depth == 0 {
				end := d.textPosition(t.position)
				if next := d.tokenAfter(t.position); next.kind == tokenPunctuation && next.text == ";" {
					end = d.textPosition(next.position)
				}
				return TextRange{Start: start, End: TextPosition{Line: end.Line, Character: end.Character + 1}}
			}
		case ";":
			if depth == 0 {
				end := d.textPosition(t.position)
				return TextRange{Start: start, End: TextPosition{Line: end.Line, Character: end.Character + 1}}
			}
		}
	}
	return TextRange{Start: start, End: d.endPosition()}
}

func (d *serviceDocument) tokenAfter(position Position) token {
	for i, t := range d.toks {
		if t.position == position && i+1 < len(d.toks) {
			return d.toks[i+1]
		}
	}
	return token{kind: tokenEOF}
}

func unqualified(name string) string {
	if separator := strings.LastIndex(name, "::"); separator >= 0 {
		return name[separator+2:]
	}
	return name
}

func (s *LanguageService) FoldingRanges(uri string) []FoldingRange {
	d := s.documents[uri]
	result := []FoldingRange{}
	if d == nil {
		return result
	}
	var open []TextPosition
	for _, t := range d.toks {
		if t.kind != tokenPunctuation {
			continue
		}
		switch t.text {
		case "{":
			open = append(open, d.textPosition(t.position))
		case "}":
			if len(open) == 0 {
				continue
			}
			start := open[len(open)-1]
			open = open[:len(open)-1]
			end := d.textPosition(t.position)
			if end.Line > start.Line {
				result = append(result, FoldingRange{
					StartLine: start.Line, StartCharacter: start.Character,
					EndLine: end.Line, EndCharacter: end.Character + 1,
				})
			}
		}
	}
	for _, t := range d.toks {
		if t.kind != tokenDocComment {
			continue
		}
		start := d.textPosition(t.position)
		lines := strings.Count(t.text, "\n")
		if lines > 0 {
			result = append(result, FoldingRange{StartLine: start.Line, StartCharacter: start.Character, EndLine: start.Line + lines, EndCharacter: 0, Kind: "comment"})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartLine != result[j].StartLine {
			return result[i].StartLine < result[j].StartLine
		}
		return result[i].StartCharacter < result[j].StartCharacter
	})
	return result
}

func (s *LanguageService) Colors(uri string) []ColorInformation {
	d := s.documents[uri]
	result := []ColorInformation{}
	if d == nil {
		return result
	}
	d.forEachAttribute(func(attribute Attribute) {
		if attribute.Name != "color" || len(attribute.Arguments) != 1 {
			return
		}
		literal, isString := attribute.Arguments[0].(*StringLiteral)
		if !isString {
			return
		}
		color, ok := parseColor(literal.Value)
		if !ok {
			return
		}
		start := d.textPosition(literal.Position)
		end := TextPosition{Line: start.Line, Character: start.Character + len(utf16.Encode([]rune(literal.Value))) + 2}
		result = append(result, ColorInformation{Range: TextRange{Start: start, End: end}, Color: color})
	})
	return result
}

func (s *LanguageService) ColorPresentations(color Color, edited TextRange) []ColorPresentation {
	label := formatColor(color)
	return []ColorPresentation{{Label: label, TextEdit: TextEdit{Range: edited, NewText: strconv.Quote(label)}}}
}

func parseColor(text string) (Color, bool) {
	if len(text) != 6 && len(text) != 8 {
		return Color{}, false
	}
	value, err := strconv.ParseUint(text, 16, 32)
	if err != nil {
		return Color{}, false
	}
	if len(text) == 6 {
		value = value<<8 | 0xff
	}
	return Color{
		Red:   float64(value>>24&0xff) / 255,
		Green: float64(value>>16&0xff) / 255,
		Blue:  float64(value>>8&0xff) / 255,
		Alpha: float64(value&0xff) / 255,
	}, true
}

func formatColor(color Color) string {
	channel := func(value float64) int { return int(value*255 + 0.5) }
	label := fmt.Sprintf("%02X%02X%02X", channel(color.Red), channel(color.Green), channel(color.Blue))
	if channel(color.Alpha) != 255 {
		label += fmt.Sprintf("%02X", channel(color.Alpha))
	}
	return label
}

func (d *serviceDocument) forEachAttribute(visit func(Attribute)) {
	for _, decl := range d.file.Declarations {
		for _, attribute := range declarationAttributes(decl) {
			visit(attribute)
		}
		walkMembers(declarationMembers(decl), func(member *Member) {
			for _, attribute := range member.Attributes {
				visit(attribute)
			}
		})
	}
	walkMembers(d.file.Body, func(member *Member) {
		for _, attribute := range member.Attributes {
			visit(attribute)
		}
	})
}

func declarationAttributes(decl Declaration) []Attribute {
	switch decl := decl.(type) {
	case *StructDecl:
		return decl.Attributes
	case *UnionDecl:
		return decl.Attributes
	case *EnumDecl:
		return decl.Attributes
	case *BitfieldDecl:
		return decl.Attributes
	case *UsingDecl:
		return decl.Attributes
	}
	return nil
}

func declarationMembers(decl Declaration) []Member {
	switch decl := decl.(type) {
	case *StructDecl:
		return decl.Members
	case *UnionDecl:
		return decl.Members
	case *BitfieldDecl:
		return decl.Members
	case *FunctionDecl:
		return decl.Body
	}
	return nil
}

func (s *LanguageService) SemanticTokens(uri string) []SemanticTokenSpan {
	d := s.documents[uri]
	if d == nil {
		return nil
	}
	var spans []SemanticTokenSpan
	add := func(name string, position Position, kind string, modifiers ...string) {
		if name == "" {
			return
		}
		spans = append(spans, d.span(unqualified(name), position, kind, modifiers))
	}
	for _, decl := range d.file.Declarations {
		switch decl := decl.(type) {
		case *StructDecl:
			add(decl.Name, decl.Position, "struct", "declaration")
			if decl.Base != nil {
				add(decl.Base.Name, decl.Base.Position, "struct")
			}
		case *UnionDecl:
			add(decl.Name, decl.Position, "struct", "declaration")
		case *EnumDecl:
			add(decl.Name, decl.Position, "enum", "declaration")
			for _, member := range decl.Members {
				add(member.Name, member.Position, "enumMember", "declaration")
			}
		case *BitfieldDecl:
			add(decl.Name, decl.Position, "struct", "declaration")
		case *FunctionDecl:
			add(decl.Name, decl.Position, "function", "declaration")
		case *UsingDecl:
			add(decl.Name, decl.Position, "type", "declaration")
			if decl.Target != nil {
				d.typeRefSpans(*decl.Target, add)
			}
		}
		walkMembers(declarationMembers(decl), func(member *Member) {
			d.memberSpans(member, add)
		})
	}
	walkMembers(d.file.Body, func(member *Member) {
		d.memberSpans(member, add)
	})
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Line != spans[j].Line {
			return spans[i].Line < spans[j].Line
		}
		return spans[i].Character < spans[j].Character
	})
	return spans
}

func (d *serviceDocument) memberSpans(member *Member, add func(string, Position, string, ...string)) {
	if member.Kind != FieldMember && member.Kind != LocalMember {
		return
	}
	if isPrimitiveType(member.Type.Name) {
		return
	}
	d.typeRefSpans(member.Type, add)
}

func (d *serviceDocument) typeRefSpans(ref TypeRef, add func(string, Position, string, ...string)) {
	if ref.Name != "" && !isPrimitiveType(ref.Name) {
		add(ref.Name, ref.Position, "type")
	}
	for _, arg := range ref.Args {
		if arg.Type != nil {
			d.typeRefSpans(*arg.Type, add)
		}
	}
}

func (d *serviceDocument) span(name string, from Position, kind string, modifiers []string) SemanticTokenSpan {
	r := d.identifierRange(name, from)
	return SemanticTokenSpan{Line: r.Start.Line, Character: r.Start.Character, Length: r.End.Character - r.Start.Character, Type: kind, Modifiers: modifiers}
}

func (s *LanguageService) Hover(uri string, position TextPosition) *Hover {
	d := s.documents[uri]
	if d == nil {
		return nil
	}
	word, wordRange := d.wordAt(position)
	decl := d.declaration(word)
	if decl == nil {
		return nil
	}
	var text strings.Builder
	text.WriteString("```hexpat\n" + describeDeclaration(decl) + " " + decl.declaredName())
	if size := d.sizeOf(decl.declaredName()); size != "" {
		text.WriteString("    // " + size)
	}
	text.WriteString("\n```")
	if doc := declarationDoc(decl); doc != "" {
		text.WriteString("\n\n" + doc)
	}
	return &Hover{Contents: MarkupContent{Kind: "markdown", Value: text.String()}, Range: wordRange}
}

func (d *serviceDocument) sizeOf(name string) string {
	module, diagnostics := Compile(d.text)
	if len(diagnostics) > 0 || module == nil {
		return ""
	}
	for _, described := range Describe(module, Targets[0]) {
		if described.Name == name && described.Size != nil {
			return fmt.Sprintf("%d bytes", *described.Size)
		}
	}
	return ""
}

func (s *LanguageService) Definition(uri string, position TextPosition) *TextLocation {
	d := s.documents[uri]
	if d == nil {
		return nil
	}
	word, _ := d.wordAt(position)
	decl := d.declaration(word)
	if decl == nil {
		return nil
	}
	symbol := d.declarationSymbol(decl)
	return &TextLocation{URI: uri, Range: symbol.SelectionRange}
}

func (d *serviceDocument) declaration(name string) Declaration {
	if name == "" {
		return nil
	}
	for _, decl := range d.file.Declarations {
		qualified := decl.declaredName()
		if qualified == name || strings.HasSuffix(qualified, "::"+name) {
			return decl
		}
	}
	return nil
}

func describeDeclaration(decl Declaration) string {
	switch decl.(type) {
	case *StructDecl:
		return "struct"
	case *UnionDecl:
		return "union"
	case *EnumDecl:
		return "enum"
	case *BitfieldDecl:
		return "bitfield"
	case *FunctionDecl:
		return "fn"
	case *UsingDecl:
		return "using"
	}
	return ""
}

func declarationDoc(decl Declaration) string {
	switch decl := decl.(type) {
	case *StructDecl:
		return decl.Doc
	case *UnionDecl:
		return decl.Doc
	case *EnumDecl:
		return decl.Doc
	case *BitfieldDecl:
		return decl.Doc
	case *FunctionDecl:
		return decl.Doc
	case *UsingDecl:
		return decl.Doc
	}
	return ""
}

func (d *serviceDocument) wordAt(position TextPosition) (string, TextRange) {
	if position.Line >= len(d.lines) {
		return "", TextRange{Start: position, End: position}
	}
	line := d.lineText(position.Line)
	units := utf16.Encode([]rune(line))
	isWord := func(unit uint16) bool {
		return unit == '_' || unit == ':' || (unit >= '0' && unit <= '9') || (unit >= 'a' && unit <= 'z') || (unit >= 'A' && unit <= 'Z')
	}
	start := min(position.Character, len(units))
	end := start
	for start > 0 && isWord(units[start-1]) {
		start--
	}
	for end < len(units) && isWord(units[end]) {
		end++
	}
	word := string(utf16.Decode(units[start:end]))
	return strings.Trim(word, ":"), TextRange{Start: TextPosition{position.Line, start}, End: TextPosition{position.Line, end}}
}

func (d *serviceDocument) wordEnd(start TextPosition) TextPosition {
	_, r := d.wordAt(start)
	if r.End.Character > start.Character {
		return r.End
	}
	return TextPosition{Line: start.Line, Character: start.Character + 1}
}

func (d *serviceDocument) textPosition(position Position) TextPosition {
	if position.Line >= len(d.lines) {
		return d.endPosition()
	}
	line := d.lineText(position.Line)
	column := min(position.Character, len(line))
	return TextPosition{Line: position.Line, Character: len(utf16.Encode([]rune(line[:column])))}
}

func (d *serviceDocument) endPosition() TextPosition {
	last := len(d.lines) - 1
	return TextPosition{Line: last, Character: len(utf16.Encode([]rune(d.lineText(last))))}
}

func (d *serviceDocument) lineText(line int) string {
	start := d.lines[line]
	end := len(d.text)
	if line+1 < len(d.lines) {
		end = d.lines[line+1] - 1
	}
	return strings.TrimSuffix(d.text[start:end], "\r")
}

func lineStarts(text string) []int {
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func less(a TextPosition, b TextPosition) bool {
	return a.Line < b.Line || (a.Line == b.Line && a.Character < b.Character)
}

func union(a TextRange, b TextRange) TextRange {
	if less(b.Start, a.Start) {
		a.Start = b.Start
	}
	if less(a.End, b.End) {
		a.End = b.End
	}
	return a
}

var primitiveTypeNames = []string{
	"u8", "u16", "u24", "u32", "u48", "u64", "u96", "u128", "s8", "s16", "s24", "s32", "s48", "s64", "s96", "s128",
	"float", "double", "bool", "char", "char16", "str", "auto", "padding",
}

var patternKeywords = []string{
	"struct", "union", "enum", "bitfield", "fn", "namespace", "using", "import", "as", "if", "else", "while", "for",
	"match", "return", "break", "continue", "try", "catch", "in", "out", "ref", "const", "let", "null", "true", "false",
	"parent", "this", "sizeof", "addressof", "typenameof", "be", "le", "signed", "unsigned",
}

func isPrimitiveType(name string) bool {
	for _, primitive := range primitiveTypeNames {
		if name == primitive {
			return true
		}
	}
	return false
}

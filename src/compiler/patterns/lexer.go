package patterns

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode"
)

type Position struct {
	Path      string
	Line      int
	Character int
}

type Diagnostic struct {
	Position Position
	Message  string
}

func (d Diagnostic) Error() string {
	if d.Position.Path != "" {
		return fmt.Sprintf("%s:%d:%d: %s", d.Position.Path, d.Position.Line+1, d.Position.Character+1, d.Message)
	}
	return fmt.Sprintf("%d:%d: %s", d.Position.Line+1, d.Position.Character+1, d.Message)
}

type tokenKind int

const (
	tokenEOF tokenKind = iota
	tokenIdentifier
	tokenInteger
	tokenFloat
	tokenString
	tokenCharacter
	tokenPunctuation
	tokenDirective
	tokenDocComment
)

type token struct {
	kind     tokenKind
	text     string
	integer  uint64
	wide     *big.Int
	unsigned bool
	position Position
	macros   macros
}

func (t token) is(kind tokenKind, text string) bool {
	return t.kind == kind && t.text == text
}

func tokenize(path string, source string) ([]token, []Diagnostic) {
	lexed, diagnostics := lex(path, source)
	tokens, diagnostics, _ := preprocess(lexed, diagnostics, nil, nil)
	return tokens, diagnostics
}

func lex(path string, source string) ([]token, []Diagnostic) {
	l := &lexer{path: path, source: source}
	for !l.atEnd() {
		l.skipWhitespace()
		if l.atEnd() {
			break
		}
		l.lexToken()
	}
	l.emit(tokenEOF, "")
	return l.tokens, l.diagnostics
}

type macros map[string][]token

type includeHandler func(path string, incoming macros) macros

func preprocess(tokens []token, diagnostics []Diagnostic, incoming macros, include includeHandler) ([]token, []Diagnostic, macros) {
	p := &preprocessor{defines: incoming.clone(), include: include}
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if t.kind == tokenDirective {
			i = p.directive(tokens, i)
			continue
		}
		if p.skipping() {
			continue
		}
		if replacement, isDefined := p.defines[t.text]; t.kind == tokenIdentifier && isDefined {
			p.output = append(p.output, replacement...)
			continue
		}
		if t.is(tokenIdentifier, "import") {
			t.macros = p.defines.clone()
		}
		p.output = append(p.output, t)
	}
	return p.output, append(diagnostics, p.diagnostics...), p.defines
}

func definedMacros(defines map[string]string) macros {
	defined := make(macros, len(defines))
	for name, body := range defines {
		tokens, _ := lex("", body)
		defined[name] = tokens[:len(tokens)-1]
	}
	return defined
}

func (m macros) clone() macros {
	cloned := make(macros, len(m))
	for name, body := range m {
		cloned[name] = body
	}
	return cloned
}

func (m macros) signature() string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	var signature strings.Builder
	for _, name := range names {
		signature.WriteString(name)
		for _, t := range m[name] {
			fmt.Fprintf(&signature, " %d%q", t.kind, t.text)
		}
		signature.WriteByte('\n')
	}
	return signature.String()
}

func splitDirective(text string) (string, string) {
	head := strings.TrimLeft(text, " \t")
	end := strings.IndexAny(head, " \t")
	if end == -1 {
		return head, ""
	}
	return head[:end], strings.TrimSpace(head[end:])
}

type preprocessor struct {
	defines     macros
	include     includeHandler
	conditions  []bool
	output      []token
	diagnostics []Diagnostic
}

func (p *preprocessor) skipping() bool {
	for _, active := range p.conditions {
		if !active {
			return true
		}
	}
	return false
}

func (p *preprocessor) directive(tokens []token, index int) int {
	t := tokens[index]
	name, rest := splitDirective(t.text)
	switch name {
	case "define":
		if p.skipping() {
			return index
		}
		macro, body := splitDirective(rest)
		bodyTokens, diagnostics := lex(t.position.Path, strings.TrimSpace(body))
		p.diagnostics = append(p.diagnostics, diagnostics...)
		p.defines[macro] = bodyTokens[:len(bodyTokens)-1]
	case "ifdef", "ifndef":
		_, defined := p.defines[rest]
		p.conditions = append(p.conditions, defined == (name == "ifdef"))
	case "else":
		if len(p.conditions) > 0 {
			p.conditions[len(p.conditions)-1] = !p.conditions[len(p.conditions)-1]
		}
	case "endif":
		if len(p.conditions) > 0 {
			p.conditions = p.conditions[:len(p.conditions)-1]
		}
	case "error":
		if !p.skipping() {
			p.diagnostics = append(p.diagnostics, Diagnostic{Position: t.position, Message: rest})
		}
	case "include":
		if !p.skipping() {
			p.includeAt(t, rest)
		}
	default:
		if !p.skipping() {
			p.output = append(p.output, t)
		}
	}
	return index
}

func (p *preprocessor) includeAt(t token, spec string) {
	t.macros = p.defines.clone()
	p.output = append(p.output, t)
	if path, isValid := includeTarget(spec); isValid && p.include != nil {
		for name, body := range p.include(path, t.macros) {
			p.defines[name] = body
		}
	}
}

func includeTarget(spec string) (string, bool) {
	if len(spec) >= 2 && (spec[0] == '"' && spec[len(spec)-1] == '"' || spec[0] == '<' && spec[len(spec)-1] == '>') {
		return spec[1 : len(spec)-1], true
	}
	return "", false
}

type lexer struct {
	path        string
	source      string
	offset      int
	line        int
	lineStart   int
	tokens      []token
	diagnostics []Diagnostic
}

func (l *lexer) lexToken() {
	start := l.position()
	c := l.peek()

	switch {
	case c == '/' && l.peekAt(1) == '/':
		l.skipLine()
	case c == '/' && l.peekAt(1) == '*':
		l.lexBlockComment(start)
	case c == '#':
		l.lexDirective(start)
	case isIdentifierStart(c):
		l.lexIdentifier(start)
	case isDigit(c):
		l.lexNumber(start)
	case c == '"':
		l.lexString(start)
	case c == '\'':
		l.lexCharacter(start)
	default:
		l.lexPunctuation(start)
	}
}

func (l *lexer) lexBlockComment(start Position) {
	isDoc := l.peekAt(2) == '*' || l.peekAt(2) == '!'
	bodyStart := l.offset + 2
	if isDoc {
		bodyStart++
	}
	end := strings.Index(l.source[l.offset+2:], "*/")
	if end == -1 {
		l.report(start, "unterminated block comment")
		l.advanceTo(len(l.source))
		return
	}
	bodyEnd := l.offset + 2 + end
	body := l.source[bodyStart:bodyEnd]
	l.advanceTo(bodyEnd + 2)
	if isDoc {
		l.tokens = append(l.tokens, token{kind: tokenDocComment, text: cleanDocComment(body), position: start})
	}
}

func cleanDocComment(body string) string {
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		lines = append(lines, line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func (l *lexer) lexDirective(start Position) {
	lineEnd := strings.IndexByte(l.source[l.offset:], '\n')
	var text string
	if lineEnd == -1 {
		text = l.source[l.offset:]
		l.advanceTo(len(l.source))
	} else {
		text = l.source[l.offset : l.offset+lineEnd]
		l.advanceTo(l.offset + lineEnd)
	}
	l.tokens = append(l.tokens, token{kind: tokenDirective, text: strings.TrimSpace(text[1:]), position: start})
}

func (l *lexer) lexIdentifier(start Position) {
	begin := l.offset
	for !l.atEnd() && isIdentifierPart(l.peek()) {
		l.advance()
	}
	l.tokens = append(l.tokens, token{kind: tokenIdentifier, text: l.source[begin:l.offset], position: start})
}

func (l *lexer) lexNumber(start Position) {
	begin := l.offset
	base := uint64(10)
	if l.peek() == '0' {
		switch l.peekAt(1) {
		case 'x', 'X':
			base = 16
		case 'b', 'B':
			base = 2
		case 'o', 'O':
			base = 8
		}
	}
	if base != 10 {
		l.advance()
		l.advance()
	}

	var value uint64
	wide := new(big.Int)
	bigBase := big.NewInt(int64(base))
	digits := 0
	overflowed := false
	for !l.atEnd() {
		c := l.peek()
		if c == '\'' {
			l.advance()
			continue
		}
		digit, ok := digitValue(c, base)
		if !ok {
			break
		}
		if value > (^uint64(0)-digit)/base {
			overflowed = true
		}
		value = value*base + digit
		wide.Mul(wide, bigBase)
		wide.Add(wide, new(big.Int).SetUint64(digit))
		digits++
		l.advance()
	}

	if base == 10 && !l.atEnd() && (l.peek() == '.' && (isDigit(l.peekAt(1)) || isFloatSuffix(l.peekAt(1))) || l.peek() == 'e' || l.peek() == 'E' || isFloatSuffix(l.peek())) {
		l.lexFloatRest(start, begin)
		return
	}

	unsigned := false
	if !l.atEnd() && (l.peek() == 'U' || l.peek() == 'u') {
		unsigned = true
		l.advance()
	}

	if digits == 0 {
		l.report(start, "malformed number")
	}
	t := token{kind: tokenInteger, text: l.source[begin:l.offset], integer: value, unsigned: unsigned, position: start}
	if overflowed {
		if wide.BitLen() > 128 {
			l.report(start, "integer literal is too large")
		}
		t.wide = wide
	}
	l.tokens = append(l.tokens, t)
}

func (l *lexer) lexFloatRest(start Position, begin int) {
	if l.peek() == '.' {
		l.advance()
		for !l.atEnd() && isDigit(l.peek()) {
			l.advance()
		}
	}
	if !l.atEnd() && (l.peek() == 'e' || l.peek() == 'E') {
		l.advance()
		if !l.atEnd() && (l.peek() == '+' || l.peek() == '-') {
			l.advance()
		}
		for !l.atEnd() && isDigit(l.peek()) {
			l.advance()
		}
	}
	if !l.atEnd() && isFloatSuffix(l.peek()) {
		l.advance()
	}
	l.tokens = append(l.tokens, token{kind: tokenFloat, text: l.source[begin:l.offset], position: start})
}

func isFloatSuffix(c byte) bool {
	return c == 'F' || c == 'f' || c == 'D' || c == 'd'
}

func (l *lexer) lexString(start Position) {
	l.advance()
	var sb strings.Builder
	for {
		if l.atEnd() || l.peek() == '\n' {
			l.report(start, "unterminated string literal")
			break
		}
		c := l.peek()
		l.advance()
		if c == '"' {
			break
		}
		if c == '\\' {
			code, isByte := l.lexEscape(start)
			if isByte {
				sb.WriteByte(byte(code))
			} else {
				sb.WriteRune(code)
			}
			continue
		}
		sb.WriteByte(c)
	}
	l.tokens = append(l.tokens, token{kind: tokenString, text: sb.String(), position: start})
}

func (l *lexer) lexCharacter(start Position) {
	l.advance()
	var value byte
	if !l.atEnd() {
		value = l.peek()
		l.advance()
		if value == '\\' {
			code, _ := l.lexEscape(start)
			if code > 0x7f {
				l.report(start, "character literal does not fit in a byte")
			}
			value = byte(code)
		}
	}
	if l.atEnd() || l.peek() != '\'' {
		l.report(start, "unterminated character literal")
	} else {
		l.advance()
	}
	l.tokens = append(l.tokens, token{kind: tokenCharacter, text: string(value), integer: uint64(value), position: start})
}

func (l *lexer) lexEscape(start Position) (rune, bool) {
	if l.atEnd() {
		return 0, true
	}
	c := l.peek()
	l.advance()
	switch c {
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'a':
		return '\a', true
	case 'b':
		return '\b', true
	case 'f':
		return '\f', true
	case 'v':
		return '\v', true
	case '0':
		return 0, true
	case '\\', '\'', '"':
		return rune(c), true
	case 'x':
		return l.lexEscapeDigits(start, 2), true
	case 'u':
		return l.lexEscapeDigits(start, 4), false
	case 'U':
		return l.lexEscapeDigits(start, 8), false
	}
	l.report(start, fmt.Sprintf("unknown escape sequence \\%c", c))
	return rune(c), true
}

func (l *lexer) lexEscapeDigits(start Position, count int) rune {
	var code rune
	for i := 0; i != count; i++ {
		digit, ok := 0, false
		if !l.atEnd() {
			var value uint64
			value, ok = digitValue(l.peek(), 16)
			digit = int(value)
		}
		if !ok {
			l.report(start, "escape sequence is missing hexadecimal digits")
			return code
		}
		code = code<<4 | rune(digit)
		l.advance()
	}
	if count > 2 && (code > unicode.MaxRune || code >= 0xd800 && code <= 0xdfff) {
		l.report(start, "escape sequence is not a valid code point")
	}
	return code
}

var punctuators = []string{
	"[[", "]]", "...", "::", "<<=", ">>=", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "^^",
	"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
	"{", "}", "[", "]", "(", ")", ";", ":", ",", ".", "=", "@", "*", "+", "-", "/", "%",
	"<", ">", "!", "~", "&", "|", "^", "?", "$",
}

func (l *lexer) lexPunctuation(start Position) {
	rest := l.source[l.offset:]
	for _, p := range punctuators {
		if strings.HasPrefix(rest, p) {
			l.advanceTo(l.offset + len(p))
			l.tokens = append(l.tokens, token{kind: tokenPunctuation, text: p, position: start})
			return
		}
	}
	l.report(start, fmt.Sprintf("unexpected character %q", rest[0]))
	l.advance()
}

func (l *lexer) skipWhitespace() {
	for !l.atEnd() && unicode.IsSpace(rune(l.peek())) {
		l.advance()
	}
}

func (l *lexer) skipLine() {
	for !l.atEnd() && l.peek() != '\n' {
		l.advance()
	}
}

func (l *lexer) emit(kind tokenKind, text string) {
	l.tokens = append(l.tokens, token{kind: kind, text: text, position: l.position()})
}

func (l *lexer) report(position Position, message string) {
	l.diagnostics = append(l.diagnostics, Diagnostic{Position: position, Message: message})
}

func (l *lexer) position() Position {
	return Position{Path: l.path, Line: l.line, Character: l.offset - l.lineStart}
}

func (l *lexer) atEnd() bool {
	return l.offset >= len(l.source)
}

func (l *lexer) peek() byte {
	return l.source[l.offset]
}

func (l *lexer) peekAt(distance int) byte {
	if l.offset+distance >= len(l.source) {
		return 0
	}
	return l.source[l.offset+distance]
}

func (l *lexer) advance() {
	if l.source[l.offset] == '\n' {
		l.line++
		l.lineStart = l.offset + 1
	}
	l.offset++
}

func (l *lexer) advanceTo(offset int) {
	for l.offset < offset {
		l.advance()
	}
}

func digitValue(c byte, base uint64) (uint64, bool) {
	var value uint64
	switch {
	case c >= '0' && c <= '9':
		value = uint64(c - '0')
	case c >= 'a' && c <= 'f':
		value = uint64(c-'a') + 10
	case c >= 'A' && c <= 'F':
		value = uint64(c-'A') + 10
	default:
		return 0, false
	}
	return value, value < base
}

func isIdentifierStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentifierPart(c byte) bool {
	return isIdentifierStart(c) || isDigit(c)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

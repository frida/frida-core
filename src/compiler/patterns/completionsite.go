package patterns

import "strings"

type completionSite int

const (
	siteNothing completionSite = iota
	siteFileStatement
	siteMemberStatement
	siteBitfieldStatement
	siteFunctionStatement
	siteType
	siteBaseType
	siteIntegerType
	siteParameter
	siteValue
	siteArraySize
	siteAttribute
	siteFunctionReference
	siteVisualizer
	siteInlineVisualizer
)

type completionRequest struct {
	site      completionSite
	qualifier string
	locals    []string
}

type lexicalState int

const (
	inCode lexicalState = iota
	inComment
	inString
)

type lexicalScan struct {
	state       lexicalState
	stringStart int
}

type frameKind int

const (
	frameFile frameKind = iota
	frameMembers
	frameBitfield
	frameEnum
	frameFunction
	frameMatch
	frameParentheses
	frameBrackets
	frameAngles
	frameAttributes
)

type completionFrame struct {
	kind      frameKind
	opened    int
	start     int
	owner     string
	argument  int
	locals    []string
	arguments []string
}

type completionWalk struct {
	tokens []token
	frames []*completionFrame
}

func locateCompletion(before string) completionRequest {
	scan := scanLexicalState(before)
	switch scan.state {
	case inComment:
		return completionRequest{site: siteNothing}
	case inString:
		return completionRequest{site: stringSite(before[:scan.stringStart])}
	}
	code, partial := splitPartialWord(before)
	if strings.HasPrefix(strings.TrimSpace(lastLine(code)), "#") {
		return completionRequest{site: siteNothing}
	}
	tokens, _ := tokenize("", code)
	walk := walkCompletionTokens(tokens)
	return completionRequest{site: walk.site(), qualifier: qualifierOf(partial), locals: walk.locals()}
}

func scanLexicalState(text string) lexicalScan {
	i := 0
	for i < len(text) {
		switch {
		case strings.HasPrefix(text[i:], "//"):
			end := strings.IndexByte(text[i:], '\n')
			if end == -1 {
				return lexicalScan{state: inComment}
			}
			i += end + 1
		case strings.HasPrefix(text[i:], "/*"):
			end := strings.Index(text[i+2:], "*/")
			if end == -1 {
				return lexicalScan{state: inComment}
			}
			i += end + 4
		case text[i] == '"' || text[i] == '\'':
			end, closed := quotedEnd(text, i)
			if !closed {
				return lexicalScan{state: inString, stringStart: i}
			}
			i = end
		default:
			i++
		}
	}
	return lexicalScan{state: inCode}
}

func stringSite(before string) completionSite {
	tokens, _ := tokenize("", before)
	walk := walkCompletionTokens(tokens)
	top := walk.top()
	if top.kind != frameParentheses || top.argument != 0 || len(walk.tail()) != 0 || walk.parent().kind != frameAttributes {
		return siteNothing
	}
	switch {
	case top.owner == "hex::visualize":
		return siteVisualizer
	case top.owner == "hex::inline_visualize":
		return siteInlineVisualizer
	case functionAttributes[top.owner]:
		return siteFunctionReference
	}
	return siteNothing
}

func splitPartialWord(text string) (string, string) {
	end := len(text)
	start := end
	for {
		for start > 0 && isIdentifierPart(text[start-1]) {
			start--
		}
		if start < 2 || text[start-2:start] != "::" {
			break
		}
		start -= 2
	}
	return text[:start], text[start:end]
}

func lastLine(text string) string {
	return text[strings.LastIndexByte(text, '\n')+1:]
}

func walkCompletionTokens(tokens []token) *completionWalk {
	w := &completionWalk{frames: []*completionFrame{{kind: frameFile}}}
	for _, t := range tokens {
		if t.kind == tokenEOF || t.kind == tokenDocComment || t.kind == tokenDirective {
			continue
		}
		w.step(t)
	}
	return w
}

func (w *completionWalk) site() completionSite {
	top := w.top()
	tail := w.tail()
	switch top.kind {
	case frameAttributes:
		if len(tail) == 0 {
			return siteAttribute
		}
		return siteNothing
	case frameParentheses:
		return w.parenthesesSite(tail)
	case frameBrackets:
		if w.parent().isBlock() {
			return siteArraySize
		}
		return siteValue
	case frameAngles:
		return siteType
	case frameEnum:
		if len(tail) == 0 || !containsText(tail, "=") {
			return siteNothing
		}
		return siteValue
	}
	return statementSite(top.kind, tail)
}

func qualifierOf(partial string) string {
	end := strings.LastIndex(partial, "::")
	if end == -1 {
		return ""
	}
	return partial[:end+2]
}

func (w *completionWalk) locals() []string {
	var names []string
	for i, frame := range w.frames {
		if frame.kind != frameMembers && frame.kind != frameBitfield && frame.kind != frameFunction {
			continue
		}
		names = append(names, frame.locals...)
		if name := declaredVariable(w.statementOf(i)); name != "" && w.hasAttributesAbove(i) {
			names = append(names, name)
		}
	}
	return names
}

func quotedEnd(text string, start int) (int, bool) {
	quote := text[start]
	i := start + 1
	for i < len(text) {
		switch text[i] {
		case '\\':
			i += 2
		case quote:
			return i + 1, true
		case '\n':
			return i, true
		default:
			i++
		}
	}
	return i, false
}

func (w *completionWalk) step(t token) {
	top := w.top()
	w.tokens = append(w.tokens, t)
	index := len(w.tokens)
	if t.kind != tokenPunctuation {
		return
	}
	switch t.text {
	case "{":
		w.push(&completionFrame{kind: w.blockKind(), start: index, locals: w.pendingArguments()})
	case "}":
		w.unwindToBlock()
		if len(w.frames) > 1 {
			w.pop()
			w.top().start = index
		}
	case ";":
		w.unwindToBlock()
		block := w.top()
		block.noteDeclaration(w.tokens[block.start : index-1])
		block.start = index
	case ",":
		switch top.kind {
		case frameEnum, frameAttributes:
			top.start = index
		case frameParentheses:
			top.noteArgument(w.tokens[top.start : index-1])
			top.argument++
			top.start = index
		}
	case "(":
		w.push(&completionFrame{kind: frameParentheses, start: index, owner: w.parenthesesOwner()})
	case ")":
		if top.kind == frameParentheses {
			top.noteArgument(w.tokens[top.start : index-1])
			w.pop()
			if top.owner == "fn" {
				w.top().arguments = top.arguments
			}
		}
	case "[[":
		w.push(&completionFrame{kind: frameAttributes, start: index})
	case "]]":
		if top.kind == frameAttributes {
			w.pop()
		}
	case "[":
		w.push(&completionFrame{kind: frameBrackets, start: index})
	case "]":
		if top.kind == frameBrackets {
			w.pop()
		}
	case "<":
		if top.isBlock() && isTypeTokens(w.tokens[top.start:index-1]) {
			w.push(&completionFrame{kind: frameAngles, start: index})
		}
	case ">":
		w.closeAngles(1)
	case ">>":
		w.closeAngles(2)
	}
}

func (w *completionWalk) blockKind() frameKind {
	statement := w.tokens[w.top().start : len(w.tokens)-1]
	if len(statement) == 0 {
		return w.top().kind
	}
	switch statement[0].text {
	case "struct", "union":
		return frameMembers
	case "bitfield":
		return frameBitfield
	case "enum":
		return frameEnum
	case "fn":
		return frameFunction
	case "namespace":
		return frameFile
	case "match":
		return frameMatch
	}
	if w.top().kind == frameMatch {
		return w.parent().kind
	}
	return w.top().kind
}

func (w *completionWalk) pendingArguments() []string {
	arguments := w.top().arguments
	w.top().arguments = nil
	return arguments
}

func (w *completionWalk) unwindToBlock() {
	for !w.top().isBlock() {
		w.pop()
	}
}

func (f *completionFrame) noteDeclaration(statement []token) {
	if f.kind == frameBitfield && len(statement) >= 2 && statement[0].kind == tokenIdentifier && statement[1].is(tokenPunctuation, ":") {
		f.locals = append(f.locals, statement[0].text)
		return
	}
	if name := declaredVariable(statement); name != "" {
		f.locals = append(f.locals, name)
	}
}

func (f *completionFrame) noteArgument(argument []token) {
	if f.owner != "fn" {
		return
	}
	if name := declaredVariable(argument); name != "" {
		f.arguments = append(f.arguments, name)
	}
}

func (w *completionWalk) parenthesesOwner() string {
	statement := w.tokens[w.top().start : len(w.tokens)-1]
	if w.top().isBlock() && len(statement) == 2 && statement[0].text == "fn" {
		return "fn"
	}
	return trailingQualifiedName(statement)
}

func (w *completionWalk) closeAngles(count int) {
	for i := 0; i < count && w.top().kind == frameAngles; i++ {
		w.pop()
	}
}

func (w *completionWalk) parenthesesSite(tail []token) completionSite {
	top := w.top()
	if w.parent().kind == frameAttributes && top.argument == 0 {
		if _, isVisualizer := visualizerPresentations[top.owner]; isVisualizer {
			return siteNothing
		}
	}
	if top.owner == "fn" {
		if isParameterPrefix(tail) {
			return siteParameter
		}
		return siteNothing
	}
	return siteValue
}

func statementSite(kind frameKind, tail []token) completionSite {
	if len(tail) == 0 || len(tail) == 1 && tail[0].text == "else" {
		return statementStartSite(kind)
	}
	first := tail[0].text
	last := tail[len(tail)-1]
	switch {
	case len(tail) == 1 && isDeclarationKeyword(first):
		return siteNothing
	case first == "import":
		return siteNothing
	case first == "using" && len(tail) == 3 && last.text == "=":
		return siteType
	case (first == "struct" || first == "union") && last.text == ":":
		return siteBaseType
	case first == "enum" && last.text == ":":
		return siteIntegerType
	case last.text == ":" && isPointerDeclaration(tail[:len(tail)-1]):
		return siteIntegerType
	case last.kind == tokenPunctuation && last.text == "*" && isTypeTokens(tail[:len(tail)-1]):
		return siteNothing
	case isTypeTokens(tail) || isDeclarationTokens(tail):
		return siteNothing
	case last.kind == tokenPunctuation || last.is(tokenIdentifier, "return"):
		return siteValue
	}
	return siteNothing
}

func statementStartSite(kind frameKind) completionSite {
	switch kind {
	case frameMembers:
		return siteMemberStatement
	case frameBitfield:
		return siteBitfieldStatement
	case frameFunction:
		return siteFunctionStatement
	case frameMatch:
		return siteValue
	}
	return siteFileStatement
}

func (w *completionWalk) hasAttributesAbove(frameIndex int) bool {
	for _, frame := range w.frames[frameIndex+1:] {
		if frame.kind == frameAttributes {
			return true
		}
	}
	return false
}

func (w *completionWalk) statementOf(frameIndex int) []token {
	end := len(w.tokens)
	if frameIndex+1 < len(w.frames) {
		end = w.frames[frameIndex+1].opened
	}
	return w.tokens[w.frames[frameIndex].start:end]
}

func (f *completionFrame) isBlock() bool {
	switch f.kind {
	case frameFile, frameMembers, frameBitfield, frameEnum, frameFunction, frameMatch:
		return true
	}
	return false
}

func declaredVariable(statement []token) string {
	end := len(statement)
	for i, t := range statement {
		if t.kind == tokenPunctuation && (t.text == "[" || t.text == "@" || t.text == "=" || t.text == ":" || t.text == "[[") {
			end = i
			break
		}
	}
	if !isDeclarationTokens(statement[:end]) {
		return ""
	}
	return statement[end-1].text
}

func isPointerDeclaration(tokens []token) bool {
	return len(tokens) >= 3 && tokens[len(tokens)-2].is(tokenPunctuation, "*") && isDeclarationTokens(tokens)
}

func isDeclarationTokens(tokens []token) bool {
	if len(tokens) < 2 || tokens[len(tokens)-1].kind != tokenIdentifier {
		return false
	}
	typeTokens := tokens[:len(tokens)-1]
	if last := typeTokens[len(typeTokens)-1]; last.is(tokenPunctuation, "*") {
		typeTokens = typeTokens[:len(typeTokens)-1]
	}
	return isTypeTokens(typeTokens)
}

func isParameterPrefix(tokens []token) bool {
	for _, t := range tokens {
		if !parameterModifiers[t.text] {
			return false
		}
	}
	return true
}

func isTypeTokens(tokens []token) bool {
	for len(tokens) > 0 && (tokens[0].text == "be" || tokens[0].text == "le" || tokens[0].text == "const" || parameterModifiers[tokens[0].text]) {
		tokens = tokens[1:]
	}
	if len(tokens) == 0 || tokens[0].kind != tokenIdentifier || isStatementWord(tokens[0].text) {
		return false
	}
	depth := 0
	expectName := false
	for _, t := range tokens[1:] {
		switch {
		case t.is(tokenPunctuation, "<"):
			depth++
		case t.is(tokenPunctuation, ">"):
			depth--
		case depth > 0:
		case t.is(tokenPunctuation, "::"):
			expectName = true
		case t.kind == tokenIdentifier && expectName:
			expectName = false
		default:
			return false
		}
	}
	return depth == 0 && !expectName
}

func trailingQualifiedName(tokens []token) string {
	start := len(tokens)
	for start > 0 {
		if tokens[start-1].kind != tokenIdentifier {
			break
		}
		start--
		if start == 0 || !tokens[start-1].is(tokenPunctuation, "::") {
			break
		}
		start--
	}
	var name strings.Builder
	for _, t := range tokens[start:] {
		name.WriteString(t.text)
	}
	return name.String()
}

func containsText(tokens []token, text string) bool {
	for _, t := range tokens {
		if t.text == text {
			return true
		}
	}
	return false
}

func isDeclarationKeyword(word string) bool {
	switch word {
	case "struct", "union", "bitfield", "enum", "fn", "namespace", "using":
		return true
	}
	return false
}

func isStatementWord(word string) bool {
	return isDeclarationKeyword(word) || isStatementKeyword(word) && word != "padding" || word == "import" || word == "return"
}

func (w *completionWalk) push(frame *completionFrame) {
	frame.opened = len(w.tokens) - 1
	w.frames = append(w.frames, frame)
}

func (w *completionWalk) pop() {
	w.frames = w.frames[:len(w.frames)-1]
}

func (w *completionWalk) top() *completionFrame {
	return w.frames[len(w.frames)-1]
}

func (w *completionWalk) parent() *completionFrame {
	return w.frames[len(w.frames)-2]
}

func (w *completionWalk) tail() []token {
	return w.tokens[w.top().start:]
}

var parameterModifiers = map[string]bool{"ref": true, "in": true, "out": true, "const": true}

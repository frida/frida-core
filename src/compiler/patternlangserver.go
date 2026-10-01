package main

import (
	"encoding/json"
	"strings"

	"github.com/frida/frida-core-compiler/patterns"
)

type patternRouter struct {
	service        *patterns.LanguageService
	emit           func(text string)
	initializeID   json.RawMessage
	tokenTypes     map[string]int
	tokenModifiers map[string]int
}

type routedMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type documentParams struct {
	TextDocument struct {
		URI  string `json:"uri"`
		Text string `json:"text"`
	} `json:"textDocument"`
	Position       patterns.TextPosition `json:"position"`
	ContentChanges []struct {
		Text string `json:"text"`
	} `json:"contentChanges"`
	Color patterns.Color     `json:"color"`
	Range patterns.TextRange `json:"range"`
}

func newPatternRouter(emit func(text string)) *patternRouter {
	return &patternRouter{service: patterns.NewLanguageService(), emit: emit}
}

func (r *patternRouter) route(text string) bool {
	var message routedMessage
	if json.Unmarshal([]byte(text), &message) != nil {
		return false
	}
	if message.Method == "initialize" {
		r.initializeID = message.ID
		return false
	}
	var params documentParams
	if !strings.HasPrefix(message.Method, "textDocument/") || json.Unmarshal(message.Params, &params) != nil {
		return false
	}
	uri := params.TextDocument.URI
	if !r.service.Handles(uri) {
		return false
	}
	result := r.handle(message.Method, uri, params)
	if message.ID != nil {
		r.respond(message.ID, result)
	}
	return true
}

func (r *patternRouter) handle(method string, uri string, params documentParams) any {
	switch method {
	case "textDocument/didOpen":
		r.service.Open(uri, params.TextDocument.Text)
	case "textDocument/didChange":
		if len(params.ContentChanges) > 0 {
			r.service.Change(uri, params.ContentChanges[len(params.ContentChanges)-1].Text)
		}
	case "textDocument/didClose":
		r.service.Close(uri)
	case "textDocument/diagnostic":
		return map[string]any{"kind": "full", "items": r.service.Diagnostics(uri)}
	case "textDocument/documentSymbol":
		return r.service.Symbols(uri)
	case "textDocument/foldingRange":
		return r.service.FoldingRanges(uri)
	case "textDocument/documentColor":
		return r.service.Colors(uri)
	case "textDocument/colorPresentation":
		return r.service.ColorPresentations(params.Color, params.Range)
	case "textDocument/semanticTokens/full":
		return map[string]any{"data": r.encodeTokens(r.service.SemanticTokens(uri))}
	case "textDocument/completion":
		return r.service.Completions(uri, params.Position)
	case "textDocument/hover":
		if hover := r.service.Hover(uri, params.Position); hover != nil {
			return hover
		}
	case "textDocument/definition":
		if location := r.service.Definition(uri, params.Position); location != nil {
			return location
		}
	}
	return nil
}

func (r *patternRouter) respond(id json.RawMessage, result any) {
	encoded, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	r.emit(string(encoded))
}

func (r *patternRouter) encodeTokens(spans []patterns.SemanticTokenSpan) []int {
	data := []int{}
	line, character := 0, 0
	for _, span := range spans {
		kind, known := r.tokenTypes[span.Type]
		if !known {
			continue
		}
		modifiers := 0
		for _, modifier := range span.Modifiers {
			if bit, known := r.tokenModifiers[modifier]; known {
				modifiers |= 1 << bit
			}
		}
		deltaLine := span.Line - line
		deltaStart := span.Character
		if deltaLine == 0 {
			deltaStart -= character
		}
		data = append(data, deltaLine, deltaStart, span.Length, kind, modifiers)
		line, character = span.Line, span.Character
	}
	return data
}

func (r *patternRouter) adjustResponse(text string) string {
	if r.initializeID == nil {
		return text
	}
	var response struct {
		ID     json.RawMessage `json:"id"`
		Result map[string]any  `json:"result"`
	}
	if json.Unmarshal([]byte(text), &response) != nil || string(response.ID) != string(r.initializeID) || response.Result == nil {
		return text
	}
	r.initializeID = nil
	capabilities, _ := response.Result["capabilities"].(map[string]any)
	if capabilities == nil {
		return text
	}
	r.readLegend(capabilities)
	capabilities["colorProvider"] = true
	var whole map[string]any
	json.Unmarshal([]byte(text), &whole)
	whole["result"] = response.Result
	adjusted, _ := json.Marshal(whole)
	return string(adjusted)
}

func (r *patternRouter) readLegend(capabilities map[string]any) {
	r.tokenTypes = map[string]int{}
	r.tokenModifiers = map[string]int{}
	provider, _ := capabilities["semanticTokensProvider"].(map[string]any)
	legend, _ := provider["legend"].(map[string]any)
	types, _ := legend["tokenTypes"].([]any)
	for index, name := range types {
		if text, isText := name.(string); isText {
			r.tokenTypes[text] = index
		}
	}
	modifiers, _ := legend["tokenModifiers"].([]any)
	for index, name := range modifiers {
		if text, isText := name.(string); isText {
			r.tokenModifiers[text] = index
		}
	}
}

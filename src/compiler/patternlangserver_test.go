package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPatternRouterServesPatternDocuments(t *testing.T) {
	var emitted []string
	router := newPatternRouter(func(text string) { emitted = append(emitted, text) })

	if router.route(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`) {
		t.Fatal("initialize belongs to the TypeScript server")
	}
	if router.route(`{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///a.ts","languageId":"typescript","version":1,"text":""}}}`) {
		t.Fatal("TypeScript documents belong to the TypeScript server")
	}

	opened := `{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///p.hexpat","languageId":"hexpat","version":1,"text":"struct A {\n u8 x;\n};\n"}}}`
	if !router.route(opened) || len(emitted) != 0 {
		t.Fatal("a pattern document should be taken without a reply")
	}
	if !router.route(`{"jsonrpc":"2.0","id":2,"method":"textDocument/documentSymbol","params":{"textDocument":{"uri":"file:///p.hexpat"}}}`) {
		t.Fatal("symbols should be served")
	}
	if len(emitted) != 1 || !strings.Contains(emitted[0], `"id":2`) || !strings.Contains(emitted[0], `"name":"A"`) {
		t.Fatalf("unexpected reply: %v", emitted)
	}
	if !router.route(`{"jsonrpc":"2.0","id":3,"method":"textDocument/hover","params":{"textDocument":{"uri":"file:///p.hexpat"},"position":{"line":1,"character":2}}}`) {
		t.Fatal("hover should be served")
	}
	if !strings.Contains(emitted[1], `"result":null`) {
		t.Fatalf("a miss should reply null: %s", emitted[1])
	}
}

func TestPatternRouterAdjustsInitializeResponse(t *testing.T) {
	router := newPatternRouter(func(string) {})
	router.route(`{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}`)

	untouched := `{"jsonrpc":"2.0","id":8,"result":{"capabilities":{}}}`
	if router.adjustResponse(untouched) != untouched {
		t.Fatal("other responses must pass through")
	}
	adjusted := router.adjustResponse(`{"jsonrpc":"2.0","id":7,"result":{"capabilities":{"semanticTokensProvider":{"legend":{"tokenTypes":["namespace","type","struct"],"tokenModifiers":["declaration"]}}}}}`)
	var response struct {
		Result struct {
			Capabilities map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(adjusted), &response); err != nil || response.Result.Capabilities["colorProvider"] != true {
		t.Fatalf("colours should be advertised: %s", adjusted)
	}
	if router.tokenTypes["struct"] != 2 || router.tokenModifiers["declaration"] != 0 {
		t.Fatalf("legend should be read: %v %v", router.tokenTypes, router.tokenModifiers)
	}

	router.route(`{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///p.hexpat","text":"struct A {\n A b;\n};\n"}}}`)
	var reply string
	router.emit = func(text string) { reply = text }
	router.route(`{"jsonrpc":"2.0","id":9,"method":"textDocument/semanticTokens/full","params":{"textDocument":{"uri":"file:///p.hexpat"}}}`)
	if !strings.Contains(reply, `"data":[0,7,1,2,1,1,1,1,1,0]`) {
		t.Fatalf("unexpected tokens: %s", reply)
	}
}

func TestPatternRouterTakesDefinesFromConfiguration(t *testing.T) {
	var emitted []string
	router := newPatternRouter(func(text string) { emitted = append(emitted, text) })
	if router.route(`{"jsonrpc":"2.0","method":"workspace/didChangeConfiguration","params":{"settings":{"patterns":{"defines":{"LIVE":""}}}}}`) {
		t.Fatal("configuration changes belong to both servers")
	}
	router.route(`{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///p.hexpat","text":"#ifdef LIVE\nstruct A { u8 x; };\n#else\nstruct A { u8 x[missing]; };\n#endif\n"}}}`)
	router.route(`{"jsonrpc":"2.0","id":4,"method":"textDocument/diagnostic","params":{"textDocument":{"uri":"file:///p.hexpat"}}}`)
	if len(emitted) != 1 || !strings.Contains(emitted[0], `"items":[]`) {
		t.Fatalf("the defined branch should be compiled: %v", emitted)
	}
}

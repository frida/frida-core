//go:build frida_compiler_backend_executable

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
)

type BackendRequest struct {
	Type             string         `json:"type"`
	ID               uint           `json:"id,omitempty"`
	SessionID        uint           `json:"session_id,omitempty"`
	ProjectRoot      string         `json:"project_root,omitempty"`
	Entrypoint       string         `json:"entrypoint,omitempty"`
	OutputDir        string         `json:"output_dir,omitempty"`
	OutputFormat     string         `json:"output_format,omitempty"`
	BundleFormat     string         `json:"bundle_format,omitempty"`
	DisableTypeCheck bool           `json:"disable_type_check,omitempty"`
	SourceMap        bool           `json:"source_map,omitempty"`
	Compress         bool           `json:"compress,omitempty"`
	Platform         string         `json:"platform,omitempty"`
	Defines          map[string]any `json:"defines,omitempty"`
	Inputs           map[string]any `json:"inputs,omitempty"`
	Externals        []string       `json:"externals,omitempty"`
	Text             string         `json:"text,omitempty"`
	TypeName         string         `json:"type_name,omitempty"`
	Data             string         `json:"data,omitempty"`
	Address          string         `json:"address,omitempty"`
	Arch             string         `json:"arch,omitempty"`
	Pattern          int            `json:"pattern,omitempty"`
	Function         string         `json:"function,omitempty"`
}

type BackendEvent struct {
	Type      string `json:"type"`
	ID        uint   `json:"id,omitempty"`
	SessionID uint   `json:"session_id,omitempty"`

	Bundle string `json:"bundle,omitempty"`
	Error  string `json:"error,omitempty"`
	Text   string `json:"text,omitempty"`

	Category  string `json:"category,omitempty"`
	Code      int    `json:"code,omitempty"`
	Path      string `json:"path,omitempty"`
	Line      int    `json:"line,omitempty"`
	Character int    `json:"character,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	reader := bufio.NewReaderSize(os.Stdin, 128*1024)
	writer := bufio.NewWriterSize(os.Stdout, 128*1024)

	var outputMu sync.Mutex
	var sessionsMu sync.Mutex
	sessions := make(map[uint]*WatchSession)
	languageServers := make(map[uint]*LanguageServer)

	emit := func(ev BackendEvent) {
		outputMu.Lock()
		defer outputMu.Unlock()

		if err := writeMessage(writer, ev); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}

	startWatch := func(sessionID uint, create func(onDispose SessionDisposeHandler, callbacks BuildEventCallbacks) (*WatchSession, error)) {
		callbacks := BuildEventCallbacks{
			OnStart: func() {
				emit(BackendEvent{
					Type:      "watch:starting",
					SessionID: sessionID,
				})
			},
			OnEnd: func() {
				emit(BackendEvent{
					Type:      "watch:finished",
					SessionID: sessionID,
				})
			},
			OnOutput: func(bundle string) {
				emit(BackendEvent{
					Type:      "watch:output",
					SessionID: sessionID,
					Bundle:    bundle,
				})
			},
			OnDiagnostic: func(d Diagnostic) {
				emit(BackendEvent{
					Type:      "watch:diagnostic",
					SessionID: sessionID,
					Category:  d.category,
					Code:      d.code,
					Path:      d.path,
					Line:      d.line,
					Character: d.character,
					Text:      d.text,
				})
			},
		}

		onDispose := func() {
			sessionsMu.Lock()
			delete(sessions, sessionID)
			sessionsMu.Unlock()
		}

		session, err := create(onDispose, callbacks)
		if err != nil {
			emit(BackendEvent{
				Type:      "watch:ready",
				SessionID: sessionID,
				Error:     err.Error(),
			})
			return
		}

		sessionsMu.Lock()
		sessions[sessionID] = session
		sessionsMu.Unlock()

		emit(BackendEvent{
			Type:      "watch:ready",
			SessionID: sessionID,
		})
	}

	for {
		var req BackendRequest
		if err := readMessage(reader, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		switch req.Type {
		case "build":
			go func(req BackendRequest) {
				options, err := buildOptionsFromRequest(req)
				if err != nil {
					emit(BackendEvent{
						Type:  "build:complete",
						ID:    req.ID,
						Error: err.Error(),
					})
					return
				}

				bundle, err := build(options, makeBuildDiagnosticEmitter(emit, req.ID))

				ev := BackendEvent{
					Type: "build:complete",
					ID:   req.ID,
				}
				if err != nil {
					ev.Error = err.Error()
				} else {
					ev.Bundle = bundle
				}
				emit(ev)
			}(req)

		case "build-library":
			go func(req BackendRequest) {
				err := buildLibrary(libraryOptionsFromRequest(req), makeBuildDiagnosticEmitter(emit, req.ID))

				ev := BackendEvent{
					Type: "build-library:complete",
					ID:   req.ID,
				}
				if err != nil {
					ev.Error = err.Error()
				}
				emit(ev)
			}(req)

		case "watch":
			go func(req BackendRequest) {
				options, err := buildOptionsFromRequest(req)
				if err != nil {
					emit(BackendEvent{
						Type:      "watch:ready",
						SessionID: req.SessionID,
						Error:     err.Error(),
					})
					return
				}

				startWatch(req.SessionID, func(onDispose SessionDisposeHandler, callbacks BuildEventCallbacks) (*WatchSession, error) {
					return NewWatchSession(options, onDispose, callbacks)
				})
			}(req)

		case "watch-library":
			go func(req BackendRequest) {
				startWatch(req.SessionID, func(onDispose SessionDisposeHandler, callbacks BuildEventCallbacks) (*WatchSession, error) {
					return NewLibraryWatchSession(libraryOptionsFromRequest(req), onDispose, callbacks)
				})
			}(req)

		case "dispose":
			sessionsMu.Lock()
			session := sessions[req.SessionID]
			delete(sessions, req.SessionID)
			sessionsMu.Unlock()

			if session != nil {
				session.Dispose()
			}

		case "language-server:open":
			server, err := NewLanguageServer(req.ProjectRoot, func(text string) {
				emit(BackendEvent{
					Type:      "language-server:message",
					SessionID: req.SessionID,
					Text:      text,
				})
			})
			if err != nil {
				emit(BackendEvent{
					Type:      "language-server:ready",
					SessionID: req.SessionID,
					Error:     err.Error(),
				})
				continue
			}

			sessionsMu.Lock()
			languageServers[req.SessionID] = server
			sessionsMu.Unlock()

			emit(BackendEvent{
				Type:      "language-server:ready",
				SessionID: req.SessionID,
			})

		case "language-server:close":
			sessionsMu.Lock()
			server := languageServers[req.SessionID]
			delete(languageServers, req.SessionID)
			sessionsMu.Unlock()

			server.Dispose()

		case "language-server:post":
			sessionsMu.Lock()
			server := languageServers[req.SessionID]
			sessionsMu.Unlock()

			if err := server.Post(req.Text); err != nil {
				emit(BackendEvent{
					Type:      "language-server:error",
					SessionID: req.SessionID,
					Error:     err.Error(),
				})
			}

		case "patterns:describe":
			go func(req BackendRequest) {
				ev := BackendEvent{Type: "patterns:result", ID: req.ID}
				result, err := describePatterns(patternQueryFromRequest(req))
				if err != nil {
					ev.Error = err.Error()
				} else {
					ev.Text = result
				}
				emit(ev)
			}(req)

		case "patterns:decode":
			go func(req BackendRequest) {
				ev := BackendEvent{Type: "patterns:result", ID: req.ID}
				result, err := decodePatternRequest(req)
				if err != nil {
					ev.Error = err.Error()
				} else {
					ev.Text = result
				}
				emit(ev)
			}(req)

		case "patterns:call":
			go func(req BackendRequest) {
				ev := BackendEvent{Type: "patterns:result", ID: req.ID}
				result, err := callPatternFunctionRequest(req)
				if err != nil {
					ev.Error = err.Error()
				} else {
					ev.Text = result
				}
				emit(ev)
			}(req)

		default:
			return fmt.Errorf("unsupported request type: %q", req.Type)
		}
	}
}

func makeBuildDiagnosticEmitter(emit func(ev BackendEvent), id uint) BuildDiagnosticCallback {
	return func(d Diagnostic) {
		emit(BackendEvent{
			Type:      "build:diagnostic",
			ID:        id,
			Category:  d.category,
			Code:      d.code,
			Path:      d.path,
			Line:      d.line,
			Character: d.character,
			Text:      d.text,
		})
	}
}

func decodePatternRequest(req BackendRequest) (string, error) {
	data, address, err := patternRequestData(req)
	if err != nil {
		return "", err
	}
	return decodePattern(patternQueryFromRequest(req), req.TypeName, data, address, req.Inputs)
}

func callPatternFunctionRequest(req BackendRequest) (string, error) {
	data, address, err := patternRequestData(req)
	if err != nil {
		return "", err
	}
	return callPatternFunction(patternQueryFromRequest(req), req.TypeName, data, address, req.Inputs, req.Pattern, req.Function)
}

func patternRequestData(req BackendRequest) ([]byte, uint64, error) {
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return nil, 0, err
	}
	address, err := strconv.ParseUint(req.Address, 0, 64)
	return data, address, err
}

func patternQueryFromRequest(req BackendRequest) patternQuery {
	return patternQuery{projectRoot: req.ProjectRoot, entrypoint: req.Entrypoint, platform: req.Platform, arch: req.Arch,
		defines: req.Defines}
}

func libraryOptionsFromRequest(req BackendRequest) LibraryOptions {
	return LibraryOptions{ProjectRoot: req.ProjectRoot, Entrypoint: req.Entrypoint, OutputDir: req.OutputDir, SourceMap: req.SourceMap}
}

func buildOptionsFromRequest(req BackendRequest) (BuildOptions, error) {
	outputFormat, err := outputFormatFromNick(req.OutputFormat)
	if err != nil {
		return BuildOptions{}, err
	}

	bundleFormat, err := bundleFormatFromNick(req.BundleFormat)
	if err != nil {
		return BuildOptions{}, err
	}

	return BuildOptions{
		ProjectRoot:      req.ProjectRoot,
		Entrypoint:       req.Entrypoint,
		OutputFormat:     outputFormat,
		BundleFormat:     bundleFormat,
		DisableTypeCheck: req.DisableTypeCheck,
		SourceMap:        req.SourceMap,
		Compress:         req.Compress,
		Platform:         platformFromFrida(req.Platform),
		Externals:        req.Externals,
	}, nil
}

func readMessage(r io.Reader, out any) error {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return err
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	return json.Unmarshal(buf, out)
}

func writeMessage(w *bufio.Writer, msg any) error {
	buf, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, uint32(len(buf))); err != nil {
		return err
	}

	if _, err := w.Write(buf); err != nil {
		return err
	}

	return w.Flush()
}

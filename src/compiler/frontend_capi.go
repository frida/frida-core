//go:build !frida_compiler_backend_executable

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef enum {
  FRIDA_OUTPUT_UNESCAPED,
  FRIDA_OUTPUT_HEX_BYTES,
  FRIDA_OUTPUT_C_STRING,
} FridaOutputFormat;

typedef enum {
  FRIDA_BUNDLE_ESM,
  FRIDA_BUNDLE_IIFE,
} FridaBundleFormat;

typedef void (* FridaBuildCompleteFunc) (char * bundle, char * error_message, void * user_data);
typedef void (* FridaWatchReadyFunc) (uintptr_t session_handle, char * error_message, void * user_data);
typedef void (* FridaStartingFunc) (void * user_data);
typedef void (* FridaFinishedFunc) (void * user_data);
typedef void (* FridaOutputFunc) (char * bundle, void * user_data);
typedef void (* FridaDiagnosticFunc) (char * category, int code, char * path, int line, int character, char * text,
    void * user_data);
typedef void (* FridaLanguageServerReadyFunc) (uintptr_t handle, char * error_message, void * user_data);
typedef void (* FridaLanguageServerMessageFunc) (char * text, void * user_data);
typedef void (* FridaPatternResultFunc) (char * json, char * error_message, void * user_data);
typedef void (* FridaDestroyFunc) (void * user_data);

static inline void
invoke_build_complete_func (FridaBuildCompleteFunc fn,
                            char * bundle,
                            char * error_message,
                            void * user_data)
{
  fn (bundle, error_message, user_data);
}

static inline void
invoke_watch_ready_func (FridaWatchReadyFunc fn,
                         uintptr_t session_handle,
                         char * error_message,
                         void * user_data)
{
  fn (session_handle, error_message, user_data);
}

static inline void
invoke_starting_func (FridaStartingFunc fn,
                      void * user_data)
{
  fn (user_data);
}

static inline void
invoke_finished_func (FridaFinishedFunc fn,
                      void * user_data)
{
  fn (user_data);
}

static inline void
invoke_output_func (FridaOutputFunc fn,
                    char * bundle,
                    void * user_data)
{
  fn (bundle, user_data);
}

static inline void
invoke_diagnostic_func (FridaDiagnosticFunc fn,
                        char * category,
                        int code,
                        char * path,
                        int line,
                        int character,
                        char * text,
                        void * user_data)
{
  fn (category, code, path, line, character, text, user_data);
}

static inline void
invoke_language_server_ready_func (FridaLanguageServerReadyFunc fn,
                                   uintptr_t handle,
                                   char * error_message,
                                   void * user_data)
{
  fn (handle, error_message, user_data);
}

static inline void
invoke_language_server_message_func (FridaLanguageServerMessageFunc fn,
                                     char * text,
                                     void * user_data)
{
  fn (text, user_data);
}

static inline void
invoke_pattern_result_func (FridaPatternResultFunc fn,
                            char * json,
                            char * error_message,
                            void * user_data)
{
  fn (json, error_message, user_data);
}

static inline void
invoke_destroy_func (FridaDestroyFunc fn,
                     void * user_data)
{
  fn (user_data);
}
*/
import "C"

import (
	"encoding/json"
	"runtime/cgo"
	"unsafe"
)

//export _frida_compiler_backend_build
func _frida_compiler_backend_build(cProjectRoot, cEntrypoint *C.char, outputFormat C.FridaOutputFormat, bundleFormat C.FridaBundleFormat,
	disableTypeCheck, sourceMap, compress uintptr, cPlatform *C.char, cExternals **C.char, numExternals C.int,
	onDiagnosticFn C.FridaDiagnosticFunc, onDiagnosticData unsafe.Pointer, onCompleteFn C.FridaBuildCompleteFunc,
	onCompleteData unsafe.Pointer, onCompleteDataDestroy C.FridaDestroyFunc) {
	options := BuildOptions{
		ProjectRoot:      C.GoString(cProjectRoot),
		Entrypoint:       C.GoString(cEntrypoint),
		OutputFormat:     OutputFormat(outputFormat),
		BundleFormat:     BundleFormat(bundleFormat),
		DisableTypeCheck: disableTypeCheck != 0,
		SourceMap:        sourceMap != 0,
		Compress:         compress != 0,
		Platform:         platformFromFrida(C.GoString(cPlatform)),
		Externals:        parseCExternals(cExternals, numExternals),
	}
	onDiagnostic := NewCDelegate(onDiagnosticFn, onDiagnosticData, nil)
	onComplete := NewCDelegate(onCompleteFn, onCompleteData, onCompleteDataDestroy)

	go func() {
		defer onComplete.Dispose()
		defer onDiagnostic.Dispose()

		onDiagnostic := makeCBuildDiagnosticCallback(onDiagnostic)

		bundle, err := build(options, onDiagnostic)

		var cBundle, cErrorMessage *C.char
		if err == nil {
			cBundle = C.CString(bundle)
		} else {
			cErrorMessage = C.CString(err.Error())
		}
		C.invoke_build_complete_func(onComplete.Func, cBundle, cErrorMessage, onComplete.Data)
		C.free(unsafe.Pointer(cBundle))
		C.free(unsafe.Pointer(cErrorMessage))
	}()
}

//export _frida_compiler_backend_build_library
func _frida_compiler_backend_build_library(cProjectRoot, cEntrypoint, cOutputDir *C.char, sourceMap uintptr,
	onDiagnosticFn C.FridaDiagnosticFunc, onDiagnosticData unsafe.Pointer, onCompleteFn C.FridaBuildCompleteFunc,
	onCompleteData unsafe.Pointer, onCompleteDataDestroy C.FridaDestroyFunc) {
	options := LibraryOptions{
		ProjectRoot: C.GoString(cProjectRoot),
		Entrypoint:  C.GoString(cEntrypoint),
		OutputDir:   C.GoString(cOutputDir),
		SourceMap:   sourceMap != 0,
	}
	onDiagnostic := NewCDelegate(onDiagnosticFn, onDiagnosticData, nil)
	onComplete := NewCDelegate(onCompleteFn, onCompleteData, onCompleteDataDestroy)

	go func() {
		defer onComplete.Dispose()
		defer onDiagnostic.Dispose()

		err := buildLibrary(options, makeCBuildDiagnosticCallback(onDiagnostic))

		var cErrorMessage *C.char
		if err != nil {
			cErrorMessage = C.CString(err.Error())
		}
		C.invoke_build_complete_func(onComplete.Func, nil, cErrorMessage, onComplete.Data)
		C.free(unsafe.Pointer(cErrorMessage))
	}()
}

//export _frida_compiler_backend_watch
func _frida_compiler_backend_watch(cProjectRoot, cEntrypoint *C.char, outputFormat C.FridaOutputFormat, bundleFormat C.FridaBundleFormat,
	disableTypeCheck, sourceMap, compress uintptr, cPlatform *C.char, cExternals **C.char, numExternals C.int,
	onStartingFn C.FridaStartingFunc, onStartingData unsafe.Pointer,
	onFinishedFn C.FridaFinishedFunc, onFinishedData unsafe.Pointer,
	onOutputFn C.FridaOutputFunc, onOutputData unsafe.Pointer,
	onDiagnosticFn C.FridaDiagnosticFunc, onDiagnosticData unsafe.Pointer,
	onReadyFn C.FridaWatchReadyFunc, onReadyData unsafe.Pointer, onReadyDataDestroy C.FridaDestroyFunc) {
	options := BuildOptions{
		ProjectRoot:      C.GoString(cProjectRoot),
		Entrypoint:       C.GoString(cEntrypoint),
		OutputFormat:     OutputFormat(outputFormat),
		BundleFormat:     BundleFormat(bundleFormat),
		DisableTypeCheck: disableTypeCheck != 0,
		SourceMap:        sourceMap != 0,
		Compress:         compress != 0,
		Platform:         platformFromFrida(C.GoString(cPlatform)),
		Externals:        parseCExternals(cExternals, numExternals),
	}
	onStarting := NewCDelegate(onStartingFn, onStartingData, nil)
	onFinished := NewCDelegate(onFinishedFn, onFinishedData, nil)
	onOutput := NewCDelegate(onOutputFn, onOutputData, nil)
	onDiagnostic := NewCDelegate(onDiagnosticFn, onDiagnosticData, nil)
	onReady := NewCDelegate(onReadyFn, onReadyData, onReadyDataDestroy)

	go func() {
		defer onReady.Dispose()

		onDispose := func() {
			onStarting.Dispose()
			onFinished.Dispose()
			onOutput.Dispose()
			onDiagnostic.Dispose()
		}

		callbacks := BuildEventCallbacks{
			OnStart: func() {
				C.invoke_starting_func(onStarting.Func, onStarting.Data)
			},
			OnEnd: func() {
				C.invoke_finished_func(onFinished.Func, onFinished.Data)
			},
			OnOutput: func(bundle string) {
				cBundle := C.CString(bundle)
				C.invoke_output_func(onOutput.Func, cBundle, onOutput.Data)
				C.free(unsafe.Pointer(cBundle))
			},
			OnDiagnostic: makeCBuildDiagnosticCallback(onDiagnostic),
		}

		session, err := NewWatchSession(options, onDispose, callbacks)

		var cSession C.uintptr_t
		var cErrorMessage *C.char
		if err == nil {
			cSession = C.uintptr_t(cgo.NewHandle(session))
		} else {
			cErrorMessage = C.CString(err.Error())
		}
		C.invoke_watch_ready_func(onReady.Func, cSession, cErrorMessage, onReady.Data)
		C.free(unsafe.Pointer(cErrorMessage))
	}()
}

//export _frida_compiler_backend_watch_library
func _frida_compiler_backend_watch_library(cProjectRoot, cEntrypoint, cOutputDir *C.char, sourceMap uintptr,
	onStartingFn C.FridaStartingFunc, onStartingData unsafe.Pointer,
	onFinishedFn C.FridaFinishedFunc, onFinishedData unsafe.Pointer,
	onDiagnosticFn C.FridaDiagnosticFunc, onDiagnosticData unsafe.Pointer,
	onReadyFn C.FridaWatchReadyFunc, onReadyData unsafe.Pointer, onReadyDataDestroy C.FridaDestroyFunc) {
	options := LibraryOptions{
		ProjectRoot: C.GoString(cProjectRoot),
		Entrypoint:  C.GoString(cEntrypoint),
		OutputDir:   C.GoString(cOutputDir),
		SourceMap:   sourceMap != 0,
	}
	onStarting := NewCDelegate(onStartingFn, onStartingData, nil)
	onFinished := NewCDelegate(onFinishedFn, onFinishedData, nil)
	onDiagnostic := NewCDelegate(onDiagnosticFn, onDiagnosticData, nil)
	onReady := NewCDelegate(onReadyFn, onReadyData, onReadyDataDestroy)

	go func() {
		defer onReady.Dispose()

		onDispose := func() {
			onStarting.Dispose()
			onFinished.Dispose()
			onDiagnostic.Dispose()
		}

		callbacks := BuildEventCallbacks{
			OnStart: func() {
				C.invoke_starting_func(onStarting.Func, onStarting.Data)
			},
			OnEnd: func() {
				C.invoke_finished_func(onFinished.Func, onFinished.Data)
			},
			OnDiagnostic: makeCBuildDiagnosticCallback(onDiagnostic),
		}

		session, err := NewLibraryWatchSession(options, onDispose, callbacks)

		var cSession C.uintptr_t
		var cErrorMessage *C.char
		if err == nil {
			cSession = C.uintptr_t(cgo.NewHandle(session))
		} else {
			cErrorMessage = C.CString(err.Error())
		}
		C.invoke_watch_ready_func(onReady.Func, cSession, cErrorMessage, onReady.Data)
		C.free(unsafe.Pointer(cErrorMessage))
	}()
}

//export _frida_compiler_backend_watch_session_dispose
func _frida_compiler_backend_watch_session_dispose(h uintptr) {
	handle := cgo.Handle(h)
	session := handle.Value().(*WatchSession)
	session.Dispose()
	handle.Delete()
}

//export _frida_compiler_backend_language_server_open
func _frida_compiler_backend_language_server_open(cProjectRoot *C.char,
	onMessageFn C.FridaLanguageServerMessageFunc, onMessageData unsafe.Pointer,
	onReadyFn C.FridaLanguageServerReadyFunc, onReadyData unsafe.Pointer, onReadyDataDestroy C.FridaDestroyFunc) {
	projectRoot := C.GoString(cProjectRoot)
	onMessage := NewCDelegate(onMessageFn, onMessageData, nil)
	onReady := NewCDelegate(onReadyFn, onReadyData, onReadyDataDestroy)

	go func() {
		defer onReady.Dispose()

		server, err := NewLanguageServer(projectRoot, func(text string) {
			cText := C.CString(text)
			C.invoke_language_server_message_func(onMessage.Func, cText, onMessage.Data)
			C.free(unsafe.Pointer(cText))
		})

		var cHandle C.uintptr_t
		var cErrorMessage *C.char
		if err == nil {
			cHandle = C.uintptr_t(cgo.NewHandle(&languageServerHandle{server, onMessage}))
		} else {
			onMessage.Dispose()
			cErrorMessage = C.CString(err.Error())
		}
		C.invoke_language_server_ready_func(onReady.Func, cHandle, cErrorMessage, onReady.Data)
		C.free(unsafe.Pointer(cErrorMessage))
	}()
}

//export _frida_compiler_backend_language_server_close
func _frida_compiler_backend_language_server_close(h uintptr) {
	handle := cgo.Handle(h)
	entry := handle.Value().(*languageServerHandle)
	entry.server.Dispose()
	entry.onMessage.Dispose()
	handle.Delete()
}

//export _frida_compiler_backend_language_server_post
func _frida_compiler_backend_language_server_post(h uintptr, cText *C.char) *C.char {
	handle := cgo.Handle(h).Value().(*languageServerHandle)
	if err := handle.server.Post(C.GoString(cText)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export _frida_compiler_backend_patterns_describe
func _frida_compiler_backend_patterns_describe(cProjectRoot, cEntrypoint, cPlatform, cArch *C.char,
	onResultFn C.FridaPatternResultFunc, onResultData unsafe.Pointer, onResultDataDestroy C.FridaDestroyFunc) {
	query := patternQueryFromC(cProjectRoot, cEntrypoint, cPlatform, cArch)
	onResult := NewCDelegate(onResultFn, onResultData, onResultDataDestroy)

	go func() {
		defer onResult.Dispose()

		result, err := describePatterns(query)
		invokePatternResultFunc(onResult, result, err)
	}()
}

//export _frida_compiler_backend_patterns_decode
func _frida_compiler_backend_patterns_decode(cProjectRoot, cEntrypoint, cTypeName *C.char, cData *C.uint8_t, dataLength C.int,
	address C.uint64_t, cPlatform, cArch, cInputs *C.char, onResultFn C.FridaPatternResultFunc, onResultData unsafe.Pointer,
	onResultDataDestroy C.FridaDestroyFunc) {
	query := patternQueryFromC(cProjectRoot, cEntrypoint, cPlatform, cArch)
	typeName := C.GoString(cTypeName)
	data := C.GoBytes(unsafe.Pointer(cData), dataLength)
	inputs := parsePatternInputs(cInputs)
	onResult := NewCDelegate(onResultFn, onResultData, onResultDataDestroy)

	go func() {
		defer onResult.Dispose()

		result, err := decodePattern(query, typeName, data, uint64(address), inputs)
		invokePatternResultFunc(onResult, result, err)
	}()
}

//export _frida_compiler_backend_patterns_call
func _frida_compiler_backend_patterns_call(cProjectRoot, cEntrypoint, cTypeName *C.char, cData *C.uint8_t, dataLength C.int,
	address C.uint64_t, cPlatform, cArch, cInputs *C.char, patternID C.uint, cFunctionName *C.char,
	onResultFn C.FridaPatternResultFunc, onResultData unsafe.Pointer, onResultDataDestroy C.FridaDestroyFunc) {
	query := patternQueryFromC(cProjectRoot, cEntrypoint, cPlatform, cArch)
	typeName := C.GoString(cTypeName)
	data := C.GoBytes(unsafe.Pointer(cData), dataLength)
	inputs := parsePatternInputs(cInputs)
	functionName := C.GoString(cFunctionName)
	onResult := NewCDelegate(onResultFn, onResultData, onResultDataDestroy)

	go func() {
		defer onResult.Dispose()

		result, err := callPatternFunction(query, typeName, data, uint64(address), inputs, int(patternID), functionName)
		invokePatternResultFunc(onResult, result, err)
	}()
}

func patternQueryFromC(cProjectRoot, cEntrypoint, cPlatform, cArch *C.char) patternQuery {
	return patternQuery{
		projectRoot: C.GoString(cProjectRoot),
		entrypoint:  C.GoString(cEntrypoint),
		platform:    C.GoString(cPlatform),
		arch:        C.GoString(cArch),
	}
}

func parsePatternInputs(cInputs *C.char) map[string]any {
	if cInputs == nil {
		return nil
	}
	var inputs map[string]any
	if err := json.Unmarshal([]byte(C.GoString(cInputs)), &inputs); err != nil {
		return nil
	}
	return inputs
}

func invokePatternResultFunc(onResult *CDelegate[C.FridaPatternResultFunc], result string, err error) {
	var cResult, cErrorMessage *C.char
	if err == nil {
		cResult = C.CString(result)
	} else {
		cErrorMessage = C.CString(err.Error())
	}
	C.invoke_pattern_result_func(onResult.Func, cResult, cErrorMessage, onResult.Data)
	C.free(unsafe.Pointer(cResult))
	C.free(unsafe.Pointer(cErrorMessage))
}

type languageServerHandle struct {
	server    *LanguageServer
	onMessage *CDelegate[C.FridaLanguageServerMessageFunc]
}

func parseCExternals(cExternals **C.char, numExternals C.int) []string {
	if numExternals == 0 {
		return nil
	}

	n := int(numExternals)
	cArray := (*[1 << 20]*C.char)(unsafe.Pointer(cExternals))[:n:n]

	externals := make([]string, n)
	for i := 0; i < n; i++ {
		externals[i] = C.GoString(cArray[i])
	}

	return externals
}

func makeCBuildDiagnosticCallback(onDiagnostic *CDelegate[C.FridaDiagnosticFunc]) BuildDiagnosticCallback {
	return func(d Diagnostic) {
		var cPath *C.char
		if d.path != "" {
			cPath = C.CString(d.path)
		}
		cCategory := C.CString(d.category)
		cText := C.CString(d.text)

		C.invoke_diagnostic_func(onDiagnostic.Func, cCategory, C.int(d.code), cPath, C.int(d.line),
			C.int(d.character), cText, onDiagnostic.Data)

		C.free(unsafe.Pointer(cCategory))
		C.free(unsafe.Pointer(cPath))
		C.free(unsafe.Pointer(cText))
	}
}

type CDelegate[F any] struct {
	Func        F
	null        F
	Data        unsafe.Pointer
	dataDestroy C.FridaDestroyFunc
}

func NewCDelegate[F any](function F, data unsafe.Pointer, dataDestroy C.FridaDestroyFunc) *CDelegate[F] {
	return &CDelegate[F]{Func: function, Data: data, dataDestroy: dataDestroy}
}

func (d *CDelegate[F]) Dispose() {
	if d.dataDestroy != nil {
		C.invoke_destroy_func(d.dataDestroy, d.Data)
	}
	d.Func = d.null
	d.Data = nil
	d.dataDestroy = nil
}

func main() {}

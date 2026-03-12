//go:build !frida_compiler_backend_executable

package main

/*
#include <stdint.h>

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
invoke_destroy_func (FridaDestroyFunc fn,
                     void * user_data)
{
  fn (user_data);
}
*/
import "C"

import (
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
				C.invoke_output_func(onOutput.Func, C.CString(bundle), onOutput.Data)
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
	}()
}

//export _frida_compiler_backend_watch_session_dispose
func _frida_compiler_backend_watch_session_dispose(h uintptr) {
	handle := cgo.Handle(h)
	session := handle.Value().(*WatchSession)
	session.Dispose()
	handle.Delete()
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

		C.invoke_diagnostic_func(onDiagnostic.Func, C.CString(d.category), C.int(d.code), cPath, C.int(d.line),
			C.int(d.character), C.CString(d.text), onDiagnostic.Data)
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

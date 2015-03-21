#define DEBUG_HEAP_LEAKS 0

#include "frida-agent.h"

#include <gio/gio.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
# include <crtdbg.h>
# include <process.h>
#else
# include <pthread.h>
#endif

void
frida_agent_environment_init (void)
{
  GMemVTable mem_vtable = {
    gum_malloc,
    gum_realloc,
    gum_free,
    gum_calloc,
    gum_malloc,
    gum_realloc
  };

#if defined (G_OS_WIN32) && DEBUG_HEAP_LEAKS
  int tmp_flag;

  /*_CrtSetBreakAlloc (1337);*/

  _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

  tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

  tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
  tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
  tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

  _CrtSetDbgFlag (tmp_flag);
#endif

  gum_memory_init ();
  g_mem_set_vtable (&mem_vtable);
  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
#if DEBUG_HEAP_LEAKS
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
  glib_init ();
  gio_init ();
  gum_init ();
}

void
frida_agent_environment_deinit (void)
{
  gum_deinit ();
  gio_deinit ();
  glib_deinit ();
  gum_memory_deinit ();
}

typedef struct _FridaAutoInterceptContext FridaAutoInterceptContext;

#ifdef G_OS_WIN32
typedef unsigned NativeThreadFuncReturnType;
# define NATIVE_THREAD_FUNC_API __stdcall
#else
typedef void * NativeThreadFuncReturnType;
# define NATIVE_THREAD_FUNC_API
#endif
typedef NativeThreadFuncReturnType (NATIVE_THREAD_FUNC_API * NativeThreadFunc) (void * data);

struct _FridaAutoInterceptContext
{
  GumInterceptor * interceptor;
  NativeThreadFunc thread_func;
  void * thread_data;
};

static NativeThreadFuncReturnType frida_agent_auto_ignorer_thread_create_proxy (void * data);

void *
frida_agent_auto_ignorer_get_address_of_thread_create_func (void)
{
#ifdef G_OS_WIN32
  return GUM_FUNCPTR_TO_POINTER (_beginthreadex);
#else
  return GUM_FUNCPTR_TO_POINTER (pthread_create);
#endif
}

void
frida_agent_auto_ignorer_intercept_thread_creation (FridaAgentAutoIgnorer * self,
    GumInvocationContext * ic)
{
  NativeThreadFunc thread_func;

  thread_func = GUM_POINTER_TO_FUNCPTR (NativeThreadFunc, gum_invocation_context_get_nth_argument (ic, 2));
  if (GUM_MEMORY_RANGE_INCLUDES (&self->agent_range, GUM_ADDRESS (thread_func)))
  {
    FridaAutoInterceptContext * ctx;

    ctx = g_slice_new (FridaAutoInterceptContext);
    ctx->interceptor = g_object_ref (self->interceptor);
    ctx->thread_func = thread_func;
    ctx->thread_data = gum_invocation_context_get_nth_argument (ic, 3);
    gum_invocation_context_replace_nth_argument (ic, 2, GUM_FUNCPTR_TO_POINTER (frida_agent_auto_ignorer_thread_create_proxy));
    gum_invocation_context_replace_nth_argument (ic, 3, ctx);
  }
}

static NativeThreadFuncReturnType
frida_agent_auto_ignorer_thread_create_proxy (void * data)
{
  GumThreadId current_thread_id;
  FridaAutoInterceptContext * ctx = data;
  NativeThreadFuncReturnType result;

  current_thread_id = gum_process_get_current_thread_id ();

  gum_script_ignore (current_thread_id);

  result = ctx->thread_func (ctx->thread_data);

  g_object_unref (ctx->interceptor);
  g_slice_free (FridaAutoInterceptContext, ctx);

  gum_script_unignore (current_thread_id);

  return result;
}

#define DEBUG_HEAP_LEAKS 0

#include "frida-agent.h"

#include <gio/gio.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
#include <crtdbg.h>
#endif

void
frida_agent_environment_init (void)
{
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

  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
#if DEBUG_HEAP_LEAKS
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
#ifdef _DEBUG
  g_thread_init_with_errorcheck_mutexes (NULL);
#else
  g_thread_init (NULL);
#endif
  g_type_init ();
  gum_init_with_features ((GumFeatureFlags)
      (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP));
}

void
frida_agent_environment_deinit (void)
{
  g_io_deinit ();

  gum_deinit ();
  g_type_deinit ();
  g_thread_deinit ();
  g_mem_deinit ();
}

typedef struct _FridaAutoInterceptContext FridaAutoInterceptContext;

struct _FridaAutoInterceptContext
{
  GumInterceptor * interceptor;
  GThreadFunc thread_func;
  gpointer thread_data;
};

static gpointer frida_agent_auto_ignorer_thread_create_proxy (gpointer data);

void *
frida_agent_auto_ignorer_get_address_of_g_thread_create_full (void)
{
  return g_thread_create_full;
}

void
frida_agent_auto_ignorer_intercept_thread_creation (FridaAgentAutoIgnorer * self,
    GumInvocationContext * ic)
{
  FridaAutoInterceptContext * ctx;

  ctx = g_slice_new (FridaAutoInterceptContext);
  ctx->interceptor = g_object_ref (self->interceptor);
  ctx->thread_func = GUM_POINTER_TO_FUNCPTR (GThreadFunc,
      gum_invocation_context_get_nth_argument (ic, 0));
  ctx->thread_data = gum_invocation_context_get_nth_argument (ic, 1);
  gum_invocation_context_replace_nth_argument (ic, 0,
      GUM_FUNCPTR_TO_POINTER (frida_agent_auto_ignorer_thread_create_proxy));
  gum_invocation_context_replace_nth_argument (ic, 1, ctx);
}

static gpointer
frida_agent_auto_ignorer_thread_create_proxy (gpointer data)
{
  FridaAutoInterceptContext * ctx = data;
  gpointer result;

  gum_interceptor_ignore_current_thread (ctx->interceptor);
  result = ctx->thread_func (ctx->thread_data);
  gum_interceptor_unignore_current_thread (ctx->interceptor);

  g_object_unref (ctx->interceptor);
  g_slice_free (FridaAutoInterceptContext, ctx);

  return result;
}

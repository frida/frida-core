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

#ifdef HAVE_ANDROID
# include <android/log.h>
#else
# include <stdio.h>
#endif

static void frida_agent_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data);

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
#if DEBUG_HEAP_LEAKS
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
  glib_init ();
  g_log_set_default_handler (frida_agent_on_log_message, NULL);
  g_log_set_always_fatal (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING);
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

static void
frida_agent_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data)
{
#ifdef HAVE_ANDROID
  int priority;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
    case G_LOG_LEVEL_CRITICAL:
    case G_LOG_LEVEL_WARNING:
      priority = ANDROID_LOG_FATAL;
      break;
    case G_LOG_LEVEL_MESSAGE:
    case G_LOG_LEVEL_INFO:
      priority = ANDROID_LOG_INFO;
      break;
    case G_LOG_LEVEL_DEBUG:
      priority = ANDROID_LOG_DEBUG;
      break;
    default:
      g_assert_not_reached ();
  }

  __android_log_write (priority, log_domain, message);
#else
  FILE * file;
  const gchar * severity;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
      file = stderr;
      severity = "ERROR";
      break;
    case G_LOG_LEVEL_CRITICAL:
      file = stderr;
      severity = "CRITICAL";
      break;
    case G_LOG_LEVEL_WARNING:
      file = stderr;
      severity = "WARNING";
      break;
    case G_LOG_LEVEL_MESSAGE:
      file = stderr;
      severity = "MESSAGE";
      break;
    case G_LOG_LEVEL_INFO:
      file = stdout;
      severity = "INFO";
      break;
    case G_LOG_LEVEL_DEBUG:
      file = stdout;
      severity = "DEBUG";
      break;
    default:
      g_assert_not_reached ();
  }

  fprintf (file, "[%s %s] %s\n", log_domain, severity, message);
  fflush (file);
#endif
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

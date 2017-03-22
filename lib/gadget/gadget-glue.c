#include "frida-gadget.h"

#ifndef G_OS_WIN32
# include "frida-interfaces.h"
#endif

#ifdef G_OS_WIN32
# include <process.h>
# define VC_EXTRALEAN
# include <windows.h>
# undef VC_EXTRALEAN
#else
# include <signal.h>
# include <unistd.h>
#endif

#ifdef HAVE_DARWIN
# include <CoreFoundation/CoreFoundation.h>
# include <dlfcn.h>

typedef struct _FridaCFApi FridaCFApi;

struct _FridaCFApi
{
  const CFAllocatorRef * kCFAllocatorDefault;
  const CFStringRef * kCFRunLoopCommonModes;

  void (* CFRelease) (CFTypeRef cf);

  CFRunLoopRef (* CFRunLoopGetMain) (void);
  void (* CFRunLoopRun) (void);
  void (* CFRunLoopStop) (CFRunLoopRef loop);
  CFRunLoopTimerRef (* CFRunLoopTimerCreate) (CFAllocatorRef allocator, CFAbsoluteTime fire_date, CFTimeInterval interval, CFOptionFlags flags, CFIndex order, CFRunLoopTimerCallBack callout, CFRunLoopTimerContext * context);
  void (* CFRunLoopAddTimer) (CFRunLoopRef loop, CFRunLoopTimerRef timer, CFStringRef mode);
  void (* CFRunLoopTimerInvalidate) (CFRunLoopTimerRef timer);
};

static void * frida_gadget_wait_for_permission_to_resume_then_stop_loop (void * user_data);
static void on_keep_alive_timer_fire (CFRunLoopTimerRef timer, void * info);

static FridaCFApi * frida_cf_api_try_get (void);

#endif

static gpointer run_main_loop (gpointer data);
static gboolean stop_main_loop (gpointer data);

static GThread * main_thread;
static GMainLoop * main_loop;
static GMainContext * main_context;

#ifdef G_OS_WIN32

BOOL WINAPI
DllMain (HINSTANCE instance, DWORD reason, LPVOID reserved)
{
  (void) instance;
  (void) reserved;

  switch (reason)
  {
    case DLL_PROCESS_ATTACH:
      frida_gadget_load ();
      break;
    case DLL_PROCESS_DETACH:
      frida_gadget_unload ();
      break;
    default:
      break;
  }

  return TRUE;
}

guint
_frida_gadget_getpid (void)
{
  return GetCurrentProcessId ();
}

void
_frida_gadget_kill (guint pid)
{
  HANDLE process;

  process = OpenProcess (PROCESS_TERMINATE, FALSE, pid);
  if (process == NULL)
    return;

  TerminateProcess (process, 1);

  CloseHandle (process);
}

#else

__attribute__ ((constructor)) static void
on_load (void)
{
  frida_gadget_load ();

#ifdef HAVE_DARWIN
  FridaCFApi * api = frida_cf_api_try_get ();
  if (api != NULL)
  {
    CFRunLoopRef loop;
    CFAbsoluteTime distant_future;
    CFRunLoopTimerRef timer;
    pthread_t thread;

    loop = api->CFRunLoopGetMain ();

    distant_future = DBL_MAX;
    timer = api->CFRunLoopTimerCreate (*(api->kCFAllocatorDefault), distant_future, 0, 0, 0, on_keep_alive_timer_fire, NULL);
    api->CFRunLoopAddTimer (loop, timer, *(api->kCFRunLoopCommonModes));

    pthread_create (&thread, NULL, frida_gadget_wait_for_permission_to_resume_then_stop_loop, loop);
    pthread_detach (thread);

    api->CFRunLoopRun ();

    api->CFRunLoopTimerInvalidate (timer);
    api->CFRelease (timer);
  }
  else
#endif
  {
    frida_gadget_wait_for_permission_to_resume ();
  }
}

__attribute__ ((destructor)) static void
on_unload (void)
{
  frida_gadget_unload ();
}

guint
_frida_gadget_getpid (void)
{
  return getpid ();
}

void
_frida_gadget_kill (guint pid)
{
  kill (pid, SIGKILL);
}

#endif

#ifdef HAVE_DARWIN

static void *
frida_gadget_wait_for_permission_to_resume_then_stop_loop (void * user_data)
{
  CFRunLoopRef loop = user_data;

  frida_gadget_wait_for_permission_to_resume ();

  frida_cf_api_try_get ()->CFRunLoopStop (loop);

  return NULL;
}

static void
on_keep_alive_timer_fire (CFRunLoopTimerRef timer, void * info)
{
}

#endif

void
frida_gadget_environment_init (void)
{
  gum_init_embedded ();

  g_thread_set_garbage_handler (frida_gadget_on_pending_garbage, NULL);

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

  main_context = g_main_context_ref (g_main_context_default ());
  main_loop = g_main_loop_new (main_context, FALSE);
  main_thread = g_thread_new ("gadget-main-loop", run_main_loop, NULL);
}

void
frida_gadget_environment_deinit (void)
{
  GSource * source;

  g_assert (main_loop != NULL);

  source = g_idle_source_new ();
  g_source_set_priority (source, G_PRIORITY_LOW);
  g_source_set_callback (source, stop_main_loop, NULL, NULL);
  g_source_attach (source, main_context);
  g_source_unref (source);

  g_thread_join (main_thread);
  main_thread = NULL;

  g_main_loop_unref (main_loop);
  main_loop = NULL;
  g_main_context_unref (main_context);
  main_context = NULL;

  gum_deinit_embedded ();
}

GMainContext *
frida_gadget_environment_get_main_context (void)
{
  return main_context;
}

GumScriptBackend *
frida_gadget_environment_obtain_script_backend (gboolean jit_enabled)
{
  GumScriptBackend * backend = NULL;

#ifdef HAVE_DIET
  backend = gum_script_backend_obtain_duk ();
#else
  if (jit_enabled)
    backend = gum_script_backend_obtain_v8 ();
  if (backend == NULL)
    backend = gum_script_backend_obtain_duk ();
#endif

  return backend;
}

static gpointer
run_main_loop (gpointer data)
{
  (void) data;

  g_main_context_push_thread_default (main_context);
  g_main_loop_run (main_loop);
  g_main_context_pop_thread_default (main_context);

  return NULL;
}

static gboolean
stop_main_loop (gpointer data)
{
  (void) data;

  g_main_loop_quit (main_loop);

  return FALSE;
}

void
frida_gadget_log_info (const gchar * message)
{
  g_info ("%s", message);
}

void
frida_gadget_log_error (const gchar * message)
{
  g_error ("%s", message);
}

#ifdef HAVE_DARWIN

static FridaCFApi *
frida_cf_api_try_get (void)
{
  static gsize api_value = 0;
  FridaCFApi * api;

  if (g_once_init_enter (&api_value))
  {
    const gchar * cf_path = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    void * cf;

    /*
     * CoreFoundation must be loaded by the main thread, so we should avoid loading it.
     */
    if (gum_module_find_base_address (cf_path) != 0)
    {
      cf = dlopen (cf_path, RTLD_GLOBAL | RTLD_LAZY);
      g_assert (cf != NULL);

      api = g_slice_new (FridaCFApi);

#define FRIDA_ASSIGN_CF_SYMBOL(n) \
    api->n = dlsym (cf, G_STRINGIFY (n)); \
    g_assert (api->n != NULL)

      FRIDA_ASSIGN_CF_SYMBOL (kCFAllocatorDefault);
      FRIDA_ASSIGN_CF_SYMBOL (kCFRunLoopCommonModes);

      FRIDA_ASSIGN_CF_SYMBOL (CFRelease);

      FRIDA_ASSIGN_CF_SYMBOL (CFRunLoopGetMain);
      FRIDA_ASSIGN_CF_SYMBOL (CFRunLoopRun);
      FRIDA_ASSIGN_CF_SYMBOL (CFRunLoopStop);
      FRIDA_ASSIGN_CF_SYMBOL (CFRunLoopTimerCreate);
      FRIDA_ASSIGN_CF_SYMBOL (CFRunLoopAddTimer);
      FRIDA_ASSIGN_CF_SYMBOL (CFRunLoopTimerInvalidate);

#undef FRIDA_ASSIGN_CF_SYMBOL

      dlclose (cf);
    }
    else
    {
      api = NULL;
    }

    g_once_init_leave (&api_value, 1 + GPOINTER_TO_SIZE (api));
  }

  api = GSIZE_TO_POINTER (api_value - 1);

  return api;
}

#endif

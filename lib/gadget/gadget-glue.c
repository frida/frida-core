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
# include <objc/runtime.h>

typedef struct _FridaCFApi FridaCFApi;
typedef struct _FridaObjCApi FridaObjCApi;

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

  CFBundleRef (* CFBundleGetMainBundle) (void);
  CFStringRef (* CFBundleGetIdentifier) (CFBundleRef bundle);

  CFIndex (* CFStringGetLength) (CFStringRef string);
  CFIndex (* CFStringGetMaximumSizeForEncoding) (CFIndex length, CFStringEncoding encoding);
  Boolean (* CFStringGetCString) (CFStringRef string, char * buffer, CFIndex buffer_size, CFStringEncoding encoding);
};

struct _FridaObjCApi
{
  Class (* objc_getClass) (const char * name);
};

static void on_keep_alive_timer_fire (CFRunLoopTimerRef timer, void * info);

static FridaCFApi * frida_cf_api_try_get (void);
static FridaObjCApi * frida_objc_api_try_get (void);

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

#ifdef HAVE_DARWIN
  /* Ensure any initializers run on the main thread. */
  frida_cf_api_try_get ();
  frida_objc_api_try_get ();
#endif

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

gboolean
frida_gadget_environment_can_block_at_load_time (void)
{
#ifdef G_OS_WIN32
  return FALSE;
#else
  return TRUE;
#endif
}

gboolean
frida_gadget_environment_has_system_loop (void)
{
#ifdef HAVE_DARWIN
  return frida_cf_api_try_get () != NULL;
#else
  return FALSE;
#endif
}

void
frida_gadget_environment_run_system_loop (void)
{
#ifdef HAVE_DARWIN
  FridaCFApi * api;
  CFAbsoluteTime distant_future;
  CFRunLoopTimerRef timer;

  api = frida_cf_api_try_get ();
  g_assert (api != NULL);

  distant_future = DBL_MAX;
  timer = api->CFRunLoopTimerCreate (*(api->kCFAllocatorDefault), distant_future, 0, 0, 0, on_keep_alive_timer_fire, NULL);
  api->CFRunLoopAddTimer (api->CFRunLoopGetMain (), timer, *(api->kCFRunLoopCommonModes));

  api->CFRunLoopRun ();

  api->CFRunLoopTimerInvalidate (timer);
  api->CFRelease (timer);
#else
  g_assert_not_reached ();
#endif
}

void
frida_gadget_environment_stop_system_loop (void)
{
#ifdef HAVE_DARWIN
  FridaCFApi * api;

  api = frida_cf_api_try_get ();
  g_assert (api != NULL);

  api->CFRunLoopStop (api->CFRunLoopGetMain ());
#else
  g_assert_not_reached ();
#endif
}

GMainContext *
frida_gadget_environment_get_main_context (void)
{
  return main_context;
}

GumScriptBackend *
frida_gadget_environment_obtain_script_backend (FridaGadgetRuntimeFlavor runtime)
{
  GumScriptBackend * backend = NULL;

#ifdef HAVE_DIET
  backend = gum_script_backend_obtain_duk ();
#else
  if (runtime == FRIDA_GADGET_RUNTIME_FLAVOR_JIT)
    backend = gum_script_backend_obtain_v8 ();
  if (backend == NULL)
    backend = gum_script_backend_obtain_duk ();
#endif

  return backend;
}

gchar *
frida_gadget_environment_detect_bundle_id (void)
{
#ifdef HAVE_DARWIN
  FridaCFApi * api;
  CFBundleRef bundle;
  CFStringRef identifier;
  CFIndex length, size;
  gchar * identifier_utf8;

  api = frida_cf_api_try_get ();
  if (api == NULL)
    return NULL;

  bundle = api->CFBundleGetMainBundle ();
  if (bundle == NULL)
    return NULL;

  identifier = api->CFBundleGetIdentifier (bundle);
  if (identifier == NULL)
    return NULL;

  length = api->CFStringGetLength (identifier);
  size = api->CFStringGetMaximumSizeForEncoding (length, kCFStringEncodingUTF8) + 1;

  identifier_utf8 = g_malloc (size);
  if (!api->CFStringGetCString (identifier, identifier_utf8, size, kCFStringEncodingUTF8))
  {
    g_clear_pointer (&identifier_utf8, g_free);
  }

  return identifier_utf8;
#else
  return NULL;
#endif
}

gboolean
frida_gadget_environment_has_objc_class (const gchar * name)
{
#ifdef HAVE_DARWIN
  FridaObjCApi * api;

  api = frida_objc_api_try_get ();
  if (api == NULL)
    return FALSE;

  return api->objc_getClass (name) != NULL;
#else
  return FALSE;
#endif
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

    cf = dlopen (cf_path, RTLD_GLOBAL | RTLD_LAZY | RTLD_NOLOAD);
    if (cf != NULL)
    {
      /*
       * Okay the process has CoreFoundation loaded!
       *
       * Now let's make sure initializers have been run:
       */
      dlclose (cf);
      cf = dlopen (cf_path, RTLD_GLOBAL | RTLD_LAZY);

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

      FRIDA_ASSIGN_CF_SYMBOL (CFBundleGetMainBundle);
      FRIDA_ASSIGN_CF_SYMBOL (CFBundleGetIdentifier);

      FRIDA_ASSIGN_CF_SYMBOL (CFStringGetLength);
      FRIDA_ASSIGN_CF_SYMBOL (CFStringGetMaximumSizeForEncoding);
      FRIDA_ASSIGN_CF_SYMBOL (CFStringGetCString);

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

static FridaObjCApi *
frida_objc_api_try_get (void)
{
  static gsize api_value = 0;
  FridaObjCApi * api;

  if (g_once_init_enter (&api_value))
  {
    const gchar * objc_path = "/usr/lib/libobjc.A.dylib";
    void * objc;

    objc = dlopen (objc_path, RTLD_GLOBAL | RTLD_LAZY | RTLD_NOLOAD);
    if (objc != NULL)
    {
      /*
       * Okay the process has the Objective-C runtime loaded!
       *
       * Now let's make sure initializers have been run:
       */
      dlclose (objc);
      objc = dlopen (objc_path, RTLD_GLOBAL | RTLD_LAZY);

      api = g_slice_new (FridaObjCApi);

#define FRIDA_ASSIGN_OBJC_SYMBOL(n) \
    api->n = dlsym (objc, G_STRINGIFY (n)); \
    g_assert (api->n != NULL)

      FRIDA_ASSIGN_OBJC_SYMBOL (objc_getClass);

#undef FRIDA_ASSIGN_OBJC_SYMBOL

      dlclose (objc);
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

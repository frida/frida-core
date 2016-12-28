#if defined (HAVE_IOS) || defined (HAVE_ANDROID)

#include "channel.h"

#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FRIDA_LOADER_DATA_DIR_MAGIC "3zPLi3BupiesaB9diyimME74fJw4jvj6"

typedef void (* FridaAgentMainFunc) (const char * data, unsigned int * stay_resident, void * mapped_range);

static void frida_loader_connect (const char * details);
static void * frida_loader_run (void * user_data);

static char frida_data_dir[256] = FRIDA_LOADER_DATA_DIR_MAGIC;

#ifdef HAVE_IOS

#include <float.h>

#define kFridaCFStringEncodingUTF8 0x08000100

typedef struct _FridaWaitForPermissionToResumeContext FridaWaitForPermissionToResumeContext;

#if __LLP64__
typedef unsigned long long FridaCFOptionFlags;
typedef signed long long FridaCFIndex;
#else
typedef unsigned long FridaCFOptionFlags;
typedef signed long FridaCFIndex;
#endif
typedef void * FridaCFRef;
typedef uint32_t FridaCFStringEncoding;
typedef unsigned char FridaCFBoolean;
typedef double FridaCFAbsoluteTime;
typedef double FridaCFTimeInterval;
typedef struct _FridaCFRunLoopTimerContext FridaCFRunLoopTimerContext;

typedef FridaCFRef (* FridaCFBundleGetMainBundleFunc) (void);
typedef FridaCFRef (* FridaCFBundleGetIdentifierFunc) (FridaCFRef bundle);
typedef FridaCFIndex (* FridaCFStringGetLengthFunc) (FridaCFRef str);
typedef FridaCFIndex (* FridaCFStringGetMaximumSizeForEncodingFunc) (FridaCFIndex length, FridaCFStringEncoding encoding);
typedef FridaCFBoolean (* FridaCFStringGetCString) (FridaCFRef str, char * buffer, FridaCFIndex buffer_size, FridaCFStringEncoding encoding);
typedef void (* FridaCFRunLoopTimerCallBack) (FridaCFRef timer, void * info);
typedef FridaCFRef (* FridaCFRunLoopTimerCreateFunc) (FridaCFRef allocator, FridaCFAbsoluteTime fire_date, FridaCFTimeInterval interval, FridaCFOptionFlags flags, FridaCFIndex order, FridaCFRunLoopTimerCallBack callout, FridaCFRunLoopTimerContext * context);
typedef FridaCFRef (* FridaCFRunLoopGetMainFunc) (void);
typedef void (* FridaCFRunLoopAddTimerFunc) (FridaCFRef loop, FridaCFRef timer, FridaCFRef mode);
typedef void (* FridaCFRunLoopRunFunc) (void);
typedef void (* FridaCFRunLoopStopFunc) (FridaCFRef loop);
typedef void (* FridaCFRunLoopTimerInvalidateFunc) (FridaCFRef timer);
typedef void (* FridaCFReleaseFunc) (FridaCFRef cf);

struct _FridaWaitForPermissionToResumeContext
{
  FridaChannel * channel;
  FridaCFRef loop;

  FridaCFRunLoopStopFunc cf_run_loop_stop;
};

static void detect_data_dir (void);

#define FRIDA_AGENT_FILENAME "frida-agent.dylib"

__attribute__ ((constructor)) static void
frida_loader_on_load (void)
{
  char * identifier = NULL, * details;
  FridaCFBundleGetMainBundleFunc cf_bundle_get_main_bundle;

  detect_data_dir ();

  cf_bundle_get_main_bundle = dlsym (RTLD_DEFAULT, "CFBundleGetMainBundle");
  if (cf_bundle_get_main_bundle != NULL)
  {
    FridaCFBundleGetIdentifierFunc cf_bundle_get_identifier;
    FridaCFStringGetLengthFunc cf_string_get_length;
    FridaCFStringGetMaximumSizeForEncodingFunc cf_string_get_maximum_size_for_encoding;
    FridaCFStringGetCString cf_string_get_c_string;
    FridaCFRef main_bundle;

    cf_bundle_get_identifier = dlsym (RTLD_DEFAULT, "CFBundleGetIdentifier");
    assert (cf_bundle_get_identifier != NULL);

    cf_string_get_length = dlsym (RTLD_DEFAULT, "CFStringGetLength");
    assert (cf_string_get_length != NULL);

    cf_string_get_maximum_size_for_encoding = dlsym (RTLD_DEFAULT, "CFStringGetMaximumSizeForEncoding");
    assert (cf_string_get_maximum_size_for_encoding != NULL);

    cf_string_get_c_string = dlsym (RTLD_DEFAULT, "CFStringGetCString");
    assert (cf_string_get_c_string != NULL);

    main_bundle = cf_bundle_get_main_bundle ();
    if (main_bundle != NULL)
    {
      FridaCFRef main_identifier;

      main_identifier = cf_bundle_get_identifier (main_bundle);
      if (main_identifier != NULL)
      {
        FridaCFIndex length, size;

        length = cf_string_get_length (main_identifier);
        size = cf_string_get_maximum_size_for_encoding (length, kFridaCFStringEncodingUTF8);
        identifier = calloc (1, size + 1);
        cf_string_get_c_string (main_identifier, identifier, size, kFridaCFStringEncodingUTF8);
      }
    }
  }

  asprintf (&details, "%d:%s", getpid (), (identifier != NULL) ? identifier : "");

  frida_loader_connect (details);

  free (details);
  if (identifier != NULL)
    free (identifier);
}

static void *
frida_loader_wait_for_permission_to_resume (void * user_data)
{
  FridaWaitForPermissionToResumeContext * original_ctx = user_data;
  FridaWaitForPermissionToResumeContext ctx;
  char * permission_to_resume;

  ctx = *original_ctx;

  permission_to_resume = frida_channel_recv_string (ctx.channel);
  free (permission_to_resume);

  ctx.cf_run_loop_stop (ctx.loop);

  return NULL;
}

static void
on_keep_alive_timer_fire (FridaCFRef timer, void * info)
{
}

static void
detect_data_dir (void)
{
  Dl_info info;
  int res;

  res = dladdr (frida_loader_on_load, &info);
  assert (res != 0);

  res = readlink (info.dli_fname, frida_data_dir, sizeof (frida_data_dir));
  assert (res != -1);
  frida_data_dir[res] = '\0';
  *strrchr (frida_data_dir, '/') = '\0';
}

#else

#include <gum/gum.h>
#include <jni.h>

#if GLIB_SIZEOF_VOID_P == 4
# define FRIDA_AGENT_FILENAME "frida-agent-32.so"
#else
# define FRIDA_AGENT_FILENAME "frida-agent-64.so"
#endif

#define FRIDA_TYPE_ZYGOTE_MONITOR (frida_zygote_monitor_get_type ())
#define FRIDA_ZYGOTE_MONITOR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FRIDA_TYPE_ZYGOTE_MONITOR, FridaZygoteMonitor))

typedef struct _FridaZygoteMonitor FridaZygoteMonitor;
typedef struct _FridaZygoteMonitorClass FridaZygoteMonitorClass;

typedef struct _FridaRuntimeBounds FridaRuntimeBounds;

typedef guint FridaZygoteMonitorState;

enum _FridaZygoteMonitorState
{
  FRIDA_ZYGOTE_MONITOR_PARENT_AWAITING_FORK,
  FRIDA_ZYGOTE_MONITOR_PARENT_READY,
  FRIDA_ZYGOTE_MONITOR_CHILD_AWAITING_SETARGV0,
  FRIDA_ZYGOTE_MONITOR_CHILD_RUNNING
};

typedef jint (* FridaGetCreatedJavaVMsFunc) (JavaVM ** vms, jsize vms_count, jsize * vm_count);

struct _FridaZygoteMonitor
{
  GObject parent;

  FridaZygoteMonitorState state;
};

struct _FridaZygoteMonitorClass
{
  GObjectClass parent_class;
};

struct _FridaRuntimeBounds
{
  gpointer start;
  gpointer end;
};

static void frida_loader_init (void);
static void frida_loader_deinit (void);
static void frida_loader_prevent_unload (void);
static void frida_loader_allow_unload (void);
static gboolean frida_store_runtime_bounds (const GumModuleDetails * details, FridaRuntimeBounds * bounds);

static void frida_zygote_monitor_iface_init (gpointer g_iface, gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (FridaZygoteMonitor,
                        frida_zygote_monitor,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            frida_zygote_monitor_iface_init));

static gpointer module = NULL;
static GumInterceptor * interceptor = NULL;
static FridaZygoteMonitor * monitor = NULL;
static gpointer fork_impl = NULL;
static gpointer set_argv0_impl = NULL;

void
frida_agent_main (const char * data_dir, void * mapped_range, size_t parent_thread_id)
{
  bool already_loaded;

  if (*data_dir == '\0')
  {
    frida_loader_deinit ();
    return;
  }

  already_loaded = strcmp (frida_data_dir, FRIDA_LOADER_DATA_DIR_MAGIC) != 0;
  strcpy (frida_data_dir, data_dir);
  if (already_loaded)
    return;

  frida_loader_init ();
}

static void
frida_loader_init (void)
{
  gpointer libc;
  GumAttachReturn attach_ret;

  frida_loader_prevent_unload ();

  gum_init_embedded ();

  libc = dlopen ("libc.so", RTLD_GLOBAL | RTLD_LAZY);
  fork_impl = dlsym (libc, "fork");
  dlclose (libc);

  interceptor = gum_interceptor_obtain ();
  monitor = g_object_new (FRIDA_TYPE_ZYGOTE_MONITOR, NULL);
  attach_ret = gum_interceptor_attach_listener (interceptor, fork_impl, GUM_INVOCATION_LISTENER (monitor), fork_impl);
  g_assert_cmpint (attach_ret, ==, GUM_ATTACH_OK);
}

static void
frida_loader_deinit (void)
{
  if (module == NULL)
    return;

  gum_interceptor_detach_listener (interceptor, GUM_INVOCATION_LISTENER (monitor));

  g_object_unref (monitor);
  monitor = NULL;

  g_object_unref (interceptor);
  interceptor = NULL;

  gum_deinit_embedded ();

  frida_loader_allow_unload ();
}

static void
frida_loader_prevent_unload (void)
{
  Dl_info info;
  int res;

  res = dladdr (frida_agent_main, &info);
  assert (res != 0);

  module = dlopen (info.dli_fname, RTLD_LAZY);
  assert (module != NULL);
}

static void
frida_loader_allow_unload (void)
{
  dlclose (module);
  module = NULL;
}

static void
frida_zygote_monitor_on_fork_enter (FridaZygoteMonitor * self)
{
  gpointer runtime;
  gboolean is_art;
  FridaGetCreatedJavaVMsFunc get_created_java_vms;
  JavaVM * vm;
  jsize vm_count;
  jint res;
  JNIEnv * env;
  jclass process;
  jmethodID set_argv0;
  FridaRuntimeBounds runtime_bounds;
  guint offset;
  GumAttachReturn attach_ret;

  if (self->state != FRIDA_ZYGOTE_MONITOR_PARENT_AWAITING_FORK)
    return;

  runtime = dlopen ("libart.so", RTLD_GLOBAL | RTLD_LAZY);
  is_art = runtime != NULL;
  if (runtime == NULL)
  {
    runtime = dlopen ("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    g_assert (runtime != NULL);
  }

  get_created_java_vms = (FridaGetCreatedJavaVMsFunc) dlsym (runtime, "JNI_GetCreatedJavaVMs");
  g_assert (get_created_java_vms != NULL);

  res = get_created_java_vms (&vm, 1, &vm_count);
  g_assert_cmpint (res, ==, JNI_OK);

  if (vm_count == 0 && is_art)
  {
    dlclose (runtime);

    runtime = dlopen ("libdvm.so", RTLD_GLOBAL | RTLD_LAZY);
    g_assert (runtime != NULL);

    is_art = FALSE;

    get_created_java_vms = (FridaGetCreatedJavaVMsFunc) dlsym (runtime, "JNI_GetCreatedJavaVMs");
    g_assert (get_created_java_vms != NULL);

    res = get_created_java_vms (&vm, 1, &vm_count);
    g_assert_cmpint (res, ==, JNI_OK);
  }

  g_assert (vm_count > 0);

  res = (*vm)->GetEnv (vm, (void **) &env, JNI_VERSION_1_6);
  g_assert_cmpint (res, ==, JNI_OK);

  process = (*env)->FindClass (env, "android/os/Process");
  g_assert (process != NULL);

  set_argv0 = (*env)->GetStaticMethodID (env, process, "setArgV0", "(Ljava/lang/String;)V");
  g_assert (set_argv0 != NULL);

  runtime_bounds.start = NULL;
  runtime_bounds.end = NULL;
  gum_process_enumerate_modules ((GumFoundModuleFunc) frida_store_runtime_bounds, &runtime_bounds);
  g_assert (runtime_bounds.end != runtime_bounds.start);

  for (offset = 0; offset != 64; offset += 4)
  {
    gpointer address = *((gpointer *) (GPOINTER_TO_SIZE (set_argv0) + offset));

    if (address >= runtime_bounds.start && address < runtime_bounds.end)
    {
      set_argv0_impl = address;
      break;
    }
  }

  attach_ret = gum_interceptor_attach_listener (interceptor, set_argv0_impl, GUM_INVOCATION_LISTENER (self), set_argv0_impl);
  g_assert_cmpint (attach_ret, ==, GUM_ATTACH_OK);

  self->state = FRIDA_ZYGOTE_MONITOR_PARENT_READY;

  dlclose (runtime);
}

static gboolean
frida_store_runtime_bounds (const GumModuleDetails * details, FridaRuntimeBounds * bounds)
{
  const GumMemoryRange * range = details->range;

  if (strcmp (details->name, "libandroid_runtime.so") != 0)
    return TRUE;

  bounds->start = GSIZE_TO_POINTER (range->base_address);
  bounds->end = GSIZE_TO_POINTER (range->base_address + range->size);

  return FALSE;
}

static void
frida_zygote_monitor_on_fork_leave (FridaZygoteMonitor * self, GumInvocationContext * context)
{
  pid_t pid;

  pid = GPOINTER_TO_INT (gum_invocation_context_get_return_value (context));

  if (self->state == FRIDA_ZYGOTE_MONITOR_PARENT_READY && pid == 0)
  {
    self->state = FRIDA_ZYGOTE_MONITOR_CHILD_AWAITING_SETARGV0;
  }
}

static void
frida_zygote_monitor_on_set_argv0_enter (FridaZygoteMonitor * self, GumInvocationContext * context)
{
  JNIEnv * env;
  jstring name;
  const gchar * name_utf8;

  env = gum_invocation_context_get_nth_argument (context, 0);
  name = gum_invocation_context_get_nth_argument (context, 2);
  name_utf8 = (*env)->GetStringUTFChars (env, name, NULL);
  *GUM_LINCTX_GET_FUNC_INVDATA (context, gchar *) = g_strdup (name_utf8);
  (*env)->ReleaseStringUTFChars (env, name, name_utf8);
}

static void
frida_zygote_monitor_on_set_argv0_leave (FridaZygoteMonitor * self, GumInvocationContext * context)
{
  gchar * name;

  name = *GUM_LINCTX_GET_FUNC_INVDATA (context, gchar *);
  if (self->state == FRIDA_ZYGOTE_MONITOR_CHILD_AWAITING_SETARGV0)
  {
    gchar * details;

    self->state = FRIDA_ZYGOTE_MONITOR_CHILD_RUNNING;

    details = g_strdup_printf ("%d:%s", getpid (), name);
    frida_loader_connect (details);
    g_free (details);
  }

  g_free (name);
}

static void
frida_zygote_monitor_on_enter (GumInvocationListener * listener, GumInvocationContext * context)
{
  FridaZygoteMonitor * self = FRIDA_ZYGOTE_MONITOR (listener);
  gpointer func = GUM_LINCTX_GET_FUNC_DATA (context, gpointer);

  if (func == fork_impl)
    frida_zygote_monitor_on_fork_enter (self);
  else if (func == set_argv0_impl)
    frida_zygote_monitor_on_set_argv0_enter (self, context);
}

static void
frida_zygote_monitor_on_leave (GumInvocationListener * listener, GumInvocationContext * context)
{
  FridaZygoteMonitor * self = FRIDA_ZYGOTE_MONITOR (listener);
  gpointer func = GUM_LINCTX_GET_FUNC_DATA (context, gpointer);

  if (func == fork_impl)
    frida_zygote_monitor_on_fork_leave (self, context);
  else if (func == set_argv0_impl)
    frida_zygote_monitor_on_set_argv0_leave (self, context);
}

static void
frida_zygote_monitor_iface_init (gpointer g_iface, gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = frida_zygote_monitor_on_enter;
  iface->on_leave = frida_zygote_monitor_on_leave;
}

static void
frida_zygote_monitor_class_init (FridaZygoteMonitorClass * klass)
{
}

static void
frida_zygote_monitor_init (FridaZygoteMonitor * self)
{
  self->state = FRIDA_ZYGOTE_MONITOR_PARENT_AWAITING_FORK;
}

#endif

static void
frida_loader_connect (const char * identifier)
{
  FridaChannel * channel;
  char * pipe_address, * permission_to_resume;
  pthread_t thread;

  channel = frida_channel_open (frida_data_dir);
  if (channel == NULL)
    goto beach;

  if (!frida_channel_send_string (channel, identifier))
    goto beach;

  pipe_address = frida_channel_recv_string (channel);
  if (pipe_address == NULL)
    goto beach;

  pthread_create (&thread, NULL, frida_loader_run, pipe_address);
  pthread_detach (thread);

#ifdef HAVE_IOS
  {
    FridaCFRunLoopTimerCreateFunc cf_run_loop_timer_create;

    cf_run_loop_timer_create = dlsym (RTLD_DEFAULT, "CFRunLoopTimerCreate");
    if (cf_run_loop_timer_create != NULL)
    {
      FridaCFRunLoopGetMainFunc cf_run_loop_get_main;
      FridaCFRef * cf_run_loop_common_modes;
      FridaCFRunLoopAddTimerFunc cf_run_loop_add_timer;
      FridaCFRunLoopRunFunc cf_run_loop_run;
      FridaWaitForPermissionToResumeContext ctx;
      FridaCFRef timer;
      FridaCFAbsoluteTime distant_future;
      FridaCFRunLoopTimerInvalidateFunc cf_run_loop_timer_invalidate;
      FridaCFReleaseFunc cf_release;

      cf_run_loop_get_main = dlsym (RTLD_DEFAULT, "CFRunLoopGetMain");
      assert (cf_run_loop_get_main != NULL);

      cf_run_loop_common_modes = dlsym (RTLD_DEFAULT, "kCFRunLoopCommonModes");
      assert (cf_run_loop_common_modes != NULL);

      cf_run_loop_add_timer = dlsym (RTLD_DEFAULT, "CFRunLoopAddTimer");
      assert (cf_run_loop_add_timer != NULL);

      cf_run_loop_run = dlsym (RTLD_DEFAULT, "CFRunLoopRun");
      assert (cf_run_loop_run != NULL);

      ctx.cf_run_loop_stop = dlsym (RTLD_DEFAULT, "CFRunLoopStop");
      assert (ctx.cf_run_loop_stop != NULL);

      cf_run_loop_timer_invalidate = dlsym (RTLD_DEFAULT, "CFRunLoopTimerInvalidate");
      assert (cf_run_loop_timer_invalidate != NULL);

      cf_release = dlsym (RTLD_DEFAULT, "CFRelease");
      assert (cf_release != NULL);

      ctx.channel = channel;
      ctx.loop = cf_run_loop_get_main ();
      distant_future = DBL_MAX;
      timer = cf_run_loop_timer_create (NULL, distant_future, 0, 0, 0, on_keep_alive_timer_fire, NULL);
      cf_run_loop_add_timer (ctx.loop, timer, *cf_run_loop_common_modes);

      pthread_create (&thread, NULL, frida_loader_wait_for_permission_to_resume, &ctx);
      pthread_detach (thread);

      cf_run_loop_run ();

      cf_run_loop_timer_invalidate (timer);
      cf_release (timer);
    }
    else
    {
      permission_to_resume = frida_channel_recv_string (channel);
      free (permission_to_resume);
    }
  }
#else
  permission_to_resume = frida_channel_recv_string (channel);
  free (permission_to_resume);
#endif

beach:
  if (channel != NULL)
    frida_channel_close (channel);
}

static void *
frida_loader_run (void * user_data)
{
  char * pipe_address = user_data;
  char * agent_path;
  void * agent;
  FridaAgentMainFunc agent_main;
  unsigned int stay_resident;

  asprintf (&agent_path, "%s/" FRIDA_AGENT_FILENAME, frida_data_dir);

  agent = dlopen (agent_path, RTLD_LAZY);
  if (agent == NULL)
    goto beach;

  agent_main = (FridaAgentMainFunc) dlsym (agent, "frida_agent_main");
  assert (agent_main != NULL);

  stay_resident = false;

  agent_main (pipe_address, &stay_resident, NULL);

  if (!stay_resident)
    dlclose (agent);

beach:
  free (agent_path);

  free (pipe_address);

  return NULL;
}

#endif

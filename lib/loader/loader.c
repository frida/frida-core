#if defined (HAVE_IOS) || defined (HAVE_ANDROID)

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef HAVE_ANDROID
# include <android/log.h>
#endif

#define FRIDA_LOADER_DATA_DIR_MAGIC "3zPLi3BupiesaB9diyimME74fJw4jvj6"

typedef void (* FridaAgentMainFunc) (const char * data_string, void * mapped_range, size_t parent_thread_id);

static void frida_loader_connect (const char * identifier);
static void * frida_loader_run (void * user_data);
static bool frida_loader_send_string (int s, const char * v);
static bool frida_loader_send_bytes (int s, const void * bytes, size_t size);
static char * frida_loader_recv_string (int s);
static bool frida_loader_recv_bytes (int s, void * bytes, size_t size);

static char frida_data_dir[256] = FRIDA_LOADER_DATA_DIR_MAGIC;

#ifdef HAVE_IOS

#define FRIDA_AGENT_FILENAME "frida-agent.dylib"

__attribute__ ((constructor)) static void
frida_loader_on_load (void)
{
  char identifier[12];

  sprintf (identifier, "%d", getpid ());

  frida_loader_connect (identifier);
}

#else

#include <android/log.h>
#include <gum/gum.h>
#include <jni.h>

#if GLIB_SIZEOF_VOID_P == 4
# define FRIDA_LOADER_FILENAME "frida-loader-32.so"
# define FRIDA_AGENT_FILENAME "frida-agent-32.so"
#else
# define FRIDA_LOADER_FILENAME "frida-loader-64.so"
# define FRIDA_AGENT_FILENAME "frida-agent-64.so"
#endif

#define FRIDA_ART_METHOD_OFFSET_JNI_CODE 32
#define FRIDA_DVM_METHOD_OFFSET_INSNS    32

#define FRIDA_TYPE_ZYGOTE_MONITOR (frida_zygote_monitor_get_type ())
#define FRIDA_ZYGOTE_MONITOR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FRIDA_TYPE_ZYGOTE_MONITOR, FridaZygoteMonitor))

typedef struct _FridaZygoteMonitor FridaZygoteMonitor;
typedef struct _FridaZygoteMonitorClass FridaZygoteMonitorClass;

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

static void frida_loader_init (void);
static void frida_loader_deinit (void);
static void frida_loader_on_assert_failure (const gchar * log_domain, const gchar * file, gint line, const gchar * func, const gchar * message, gpointer user_data) G_GNUC_NORETURN;
static void frida_loader_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data);
static void frida_loader_prevent_unload (void);
static void frida_loader_allow_unload (void);

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
  GMemVTable mem_vtable = {
    gum_malloc,
    gum_realloc,
    gum_free,
    gum_calloc,
    gum_malloc,
    gum_realloc
  };
  gpointer libc;
  GumAttachReturn attach_ret;

  frida_loader_prevent_unload ();

  gum_memory_init ();
  g_mem_set_vtable (&mem_vtable);
  glib_init ();
  g_assertion_set_handler (frida_loader_on_assert_failure, NULL);
  g_log_set_default_handler (frida_loader_on_log_message, NULL);
  g_log_set_always_fatal (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING);
  gum_init ();

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

  gum_deinit ();
  glib_deinit ();
  gum_memory_deinit ();

  frida_loader_allow_unload ();
}

static void
frida_loader_on_assert_failure (const gchar * log_domain, const gchar * file, gint line, const gchar * func, const gchar * message, gpointer user_data)
{
  gchar * full_message;

  while (g_str_has_prefix (file, ".." G_DIR_SEPARATOR_S))
    file += 3;
  if (message == NULL)
    message = "code should not be reached";

  full_message = g_strdup_printf ("%s:%d:%s%s %s", file, line, func, (func[0] != '\0') ? ":" : "", message);
  frida_loader_on_log_message (log_domain, G_LOG_LEVEL_ERROR, full_message, user_data);
  g_free (full_message);

  abort ();
}

static void
frida_loader_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data)
{
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
}

static void
frida_loader_prevent_unload (void)
{
  module = dlopen (FRIDA_LOADER_FILENAME, RTLD_GLOBAL | RTLD_LAZY);
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
  g_assert (vm_count > 0);

  res = (*vm)->GetEnv (vm, (void **) &env, JNI_VERSION_1_6);
  g_assert_cmpint (res, ==, JNI_OK);

  process = (*env)->FindClass (env, "android/os/Process");
  g_assert (process != NULL);

  set_argv0 = (*env)->GetStaticMethodID (env, process, "setArgV0", "(Ljava/lang/String;)V");
  g_assert (set_argv0 != NULL);

  set_argv0_impl = *((gpointer *) (GPOINTER_TO_SIZE (set_argv0) +
      (is_art ? FRIDA_ART_METHOD_OFFSET_JNI_CODE : FRIDA_DVM_METHOD_OFFSET_INSNS)));
  attach_ret = gum_interceptor_attach_listener (interceptor, set_argv0_impl, GUM_INVOCATION_LISTENER (self), set_argv0_impl);
  g_assert_cmpint (attach_ret, ==, GUM_ATTACH_OK);

  self->state = FRIDA_ZYGOTE_MONITOR_PARENT_READY;

  dlclose (runtime);
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
    gchar * identifier;

    self->state = FRIDA_ZYGOTE_MONITOR_CHILD_RUNNING;

    identifier = g_strdup_printf ("%d:%s", getpid (), name);
    frida_loader_connect (identifier);
    g_free (identifier);
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
  char * callback_path;
  int s;
  struct sockaddr_un callback;
  socklen_t callback_len;
  char * pipe_address, * permission_to_resume;
  pthread_t thread;

  asprintf (&callback_path, "%s/callback", frida_data_dir);

  s = socket (AF_UNIX, SOCK_STREAM, 0);
  if (s == -1)
    goto beach;

#ifdef HAVE_IOS
  callback.sun_len = sizeof (callback.sun_len) + sizeof (callback.sun_family) + strlen (callback_path);
  callback_len = callback.sun_len;
#else
  callback_len = sizeof (callback);
#endif
  callback.sun_family = AF_UNIX;
  strcpy (callback.sun_path, callback_path);
  if (connect (s, (struct sockaddr *) &callback, callback_len) == -1)
    goto beach;

  if (!frida_loader_send_string (s, identifier))
    goto beach;

  pipe_address = frida_loader_recv_string (s);
  if (pipe_address == NULL)
    goto beach;

  pthread_create (&thread, NULL, frida_loader_run, pipe_address);
  pthread_detach (thread);

  permission_to_resume = frida_loader_recv_string (s);
  free (permission_to_resume);

beach:
  if (s != -1)
    close (s);

  free (callback_path);
}

static void *
frida_loader_run (void * user_data)
{
  char * pipe_address = user_data;
  char * agent_path;
  void * agent;
  FridaAgentMainFunc agent_main;

  asprintf (&agent_path, "%s/" FRIDA_AGENT_FILENAME, frida_data_dir);

  agent = dlopen (agent_path, RTLD_GLOBAL | RTLD_LAZY);
  if (agent == NULL)
    goto beach;

  agent_main = (FridaAgentMainFunc) dlsym (agent, "frida_agent_main");
  assert (agent_main != NULL);

  agent_main (pipe_address, NULL, 0);

  dlclose (agent);

beach:
  free (agent_path);

  free (pipe_address);

  return NULL;
}

static bool
frida_loader_send_string (int s, const char * v)
{
  uint8_t size = strlen (v);
  if (!frida_loader_send_bytes (s, &size, sizeof (size)))
    return false;

  return frida_loader_send_bytes (s, v, size);
}

static bool
frida_loader_send_bytes (int s, const void * bytes, size_t size)
{
  size_t offset = 0;

  while (offset != size)
  {
    ssize_t n;

    n = send (s, bytes + offset, size - offset, 0);
    if (n != -1)
      offset += n;
    else if (errno != EINTR)
      return false;
  }

  return true;
}

static char *
frida_loader_recv_string (int s)
{
  uint8_t size;
  char * buf;

  if (!frida_loader_recv_bytes (s, &size, sizeof (size)))
    return NULL;

  buf = malloc (size + 1);
  buf[size] = '\0';
  if (!frida_loader_recv_bytes (s, buf, size))
  {
    free (buf);
    return NULL;
  }

  return buf;
}

static bool
frida_loader_recv_bytes (int s, void * bytes, size_t size)
{
  size_t offset = 0;

  while (offset != size)
  {
    ssize_t n;

    n = recv (s, bytes + offset, size - offset, 0);
    if (n > 0)
      offset += n;
    else if (n == 0)
      return false;
    else if (n == -1 && errno != EINTR)
      return false;
  }

  return true;
}

#endif

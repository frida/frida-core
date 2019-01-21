#include "frida-agent.h"

#ifndef G_OS_WIN32
# include "frida-interfaces.h"
#endif

#ifndef HAVE_WINDOWS
# include <pthread.h>
#endif
#ifdef HAVE_DARWIN
# include <gum/gum.h>
# include <gum/gumdarwin.h>
# include <limits.h>
# include <mach-o/dyld.h>
#endif
#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
# include <signal.h>
#endif
#ifdef HAVE_GLIB_SCHANNEL_STATIC
# include <glib-schannel-static.h>
#endif
#ifdef HAVE_GLIB_OPENSSL_STATIC
# include <glib-openssl-static.h>
#endif

void
_frida_agent_environment_init (void)
{
  gum_init_embedded ();

  g_thread_set_garbage_handler (_frida_agent_on_pending_garbage, NULL);

#ifdef HAVE_GLIB_SCHANNEL_STATIC
  g_io_module_schannel_register ();
#endif
#ifdef HAVE_GLIB_OPENSSL_STATIC
  g_io_module_openssl_register ();
#endif

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
  /*
   * We might be holding the dynamic linker's lock, so force-initialize
   * our bsd_signal() wrapper on this thread.
   */
  bsd_signal (G_MAXINT32, SIG_DFL);
#endif
}

void
_frida_agent_environment_deinit (void)
{
  gum_deinit_embedded ();
}

GumScriptBackend *
_frida_agent_environment_obtain_script_backend (gboolean jit_enabled)
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

gchar *
_frida_agent_environment_try_get_executable_path (void)
{
#ifdef HAVE_DARWIN
  uint32_t buf_size;
  gchar * buf;

  buf_size = PATH_MAX;

  do
  {
    buf = g_malloc (buf_size);
    if (_NSGetExecutablePath (buf, &buf_size) == 0)
      return buf;

    g_free (buf);
  }
  while (TRUE);
#elif HAVE_LINUX
  return g_file_read_link ("/proc/self/exe", NULL);
#else
  return NULL;
#endif
}

gpointer
_frida_agent_environment_get_current_pthread (void)
{
#ifndef HAVE_WINDOWS
  return (gpointer) pthread_self ();
#else
  return NULL;
#endif
}

void
_frida_agent_environment_join_pthread (gpointer pthread)
{
#ifndef HAVE_WINDOWS
  int join_result;

  join_result = pthread_join ((pthread_t) pthread, NULL);
  g_assert_cmpint (join_result, ==, 0);
#endif
}

#ifdef HAVE_WINDOWS

# define VC_EXTRALEAN
# include <windows.h>

static gchar * frida_ansi_string_to_utf8 (const gchar * str_ansi, gint length);

guint32
_frida_agent_spawn_monitor_get_current_process_id (void)
{
  return GetCurrentProcessId ();
}

guint32
_frida_agent_spawn_monitor_resume_thread (void * thread)
{
  return ResumeThread (thread);
}

gchar **
_frida_agent_spawn_monitor_get_environment (int * length)
{
  gchar ** result;
  LPWCH strings;

  strings = GetEnvironmentStringsW ();
  result = _frida_agent_spawn_monitor_parse_unicode_environment (strings, length);
  FreeEnvironmentStrings (strings);

  return result;
}

gchar **
_frida_agent_spawn_monitor_parse_unicode_environment (void * env, int * length)
{
  GPtrArray * result;
  WCHAR * element_data;
  gsize element_length;

  result = g_ptr_array_new ();

  element_data = env;
  while ((element_length = wcslen (element_data)) != 0)
  {
    g_ptr_array_add (result, g_utf16_to_utf8 (element_data, element_length, NULL, NULL, NULL));
    element_data += element_length + 1;
  }

  *length = result->len;

  g_ptr_array_add (result, NULL);

  return (gchar **) g_ptr_array_free (result, FALSE);
}

gchar **
_frida_agent_spawn_monitor_parse_ansi_environment (void * env, int * length)
{
  GPtrArray * result;
  gchar * element_data;
  gsize element_length;

  result = g_ptr_array_new ();

  element_data = env;
  while ((element_length = strlen (element_data)) != 0)
  {
    g_ptr_array_add (result, frida_ansi_string_to_utf8 (element_data, element_length));
    element_data += element_length + 1;
  }

  *length = result->len;

  g_ptr_array_add (result, NULL);

  return (gchar **) g_ptr_array_free (result, FALSE);
}

static gchar *
frida_ansi_string_to_utf8 (const gchar * str_ansi, gint length)
{
  guint str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_size = (guint) (length + 1) * sizeof (WCHAR);
  str_utf16 = (WCHAR *) g_malloc (str_utf16_size);
  MultiByteToWideChar (CP_ACP, 0, str_ansi, length, str_utf16, str_utf16_size);
  str_utf16[length] = L'\0';
  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);
  g_free (str_utf16);

  return str_utf8;
}

#endif

#ifdef HAVE_DARWIN

void
_frida_agent_thread_suspend_monitor_remove_cloaked_threads (FridaAgentThreadSuspendMonitor * self, task_inspect_t task, thread_act_array_t * threads, mach_msg_type_number_t * count)
{
  guint i, o;
  thread_act_array_t old_threads = *threads;
  gsize page_size, old_size, new_size, pages_before, pages_after;

  if (task != mach_task_self () || *count == 0)
    return;

  for (i = 0, o = 0; i != *count; i++)
  {
    thread_t thread = old_threads[i];

    if (gum_cloak_has_thread (thread))
      mach_port_deallocate (task, thread);
    else
      old_threads[o++] = thread;
  }
  g_assert_cmpuint (o, >, 0);

  page_size = getpagesize ();
  old_size = *count * sizeof (thread_t);
  new_size = o * sizeof (thread_t);
  pages_before = GUM_ALIGN_SIZE (old_size, page_size) / page_size;
  pages_after = GUM_ALIGN_SIZE (new_size, page_size) / page_size;

  if (pages_before != pages_after)
  {
    thread_act_array_t new_threads;

    mach_vm_allocate (task, (mach_vm_address_t *) &new_threads, new_size, VM_FLAGS_ANYWHERE);
    mach_vm_copy (task, (mach_vm_address_t) old_threads, new_size, (mach_vm_address_t) new_threads);

    *threads = new_threads;
    *count = o;

    mach_vm_deallocate (task, (mach_vm_address_t) old_threads, old_size);
  }
  else
  {
    *count = o;
  }
}

/*
 * Get rid of the -lresolv dependency until we actually need it, i.e. if/when
 * we expose GLib's resolvers to JavaScript. This is however not needed for
 * our current Socket.connect() API, which is neat.
 */

#include <resolv.h>

int
res_9_init (void)
{
  g_assert_not_reached ();
  return -1;
}

int
res_9_ninit (res_9_state state)
{
  g_assert_not_reached ();
  return -1;
}

void
res_9_ndestroy (res_9_state state)
{
  g_assert_not_reached ();
}

int
res_9_nquery (res_9_state state, const char * dname, int klass, int type, u_char * answer, int anslen)
{
  g_assert_not_reached ();
  return -1;
}

int
res_9_dn_expand (const u_char * msg, const u_char * eomorig, const u_char * comp_dn, char * exp_dn, int length)
{
  g_assert_not_reached ();
  return -1;
}

#endif

#ifdef HAVE_LINUX

#include <errno.h>

G_GNUC_INTERNAL long
frida_set_errno (int n)
{
  errno = n;

  return -1;
}

#endif

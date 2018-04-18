#include "frida-agent.h"

#ifndef G_OS_WIN32
# include "frida-interfaces.h"
#endif

#ifndef HAVE_WINDOWS
# include <pthread.h>
#endif
#ifdef HAVE_DARWIN
# include <limits.h>
# include <mach-o/dyld.h>
#endif
#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
# include <signal.h>
#endif

void
_frida_agent_environment_init (void)
{
  gum_init_embedded ();

  g_thread_set_garbage_handler (_frida_agent_on_pending_garbage, NULL);

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

#endif

#ifdef HAVE_DARWIN

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

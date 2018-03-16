#include "frida-agent.h"

#ifndef G_OS_WIN32
# include "frida-interfaces.h"
#endif

#ifndef HAVE_WINDOWS
# include <pthread.h>
#endif
#ifdef HAVE_DARWIN
# include <stdlib.h>
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
_frida_agent_environment_try_get_program_name (void)
{
#if defined (HAVE_DARWIN) || (defined (HAVE_ANDROID) && __ANDROID_API__ >= __ANDROID_API_L__)
  return g_strdup (getprogname ());
#elif defined (HAVE_GLIBC)
  return g_strdup (program_invocation_name);
#else
  return NULL;
#endif
}

void *
_frida_agent_environment_get_current_pthread (void)
{
#ifndef HAVE_WINDOWS
  return pthread_self ();
#else
  return NULL;
#endif
}

void
_frida_agent_environment_join_pthread (void * pthread)
{
#ifndef HAVE_WINDOWS
  pthread_join (pthread, NULL);
#endif
}

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

#include "frida-gadget.h"

#include "frida-interfaces.h"
#include "frida-payload.h"

#ifdef HAVE_WINDOWS
# include <windows.h>
#else
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <signal.h>
# include <unistd.h>
#endif
#include <gumjs/gumscriptbackend.h>
#ifdef HAVE_GIOSCHANNEL
# include <gioschannel.h>
#endif
#ifdef HAVE_GIOOPENSSL
# include <gioopenssl.h>
#endif

#ifdef HAVE_DARWIN
static void frida_parse_apple_parameters (const gchar * apple[], gboolean * found_range, GumMemoryRange * range, gchar ** config_data);
#endif

static gpointer run_main_loop (gpointer data);
static gboolean stop_main_loop (gpointer data);

static GThread * main_thread;
static GMainLoop * main_loop;
static GMainContext * main_context;

#ifdef HAVE_WINDOWS

BOOL WINAPI
DllMain (HINSTANCE instance, DWORD reason, LPVOID reserved)
{
  switch (reason)
  {
    case DLL_PROCESS_ATTACH:
      frida_gadget_load (NULL, NULL, NULL);
      break;
    case DLL_PROCESS_DETACH:
      frida_gadget_unload ();
      break;
    default:
      break;
  }

  return TRUE;
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

# ifdef HAVE_DARWIN

__attribute__ ((constructor)) static void
frida_on_load (int argc, const char * argv[], const char * envp[], const char * apple[], int * result)
{
  gboolean found_range;
  GumMemoryRange range;
  gchar * config_data;

  frida_parse_apple_parameters (apple, &found_range, &range, &config_data);

  frida_gadget_load (found_range ? &range : NULL, config_data, (config_data != NULL) ? result : NULL);

  g_free (config_data);
}

# else

__attribute__ ((constructor)) static void
frida_on_load (void)
{
  frida_gadget_load (NULL, NULL, NULL);
}

__attribute__ ((destructor)) static void
frida_on_unload (void)
{
  frida_gadget_unload ();
}

# endif

void
_frida_gadget_kill (guint pid)
{
  kill (pid, SIGKILL);
}

#endif

void
frida_gadget_environment_init (void)
{
  gum_init_embedded ();

  g_thread_set_garbage_handler (_frida_gadget_on_pending_thread_garbage, NULL);

#ifdef HAVE_GIOSCHANNEL
  g_io_module_schannel_register ();
#endif
#ifdef HAVE_GIOOPENSSL
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

  main_context = g_main_context_ref (g_main_context_default ());
  main_loop = g_main_loop_new (main_context, FALSE);
  main_thread = g_thread_new ("frida-gadget", run_main_loop, NULL);
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

  frida_run_atexit_handlers ();

#ifdef HAVE_DARWIN
  /* Do what frida_deinit_memory() does on the other platforms. */
  gum_internal_heap_unref ();
#endif
}

gboolean
frida_gadget_environment_can_block_at_load_time (void)
{
#ifdef HAVE_WINDOWS
  return FALSE;
#else
  return TRUE;
#endif
}

GMainContext *
frida_gadget_environment_get_main_context (void)
{
  return main_context;
}

#ifndef HAVE_DARWIN

gchar *
frida_gadget_environment_detect_bundle_id (void)
{
  return NULL;
}

gchar *
frida_gadget_environment_detect_documents_dir (void)
{
  return NULL;
}

gboolean
frida_gadget_environment_has_objc_class (const gchar * name)
{
  return FALSE;
}

void
frida_gadget_environment_set_thread_name (const gchar * name)
{
  /* For now only implemented on i/macOS as Fruity.Injector relies on it there. */
}

#endif

void
frida_gadget_tcp_enable_nodelay (GSocket * socket)
{
  g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);
}

static gpointer
run_main_loop (gpointer data)
{
  g_main_context_push_thread_default (main_context);
  g_main_loop_run (main_loop);
  g_main_context_pop_thread_default (main_context);

  return NULL;
}

static gboolean
stop_main_loop (gpointer data)
{
  g_main_loop_quit (main_loop);

  return FALSE;
}

void
frida_gadget_log_info (const gchar * message)
{
  g_info ("%s", message);
}

void
frida_gadget_log_warning (const gchar * message)
{
  g_warning ("%s", message);
}

#ifdef HAVE_DARWIN

static void
frida_parse_apple_parameters (const gchar * apple[], gboolean * found_range, GumMemoryRange * range, gchar ** config_data)
{
  const gchar * entry;
  guint i = 0;

  *found_range = FALSE;
  *config_data = NULL;

  while ((entry = apple[i++]) != NULL)
  {
    if (g_str_has_prefix (entry, "frida_dylib_range="))
    {
      *found_range = sscanf (entry, "frida_dylib_range=0x%" G_GINT64_MODIFIER "x,0x%" G_GSIZE_MODIFIER "x",
          &range->base_address, &range->size) == 2;
    }
    else if (g_str_has_prefix (entry, "frida_gadget_config="))
    {
      guchar * data;
      gsize size;

      data = g_base64_decode (entry + 20, &size);
      if (data != NULL)
      {
        *config_data = g_strndup ((const gchar *) data, size);
        g_free (data);
      }
    }
  }
}

#endif

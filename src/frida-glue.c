#include "frida-core.h"

static GThread * main_thread;
static GMainLoop * main_loop;
static GMainContext * main_context;

static gpointer run_main_loop (gpointer data);
static gboolean stop_main_loop (gpointer data);

void
frida_init (void)
{
  g_assert (main_loop == NULL);

  g_type_init ();

  main_context = g_main_context_ref (g_main_context_default ());
  main_loop = g_main_loop_new (main_context, FALSE);
  main_thread = g_thread_create (run_main_loop, NULL, TRUE, NULL);
}

void
frida_shutdown (void)
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
}

void
frida_deinit (void)
{
  g_assert (main_loop != NULL);

  if (main_thread != NULL)
    frida_shutdown ();

  g_main_loop_unref (main_loop);
  g_main_context_unref (main_context);

  g_io_deinit ();

  g_type_deinit ();
  g_thread_deinit ();
  g_mem_deinit ();
}

GMainContext *
frida_get_main_context (void)
{
  return main_context;
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

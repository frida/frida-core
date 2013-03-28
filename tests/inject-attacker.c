#include "zed-pipe.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void append_to_log (char c);

__attribute__ ((constructor)) static void
on_load (void)
{
  append_to_log ('>');
}

__attribute__ ((destructor)) static void
on_unload (void)
{
  append_to_log ('<');
}

void
zed_agent_main (const char * data)
{
  guint8 exit_code;

  append_to_log ('m');

  if (g_str_has_prefix (data, "pipe:"))
  {
    GIOStream * stream;
    GError * error = NULL;

    g_thread_init (NULL);
    g_type_init ();

    stream = G_IO_STREAM (zed_pipe_new (data));

    g_input_stream_read (g_io_stream_get_input_stream (stream), &exit_code, sizeof (exit_code), NULL, &error);
    if (error != NULL)
    {
      g_print ("read failed: %s\n", error->message);
      g_clear_error (&error);
    }

    g_io_stream_close (stream, NULL, &error);
    if (error != NULL)
    {
      g_print ("close failed: %s\n", error->message);
      g_clear_error (&error);
    }

    g_object_unref (stream);

    g_io_deinit ();

    g_type_deinit ();
    g_thread_deinit ();
    g_mem_deinit ();
  }
  else
  {
    if (strlen (data) > 0)
      exit_code = atoi (data);
    else
      exit_code = 0xff;
  }

  if (exit_code != 0xff)
    exit (exit_code);
}

static void
append_to_log (char c)
{
  FILE *f;

  f = fopen (getenv ("ZED_LABRAT_LOGFILE"), "ab");
  g_assert (f != NULL);
  fwrite (&c, 1, 1, f);
  fclose (f);
}


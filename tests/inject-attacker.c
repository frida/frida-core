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
zed_agent_main (const char * data_string)
{
  append_to_log ('m');

  if (strlen (data_string) > 0)
  {
    int exit_code = atoi (data_string);
    exit (exit_code);
  }
}

static void
append_to_log (char c)
{
  FILE *f;

#ifdef HAVE_LINUX
  gchar * exe_path, * exe_dir, * log_path;

  exe_path = g_file_read_link ("/proc/self/exe", NULL);
  exe_dir = g_path_get_dirname (exe_path);
  log_path = g_build_filename (exe_dir, "inject-attacker.log", NULL);
  f = fopen (log_path, "ab");
  g_free (log_path);
  g_free (exe_dir);
  g_free (exe_path);
#else
  f = fopen (PKGTESTDIR "/inject-attacker.log", "ab");
#endif
  g_assert (f != NULL);

  fwrite (&c, 1, 1, f);
  fclose (f);
}


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
frida_agent_main (const char * data_string)
{
  append_to_log ('m');

  if (strlen (data_string) > 0)
    exit (atoi (data_string));
}

static void
append_to_log (char c)
{
  FILE *f;

  f = fopen (getenv ("FRIDA_LABRAT_LOGFILE"), "ab");
  g_assert (f != NULL);
  fwrite (&c, 1, 1, f);
  fclose (f);
}
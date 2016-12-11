#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void append_to_log (char c);

#ifdef _WIN32

#include <windows.h>

BOOL WINAPI
DllMain (HINSTANCE instance, DWORD reason, LPVOID reserved)
{
  (void) instance;
  (void) reserved;

  switch (reason)
  {
    case DLL_PROCESS_ATTACH:
      append_to_log ('>');
      break;
    case DLL_PROCESS_DETACH:
      append_to_log ('<');
      break;
    default:
      break;
  }
}

#else

__attribute__ ((constructor)) static void
on_load (void)
{
  append_to_log ('>');
}

__attribute__ ((destructor)) static void  q
on_unload (void)
{
  append_to_log ('<');
}

#endif

void
frida_agent_main (const char * data)
{
  if (strlen (data) > 0)
  {
    int exit_code = atoi (data);
    exit (exit_code);
  }
}

static void
append_to_log (char c)
{
  FILE * f;

  f = fopen (getenv ("FRIDA_LABRAT_LOGFILE"), "ab");
  assert (f != NULL);
  fwrite (&c, 1, 1, f);
  fclose (f);
}

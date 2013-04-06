#include <stdlib.h>
#include <string.h>

void
frida_agent_main (const char * data_string)
{
  if (strlen (data_string) > 0)
  {
    int exit_code = atoi (data_string);
    exit (exit_code);
  }
}

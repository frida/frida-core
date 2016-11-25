#include <stdlib.h>
#include <string.h>

void
frida_agent_main (const char * data)
{
  if (strlen (data) > 0)
  {
    int exit_code = atoi (data);
    exit (exit_code);
  }
}

#include "zid-tests.h"

#include <unistd.h>

gboolean
zid_test_process_backend_do_start (const char * filename,
    void ** handle, glong * id)
{
  pid_t pid;

  pid = fork ();
  if (pid == 0)
    execl (filename, filename, NULL);
  else
    *id = pid;

  return TRUE;
}

glong
zid_test_process_backend_do_join (void * handle, guint timeout_msec,
    GError ** error)
{
  return -1;
}

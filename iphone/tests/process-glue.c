#include "zid-tests.h"

#include <errno.h>
#include <unistd.h>

int
zid_test_process_backend_do_start (const char * filename, GError ** error)
{
  pid_t pid;

  pid = fork ();
  if (pid == 0)
  {
    execl (filename, filename, NULL);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "execl of %s failed: %d", filename, errno);
    return -1;
  }
  else if (pid > 0)
  {
    return pid;
  }

  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
      "fork failed: %d", errno);
  return -1;
}

int
zid_test_process_backend_do_join (int pid, guint timeout_msec,
    GError ** error)
{
  int status = -1;

  if (waitpid (pid, &status, 0) < 0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "waitpid failed: %d", errno);
  }

  return status;
}

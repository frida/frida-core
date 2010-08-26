#include "zid-tests.h"

#include <errno.h>
#include <unistd.h>
#include <gio/gio.h>

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
  GTimer * timer;

  timer = g_timer_new ();

  while (TRUE)
  {
    int ret;

    ret = waitpid (pid, &status, WNOHANG);
    if (ret > 0)
    {
      if (WIFEXITED (status))
        status = WEXITSTATUS (status);
      else
        status = -1;
      break;
    }
    else if (ret < 0 && errno != ETIMEDOUT)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "waitpid failed: %d", errno);
      break;
    }
    else if (g_timer_elapsed (timer, NULL) * 1000.0 >= timeout_msec)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
          "waitpid timed out");
      break;
    }

    g_usleep (G_USEC_PER_SEC / 50);
  }

  g_timer_destroy (timer);

  return status;
}

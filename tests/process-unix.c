#include "zed-tests.h"

#include <errno.h>
#include <sys/wait.h>
#ifdef HAVE_DARWIN
# include <mach-o/dyld.h>
#endif

static int zed_magic_self_handle = -1;

#ifdef HAVE_DARWIN

char *
zed_test_process_backend_filename_of (void * handle)
{
  guint image_count, image_idx;

  g_assert (handle == &zed_magic_self_handle);

  image_count = _dyld_image_count ();
  for (image_idx = 0; image_idx != image_count; image_idx++)
  {
    const gchar * image_path = _dyld_get_image_name (image_idx);

    if (g_str_has_suffix (image_path, "/zed-tests"))
      return g_strdup (image_path);
  }

  g_assert_not_reached ();
  return NULL;
}

#else

char *
zed_test_process_backend_filename_of (void * handle)
{
  g_assert (handle == &zed_magic_self_handle);

  return g_file_read_link ("/proc/self/exe", NULL);
}

#endif

void *
zed_test_process_backend_self_handle (void)
{
  return &zed_magic_self_handle;
}

guint
zed_test_process_backend_self_id (void)
{
  return getpid ();
}

void
zed_test_process_backend_do_start (const char * filename,
    void ** handle, guint * id, GError ** error)
{
  const gchar * override = g_getenv ("ZED_TARGET_PID");
  if (override != NULL)
  {
    *id = atoi (override);
    *handle = GSIZE_TO_POINTER (*id);
  }
  else
  {
    pid_t pid;

    pid = vfork ();
    if (pid == 0)
    {
      execl (filename, filename, NULL);
      _exit (1);
    }
    else if (pid < 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "vfork failed: %d", errno);
      return;
    }

    *handle = GSIZE_TO_POINTER (pid);
    *id = pid;
  }
}

int
zed_test_process_backend_do_join (void * handle, guint timeout_msec,
    GError ** error)
{
  int status = -1;
  GTimer * timer;

  timer = g_timer_new ();

  while (TRUE)
  {
    int ret;

    ret = waitpid (GPOINTER_TO_SIZE (handle), &status, WNOHANG);
    if (ret > 0)
    {
      if (WIFEXITED (status))
      {
        status = WEXITSTATUS (status);
      }
      else
      {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
            "child crashed");
        status = -1;
      }

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

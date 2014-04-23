#include "frida-tests.h"

#include <errno.h>
#ifdef HAVE_SPAWN_H
# include <spawn.h>
#endif
#include <sys/wait.h>
#ifdef HAVE_DARWIN
# include <mach-o/dyld.h>
#endif

static int frida_magic_self_handle = -1;

#ifdef HAVE_DARWIN

char *
frida_test_process_backend_filename_of (void * handle)
{
  guint image_count, image_idx;

  g_assert (handle == &frida_magic_self_handle);

  image_count = _dyld_image_count ();
  for (image_idx = 0; image_idx != image_count; image_idx++)
  {
    const gchar * image_path = _dyld_get_image_name (image_idx);

    if (g_str_has_suffix (image_path, "/frida-tests"))
      return g_strdup (image_path);
  }

  g_assert_not_reached ();
  return NULL;
}

#else

char *
frida_test_process_backend_filename_of (void * handle)
{
  g_assert (handle == &frida_magic_self_handle);

  return g_file_read_link ("/proc/self/exe", NULL);
}

#endif

void *
frida_test_process_backend_self_handle (void)
{
  return &frida_magic_self_handle;
}

guint
frida_test_process_backend_self_id (void)
{
  return getpid ();
}

void
frida_test_process_backend_do_start (const char * path, gchar ** argv,
    int argv_length, gchar ** envp, int envp_length, FridaTestArch arch,
    void ** handle, guint * id, GError ** error)
{
  const gchar * override = g_getenv ("FRIDA_TARGET_PID");
  if (override != NULL)
  {
    *id = atoi (override);
    *handle = GSIZE_TO_POINTER (*id);
  }
  else
  {
    pid_t pid;
#ifdef HAVE_SPAWN_H
    posix_spawnattr_t attr;
    sigset_t signal_mask_set;
    int result;

    posix_spawnattr_init (&attr);
    sigemptyset (&signal_mask_set);
    posix_spawnattr_setsigmask (&attr, &signal_mask_set);
    posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGMASK);

#ifdef HAVE_DARWIN
    if (arch == FRIDA_TEST_ARCH_OTHER)
    {
      cpu_type_t pref;
      size_t ocount;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
      pref = CPU_TYPE_X86_64;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
      pref = CPU_TYPE_X86;
#elif defined (HAVE_ARM)
      pref = CPU_TYPE_ARM64;
#elif defined (HAVE_ARM64)
      pref = CPU_TYPE_ARM;
#endif

      posix_spawnattr_setbinpref_np (&attr, 1, &pref, &ocount);
    }
#endif

    result = posix_spawn (&pid, path, NULL, &attr, argv, envp);

    posix_spawnattr_destroy (&attr);

    if (result != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "posix_spawn failed: %d", errno);
      return;
    }
#else
    pid = vfork ();
    if (pid == 0)
    {
      execv (path, argv);
      _exit (1);
    }
    else if (pid < 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "vfork failed: %d", errno);
      return;
    }
#endif

    *handle = GSIZE_TO_POINTER (pid);
    *id = pid;
  }
}

int
frida_test_process_backend_do_join (void * handle, guint timeout_msec,
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

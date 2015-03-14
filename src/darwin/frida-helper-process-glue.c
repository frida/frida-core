#include "frida-core.h"

#include <errno.h>
#include <spawn.h>
#include <sys/stat.h>

guint
frida_helper_process_spawn_helper (const gchar * path, gchar ** argv, int argv_length, GError ** error)
{
  gchar ** envp;
  pid_t pid;
  int result;

  chmod (path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

  envp = g_get_environ ();
  result = posix_spawn (&pid, path, NULL, NULL, argv, envp);
  g_strfreev (envp);
  if (result != 0)
    goto handle_spawn_error;

  return pid;

handle_spawn_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "posix_spawn failed: %s (%d)", strerror (errno), errno);
    return 0;
  }
}

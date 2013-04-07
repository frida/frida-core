#include "frida-core.h"

#include <crt_externs.h>
#include <errno.h>
#include <spawn.h>
#include <sys/stat.h>

guint
frida_fruitjector_helper_factory_spawn (const gchar * path, gchar ** argv, int argv_length, GError ** error)
{
  pid_t pid;

  chmod (path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

  if (posix_spawn (&pid, path, NULL, NULL, argv, *_NSGetEnviron ()) != 0)
    goto handle_spawn_error;

  return pid;

handle_spawn_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "posix_spawn failed: %s (%d)", strerror (errno), errno);
    return 0;
  }
}

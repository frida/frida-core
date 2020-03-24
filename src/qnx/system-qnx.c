#include "frida-core.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/procfs.h>

void
frida_system_get_frontmost_application (FridaHostApplicationInfo * result, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not implemented");
}

FridaHostApplicationInfo *
frida_system_enumerate_applications (int * result_length)
{
  *result_length = 0;

  return NULL;
}

FridaHostProcessInfo *
frida_system_enumerate_processes (int * result_length)
{
  GArray * processes;
  FridaImageData no_icon;
  GDir * proc_dir;
  const gchar * proc_name;

  static struct
  {
    procfs_debuginfo    info;
    char                buff [PATH_MAX];
  } procfs_name;

  processes = g_array_new (FALSE, FALSE, sizeof (FridaHostProcessInfo));
  frida_image_data_init_empty (&no_icon);

  proc_dir = g_dir_open ("/proc", 0, NULL);
  g_assert (proc_dir != NULL);

  while ((proc_name = g_dir_read_name (proc_dir)) != NULL)
  {
    guint pid;
    gchar * tmp = NULL, * name;
    gint fd;
    FridaHostProcessInfo * process_info;

    pid = strtoul (proc_name, &tmp, 10);
    if (*tmp != '\0')
      continue;

    tmp = g_build_filename ("/proc", proc_name, "as", NULL);
    fd = open(tmp, O_RDONLY);
    g_free (tmp);
    g_assert (fd != -1);

    if (devctl (fd, DCMD_PROC_MAPDEBUG_BASE, &procfs_name, sizeof (procfs_name), 0) != EOK)
      continue;

    name = g_path_get_basename (procfs_name.info.path);

    g_array_set_size (processes, processes->len + 1);
    process_info = &g_array_index (processes, FridaHostProcessInfo, processes->len - 1);
    frida_host_process_info_init (process_info, pid, name, &no_icon, &no_icon);

    g_free (name);
  }

  g_dir_close (proc_dir);

  frida_image_data_destroy (&no_icon);

  *result_length = processes->len;

  return (FridaHostProcessInfo *) g_array_free (processes, FALSE);
}

void
frida_system_kill (guint pid)
{
  kill (pid, SIGKILL);
}

gchar *
frida_temporary_directory_get_system_tmp (void)
{
  return g_strdup (g_get_tmp_dir ());
}

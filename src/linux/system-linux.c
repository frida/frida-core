#include "frida-core.h"

#include <string.h>

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

  processes = g_array_new (FALSE, FALSE, sizeof (FridaHostProcessInfo));
  frida_image_data_init_empty (&no_icon);

  proc_dir = g_dir_open ("/proc", 0, NULL);
  g_assert (proc_dir != NULL);

  while ((proc_name = g_dir_read_name (proc_dir)) != NULL)
  {
    guint pid;
    gchar * end;
    gchar * exe_path = NULL;
    gboolean is_userland;
    gchar * cmdline_path = NULL;
    gchar * cmdline_data = NULL;
    gchar * name = NULL;
    FridaHostProcessInfo * info;

    pid = strtoul (proc_name, &end, 10);
    if (*end != '\0')
      goto next;

    exe_path = g_build_filename ("/proc", proc_name, "exe", NULL);

    is_userland = g_file_test (exe_path, G_FILE_TEST_EXISTS);
    if (!is_userland)
      goto next;

    cmdline_path = g_build_filename ("/proc", proc_name, "cmdline", NULL);

    g_file_get_contents (cmdline_path, &cmdline_data, NULL, NULL);
    if (cmdline_data == NULL)
      goto next;

    if (g_str_has_prefix (cmdline_data, "/proc/"))
    {
      gchar * program_path;

      program_path = g_file_read_link (exe_path, NULL);
      name = g_path_get_basename (program_path);
      g_free (program_path);
    }
    else
    {
      gchar * space_dash;

      space_dash = strstr (cmdline_data, " -");
      if (space_dash != NULL)
        *space_dash = '\0';

      name = g_path_get_basename (cmdline_data);
    }

    g_array_set_size (processes, processes->len + 1);
    info = &g_array_index (processes, FridaHostProcessInfo, processes->len - 1);
    frida_host_process_info_init (info, pid, name, &no_icon, &no_icon);

next:
    g_free (name);
    g_free (cmdline_data);
    g_free (cmdline_path);
    g_free (exe_path);
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
#ifdef HAVE_ANDROID
  if (getuid () == 0)
    return g_strdup ("/data/local/tmp");
#endif

  return g_strdup (g_get_tmp_dir ());
}

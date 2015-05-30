#include "frida-core.h"

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
  frida_image_data_init (&no_icon, 0, 0, 0, "");

  proc_dir = g_dir_open ("/proc", 0, NULL);
  g_assert (proc_dir != NULL);

  while ((proc_name = g_dir_read_name (proc_dir)) != NULL)
  {
    guint pid;
    gchar * tmp = NULL, * cmdline = NULL, * name;
    gboolean is_process;
    FridaHostProcessInfo * process_info;

    pid = strtoul (proc_name, &tmp, 10);
    if (*tmp != '\0')
      continue;

    tmp = g_build_filename ("/proc", proc_name, "exe", NULL);
    is_process = g_file_test (tmp, G_FILE_TEST_EXISTS);
    g_free (tmp);

    if (!is_process)
      continue;

    tmp = g_build_filename ("/proc", proc_name, "cmdline", NULL);
    g_file_get_contents (tmp, &cmdline, NULL, NULL);
    g_free (tmp);

    if (cmdline == NULL)
      continue;

    name = g_path_get_basename (cmdline);
    g_free (cmdline);

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
#ifdef HAVE_ANDROID
  return g_strdup ("/data/local/tmp");
#else
  return g_strdup (g_get_tmp_dir ());
#endif
}

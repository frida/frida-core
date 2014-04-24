#include "frida-core.h"

FridaHostProcessInfo *
frida_system_enumerate_processes (int * result_length1)
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
    gchar * tmp = NULL;
    gchar * name;
    FridaHostProcessInfo * process_info;

    pid = strtoul (proc_name, &tmp, 10);
    if (*tmp != '\0')
      continue;

    tmp = g_build_filename ("/proc", proc_name, "exe", NULL);
    name = g_file_read_link (tmp, NULL);
    g_free (tmp);

    if (name == NULL)
      continue;

    tmp = g_path_get_basename (name);
    g_free (name);
    name = tmp;

    g_array_set_size (processes, processes->len + 1);
    process_info = &g_array_index (processes, FridaHostProcessInfo, processes->len - 1);
    frida_host_process_info_init (process_info, pid, name, &no_icon, &no_icon);

    g_free (name);
  }

  g_dir_close (proc_dir);

  *result_length1 = processes->len;
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

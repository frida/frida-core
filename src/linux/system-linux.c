#include "frida-core.h"

#include <string.h>

static gchar * b2g_get_app_id (const gchar * fd);
static gchar * b2g_get_app_name (const gchar * str);

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
  GArray * applications;
  GDir * proc_dir;
  const gchar * proc_name;

  applications = g_array_new (FALSE, TRUE, sizeof (FridaHostApplicationInfo));

  proc_dir = g_dir_open ("/proc", 0, NULL);
  g_assert (proc_dir != NULL);

  while ((proc_name = g_dir_read_name (proc_dir)) != NULL)
  {
    gchar * tmp;
    guint pid;
    gchar * bin_path;
    gboolean is_process, is_b2g;
    gchar * status;
    gsize status_len;
    gchar * app_id;
    gchar * app_name;
    FridaHostApplicationInfo * info;

    tmp = NULL;
    pid = strtoul (proc_name, &tmp, 10);
    if (*tmp != '\0')
      continue;

    tmp = g_build_filename ("/proc", proc_name, "exe", NULL);
    bin_path = g_file_read_link (tmp, NULL);

    is_process = g_file_test (tmp, G_FILE_TEST_EXISTS);
    is_b2g = g_strcmp0 (bin_path, "/system/b2g/b2g") == 0;

    g_free (bin_path);
    g_free (tmp);

    if (bin_path == NULL || !is_process || !is_b2g)
      continue;

    tmp = g_build_filename ("/proc", proc_name, "status", NULL);
    if (!g_file_get_contents (tmp, &status, &status_len, NULL))
      status = NULL;
    g_free (tmp);

    tmp = g_build_filename ("/proc", proc_name, "fd", NULL);
    app_id = b2g_get_app_id (tmp);
    if (app_id == NULL)
      app_id = g_strdup ("");
    g_free (tmp);

    app_name = b2g_get_app_name (status);

    g_free (status);

    if (app_name == NULL)
    {
      g_free (app_id);
      continue;
    }

    g_array_set_size (applications, applications->len + 1);
    info = &g_array_index (applications, FridaHostApplicationInfo, applications->len - 1);
    info->_identifier = app_id;
    info->_name = app_name;
    info->_pid = pid;
    frida_image_data_init_empty (&info->_small_icon);
    frida_image_data_init_empty (&info->_large_icon);
  }

  g_dir_close (proc_dir);

  *result_length = applications->len;

  return (FridaHostApplicationInfo *) g_array_free (applications, FALSE);
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

static gchar *
b2g_get_app_id (const gchar * fd)
{
  gchar * app_id = NULL;
  GDir * fd_dir;
  const gchar * fn;

  if (fd == NULL)
    return NULL;

  fd_dir = g_dir_open (fd, 0, NULL);
  g_assert (fd_dir != NULL);

  while (((fn = g_dir_read_name (fd_dir)) != NULL) && app_id == NULL)
  {
    gchar * fd_file, * target;

    fd_file = g_build_filename (fd, fn, NULL);
    target = g_file_read_link (fd_file, NULL);
    if (target != NULL)
    {
      gchar * app_zip;

      app_zip = strstr (target, "/application.zip");
      if (app_zip != NULL)
      {
        *app_zip = 0;
        for (--app_zip; app_zip != target && *app_zip != '/'; app_zip--);

        app_id = g_strdup (app_zip + 1);
      }
    }

    g_free (target);
    g_free (fd_file);
  }

  g_dir_close (fd_dir);

  return app_id;
}

static gchar *
b2g_get_app_name (const gchar * str)
{
  const gchar * record, * name, * nl;

  if (str == NULL)
    return NULL;

  record = strstr (str, "Name:");
  if (record == NULL)
    return NULL;

  for (name = record + 5; g_ascii_isspace (*name); name++);

  nl = strchr (name, '\n');
  if (nl == NULL)
    return NULL;

  return g_strndup (name, (guint) (size_t) (nl - name));
}


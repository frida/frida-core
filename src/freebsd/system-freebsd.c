#include "frida-core.h"

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#ifdef HAVE_PROSPERO
# include <json-glib/json-glib.h>
# include <ps5/kernel.h>

# define FRIDA_MAIN_MODULE_HANDLE 0
# define FRIDA_APP_INFO_SIZE 256
# define FRIDA_APP_INFO_TITLE_ID_OFFSET 0x10
# define FRIDA_APP_INFO_TITLE_ID_SIZE 10

extern int kernel_dynlib_path (pid_t pid, guint32 handle, gchar * buffer, gsize size);
extern int sceKernelGetAppInfo (pid_t pid, void * info);

static void frida_collect_applications_in (const gchar * root, GHashTable * pids_by_title, FridaScope scope,
    GArray * result);
static gboolean frida_collect_app_metadata (const gchar * dir, gchar ** identifier, gchar ** name, gchar ** icon_path);
static GHashTable * frida_query_pids_by_title (void);
static gchar * frida_query_title_id (pid_t pid);
static gchar * frida_find_app_icon (const gchar * title_id);
static void frida_add_app_icon (GHashTable * parameters, const gchar * icon_path);
#endif

typedef struct _FridaEnumerateProcessesOperation FridaEnumerateProcessesOperation;

struct _FridaEnumerateProcessesOperation
{
  FridaScope scope;

  GArray * result;
};

static void frida_collect_process_info_from_pid (guint pid, FridaEnumerateProcessesOperation * op);
static void frida_collect_process_info_from_kinfo (struct kinfo_proc * process, FridaEnumerateProcessesOperation * op);

static void frida_add_process_metadata (GHashTable * parameters, const struct kinfo_proc * process);

static struct kinfo_proc * frida_system_query_kinfo_procs (guint * count);
static gboolean frida_system_query_proc_pathname (pid_t pid, gchar * path, gsize size);
static GVariant * frida_query_process_argv (guint pid);
#ifndef HAVE_PROSPERO
static GVariant * frida_uid_to_name (uid_t uid);
#endif

void
frida_system_get_frontmost_application (FridaFrontmostQueryOptions * options, FridaHostApplicationInfo * result, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not implemented");
}

FridaHostApplicationInfo *
frida_system_enumerate_applications (FridaApplicationQueryOptions * options, int * result_length)
{
#ifdef HAVE_PROSPERO
  GArray * result;
  GHashTable * pids_by_title;
  FridaScope scope = frida_application_query_options_get_scope (options);

  result = g_array_new (FALSE, FALSE, sizeof (FridaHostApplicationInfo));

  pids_by_title = frida_query_pids_by_title ();

  frida_collect_applications_in ("/user/appmeta", pids_by_title, scope, result);
  frida_collect_applications_in ("/system_ex/app", pids_by_title, scope, result);

  g_hash_table_unref (pids_by_title);

  *result_length = result->len;

  return (FridaHostApplicationInfo *) g_array_free (result, FALSE);
#else
  *result_length = 0;

  return NULL;
#endif
}

#ifdef HAVE_PROSPERO

static void
frida_collect_applications_in (const gchar * root,
                               GHashTable * pids_by_title,
                               FridaScope scope,
                               GArray * result)
{
  GDir * dir;
  const gchar * entry;

  dir = g_dir_open (root, 0, NULL);
  if (dir == NULL)
    return;

  while ((entry = g_dir_read_name (dir)) != NULL)
  {
    gchar * path;
    FridaHostApplicationInfo info = { 0, };
    gchar * icon_path = NULL;

    path = g_build_filename (root, entry, NULL);

    if (frida_collect_app_metadata (path, &info.identifier, &info.name, &icon_path))
    {
      info.pid = GPOINTER_TO_UINT (g_hash_table_lookup (pids_by_title, info.identifier));
      info.parameters = frida_make_parameters_dict ();

      if (icon_path != NULL && scope == FRIDA_SCOPE_FULL)
        frida_add_app_icon (info.parameters, icon_path);

      g_array_append_val (result, info);
    }

    g_free (icon_path);
    g_free (path);
  }

  g_dir_close (dir);
}

static gboolean
frida_collect_app_metadata (const gchar * dir,
                            gchar ** identifier,
                            gchar ** name,
                            gchar ** icon_path)
{
  gboolean success = FALSE;
  gchar * param_path, * icon_candidate;
  JsonParser * parser;
  JsonReader * reader = NULL;
  gchar * title_id, * language;
  const gchar * title_name;

  param_path = g_build_filename (dir, "param.json", NULL);
  if (!g_file_test (param_path, G_FILE_TEST_IS_REGULAR))
  {
    g_free (param_path);
    param_path = g_build_filename (dir, "sce_sys", "param.json", NULL);
  }

  parser = json_parser_new ();
  if (!json_parser_load_from_file (parser, param_path, NULL))
    goto beach;

  reader = json_reader_new (json_parser_get_root (parser));

  json_reader_read_member (reader, "titleId");
  title_id = g_strdup (json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  if (title_id == NULL)
    goto beach;

  *identifier = title_id;
  *name = g_strdup (title_id);

  json_reader_read_member (reader, "localizedParameters");

  json_reader_read_member (reader, "defaultLanguage");
  language = g_strdup (json_reader_get_string_value (reader));
  json_reader_end_member (reader);

  if (language != NULL)
  {
    json_reader_read_member (reader, language);
    json_reader_read_member (reader, "titleName");

    title_name = json_reader_get_string_value (reader);
    if (title_name != NULL && title_name[0] != '\0')
    {
      g_free (*name);
      *name = g_strdup (title_name);
    }

    json_reader_end_member (reader);
    json_reader_end_member (reader);

    g_free (language);
  }

  json_reader_end_member (reader);

  icon_candidate = g_build_filename (dir, "icon0.png", NULL);
  if (!g_file_test (icon_candidate, G_FILE_TEST_IS_REGULAR))
  {
    g_free (icon_candidate);
    icon_candidate = g_build_filename (dir, "sce_sys", "icon0.png", NULL);
  }
  if (g_file_test (icon_candidate, G_FILE_TEST_IS_REGULAR))
    *icon_path = icon_candidate;
  else
    g_free (icon_candidate);

  success = TRUE;

beach:
  g_clear_object (&reader);
  g_object_unref (parser);
  g_free (param_path);

  return success;
}

static GHashTable *
frida_query_pids_by_title (void)
{
  GHashTable * pids_by_title;
  struct kinfo_proc * processes;
  guint count, i;

  pids_by_title = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  processes = frida_system_query_kinfo_procs (&count);
  if (processes == NULL)
    return pids_by_title;

  for (i = 0; i != count; i++)
  {
    pid_t pid = processes[i].ki_pid;
    gchar * title_id;

    title_id = frida_query_title_id (pid);
    if (title_id != NULL)
      g_hash_table_insert (pids_by_title, title_id, GUINT_TO_POINTER (pid));
  }

  g_free (processes);

  return pids_by_title;
}

static gchar *
frida_query_title_id (pid_t pid)
{
  guint8 info[FRIDA_APP_INFO_SIZE];
  const gchar * title_id;

  memset (info, 0, sizeof (info));

  if (sceKernelGetAppInfo (pid, info) != 0)
    return NULL;

  title_id = (const gchar *) (info + FRIDA_APP_INFO_TITLE_ID_OFFSET);
  if (title_id[0] == '\0')
    return NULL;

  return g_strndup (title_id, FRIDA_APP_INFO_TITLE_ID_SIZE);
}

static gchar *
frida_find_app_icon (const gchar * title_id)
{
  const gchar * roots[] = { "/user/appmeta", "/system_ex/app" };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (roots); i++)
  {
    gchar * direct, * nested;

    direct = g_build_filename (roots[i], title_id, "icon0.png", NULL);
    if (g_file_test (direct, G_FILE_TEST_IS_REGULAR))
      return direct;
    g_free (direct);

    nested = g_build_filename (roots[i], title_id, "sce_sys", "icon0.png", NULL);
    if (g_file_test (nested, G_FILE_TEST_IS_REGULAR))
      return nested;
    g_free (nested);
  }

  return NULL;
}

static void
frida_add_app_icon (GHashTable * parameters,
                    const gchar * icon_path)
{
  gchar * data;
  gsize size;
  GVariantBuilder builder;

  if (!g_file_get_contents (icon_path, &data, &size, NULL))
    return;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

  g_variant_builder_open (&builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add (&builder, "{sv}", "format", g_variant_new_string ("png"));
  g_variant_builder_add (&builder, "{sv}", "image",
      g_variant_new_from_data (G_VARIANT_TYPE ("ay"), data, size, TRUE, g_free, data));
  g_variant_builder_close (&builder);

  g_hash_table_insert (parameters, g_strdup ("icons"), g_variant_ref_sink (g_variant_builder_end (&builder)));
}

#endif

FridaHostProcessInfo *
frida_system_enumerate_processes (FridaProcessQueryOptions * options, int * result_length)
{
  FridaEnumerateProcessesOperation op;

  op.scope = frida_process_query_options_get_scope (options);

  op.result = g_array_new (FALSE, FALSE, sizeof (FridaHostProcessInfo));

  if (frida_process_query_options_has_selected_pids (options))
  {
    frida_process_query_options_enumerate_selected_pids (options, (GFunc) frida_collect_process_info_from_pid, &op);
  }
  else
  {
    struct kinfo_proc * processes;
    guint count, i;

    processes = frida_system_query_kinfo_procs (&count);

    for (i = 0; i != count; i++)
      frida_collect_process_info_from_kinfo (&processes[i], &op);

    g_free (processes);
  }

  *result_length = op.result->len;

  return (FridaHostProcessInfo *) g_array_free (op.result, FALSE);
}

static void
frida_collect_process_info_from_pid (guint pid, FridaEnumerateProcessesOperation * op)
{
  struct kinfo_proc process;
  size_t size;
  int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  gint err G_GNUC_UNUSED;

  size = sizeof (process);

  err = sysctl (mib, G_N_ELEMENTS (mib), &process, &size, NULL, 0);
  g_assert (err != -1);

  if (size == 0)
    return;

  frida_collect_process_info_from_kinfo (&process, op);
}

static void
frida_collect_process_info_from_kinfo (struct kinfo_proc * process, FridaEnumerateProcessesOperation * op)
{
  FridaHostProcessInfo info = { 0, };
  FridaScope scope = op->scope;
  gboolean still_alive;
  gchar path[PATH_MAX];

  info.pid = process->ki_pid;

  info.parameters = frida_make_parameters_dict ();

  if (scope != FRIDA_SCOPE_MINIMAL)
    frida_add_process_metadata (info.parameters, process);

  still_alive = frida_system_query_proc_pathname (info.pid, path, sizeof (path));
  if (still_alive)
  {
#ifdef HAVE_PROSPERO
    info.name = g_strdup (process->ki_comm);
#else
    if (path[0] != '\0')
      info.name = g_path_get_basename (path);
    else
      info.name = g_strdup (process->ki_comm);
#endif

    if (scope != FRIDA_SCOPE_MINIMAL)
    {
      GVariant * argv;

      g_hash_table_insert (info.parameters, g_strdup ("path"), g_variant_ref_sink (g_variant_new_string (path)));

      argv = frida_query_process_argv (info.pid);
      if (argv != NULL)
        g_hash_table_insert (info.parameters, g_strdup ("argv"), g_variant_ref_sink (argv));
    }
  }

#ifdef HAVE_PROSPERO
  if (still_alive && scope != FRIDA_SCOPE_MINIMAL)
  {
    gchar * title_id;

    title_id = frida_query_title_id (info.pid);
    if (title_id != NULL)
    {
      g_hash_table_insert (info.parameters, g_strdup ("identifier"),
          g_variant_ref_sink (g_variant_new_string (title_id)));

      if (scope == FRIDA_SCOPE_FULL)
      {
        gchar * icon_path;

        icon_path = frida_find_app_icon (title_id);
        if (icon_path != NULL)
        {
          frida_add_app_icon (info.parameters, icon_path);
          g_free (icon_path);
        }
      }

      g_free (title_id);
    }
  }
#endif

  if (still_alive)
    g_array_append_val (op->result, info);
  else
    frida_host_process_info_destroy (&info);
}

void
frida_system_kill (guint pid)
{
  kill (pid, SIGKILL);
}

gchar *
frida_temporary_directory_get_system_tmp (void)
{
#ifdef HAVE_PROSPERO
  return g_strdup ("/user/temp");
#else
  return g_strdup (g_get_tmp_dir ());
#endif
}

static void
frida_add_process_metadata (GHashTable * parameters, const struct kinfo_proc * process)
{
  const struct timeval * started = &process->ki_start;
  GDateTime * t0, * t1;

#ifndef HAVE_PROSPERO
  g_hash_table_insert (parameters, g_strdup ("user"), frida_uid_to_name (process->ki_uid));
#endif

  g_hash_table_insert (parameters, g_strdup ("ppid"), g_variant_ref_sink (g_variant_new_int64 (process->ki_ppid)));

  t0 = g_date_time_new_from_unix_utc (started->tv_sec);
  t1 = g_date_time_add (t0, started->tv_usec);
  g_hash_table_insert (parameters, g_strdup ("started"), g_variant_ref_sink (g_variant_new_take_string (g_date_time_format_iso8601 (t1))));
  g_date_time_unref (t1);
  g_date_time_unref (t0);
}

static struct kinfo_proc *
frida_system_query_kinfo_procs (guint * count)
{
  gboolean success = FALSE;
  int mib[3];
  struct kinfo_proc * processes = NULL;
  size_t size;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PROC;

  size = 0;
  if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0)
    goto beach;

  while (TRUE)
  {
    size_t previous_size;
    gboolean still_too_small;

    processes = g_realloc (processes, size);

    previous_size = size;
    if (sysctl (mib, G_N_ELEMENTS (mib), processes, &size, NULL, 0) == 0)
      break;

    still_too_small = errno == ENOMEM && size == previous_size;
    if (!still_too_small)
      goto beach;

    size += size / 10;
  }

  {
    guint8 * cursor = (guint8 *) processes;
    const guint8 * end = cursor + size;
    guint n = 0;

    while (cursor != end)
    {
      gint record_size = *((gint *) cursor);

      if (record_size <= 0 || cursor + record_size > end)
        break;

      memmove (&processes[n], cursor, MIN ((gsize) record_size, sizeof (struct kinfo_proc)));
      n++;

      cursor += record_size;
    }

    *count = n;
  }

  success = TRUE;

beach:
  if (!success)
    g_clear_pointer (&processes, g_free);

  return processes;
}

static gboolean
frida_system_query_proc_pathname (pid_t pid, gchar * path, gsize size)
{
#ifdef HAVE_PROSPERO
  if (kernel_dynlib_path (pid, FRIDA_MAIN_MODULE_HANDLE, path, size) != 0)
    path[0] = '\0';

  return kill (pid, 0) == 0 || errno == EPERM;
#else
  gboolean success;
  int mib[4];
  size_t n;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = pid;

  n = size;

  success = sysctl (mib, G_N_ELEMENTS (mib), path, &n, NULL, 0) == 0;

  if (n == 0)
    path[0] = '\0';

  return success;
#endif
}

static GVariant *
frida_query_process_argv (guint pid)
{
  GVariant * result = NULL;
  int mib[4];
  gchar * buffer = NULL;
  size_t size;
  const gchar * cursor, * end;
  GVariantBuilder builder;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_ARGS;
  mib[3] = pid;

  size = 0;
  if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0 || size == 0)
    goto beach;

  buffer = g_malloc (size);
  if (sysctl (mib, G_N_ELEMENTS (mib), buffer, &size, NULL, 0) != 0)
    goto beach;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("as"));

  cursor = buffer;
  end = buffer + size;
  while (cursor != end)
  {
    gsize arg_length = strnlen (cursor, end - cursor);
    g_variant_builder_add_value (&builder, g_variant_new_take_string (g_strndup (cursor, arg_length)));
    cursor += arg_length;
    if (cursor != end)
      cursor++;
  }

  result = g_variant_builder_end (&builder);

beach:
  g_free (buffer);

  return result;
}

#ifndef HAVE_PROSPERO

static GVariant *
frida_uid_to_name (uid_t uid)
{
  GVariant * name;
  static size_t cached_buffer_size = 0;
  char * buffer;
  size_t size;
  struct passwd pwd, * entry;
  int error;

  if (cached_buffer_size == 0)
  {
    long n = sysconf (_SC_GETPW_R_SIZE_MAX);
    if (n > 0)
      cached_buffer_size = n;
  }

  size = (cached_buffer_size != 0) ? cached_buffer_size : 128;
  buffer = g_malloc (size);
  entry = NULL;

  while ((error = getpwuid_r (uid, &pwd, buffer, size, &entry)) == ERANGE)
  {
    size *= 2;
    buffer = g_realloc (buffer, size);
  }

  if (error == 0 && size > cached_buffer_size)
    cached_buffer_size = size;

  if (entry != NULL)
    name = g_variant_new_string (entry->pw_name);
  else
    name = g_variant_new_take_string (g_strdup_printf ("%u", uid));
  name = g_variant_ref_sink (name);

  g_free (buffer);

  return name;
}

#endif

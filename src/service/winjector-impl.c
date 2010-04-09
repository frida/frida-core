#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

#define PIPE_BUFSIZE 4096
#define PIPE_TIMEOUT 5000

typedef struct _ZedServiceWinjectorInjectAsyncData
    ZedServiceWinjectorInjectAsyncData;

static void zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data);

#include "src/service/winjector.c"

typedef struct _ZedWinjectorPipe ZedWinjectorPipe;
typedef struct _ZedWinjectorHelper ZedWinjectorHelper;
typedef struct _ZedHelperExecutable ZedHelperExecutable;

struct _ZedWinjectorPipe
{
  HANDLE handle;
};

struct _ZedWinjectorHelper
{
  TCHAR * tempfile;

  HANDLE process;
  HANDLE stdin_rd;
  HANDLE stdin_wr;
  HANDLE stdout_rd;
  HANDLE stdout_wr;
};

struct _ZedHelperExecutable
{
  const TCHAR * name;
  const guint8 * data;
  guint size;
};

static gboolean create_pipe_and_connect (ZedServiceWinjector * self,
    OVERLAPPED * overlapped);

static ZedWinjectorHelper * create_helper (
    const ZedHelperExecutable * executable, const TCHAR * temp_dir);
static void clear_helper (ZedWinjectorHelper ** helper);
static void destroy_helper (ZedWinjectorHelper * helper);
static void send_inject_request (ZedWinjectorHelper * helper, glong target_pid,
    const gchar * filename);
static gboolean receive_inject_response (ZedWinjectorHelper * helper,
    GError ** err);

static TCHAR * create_temp_directory (void);
static void clear_temp_directory (TCHAR ** temp_dir);
static void destroy_temp_directory (TCHAR * temp_dir);

static TCHAR * create_temp_executable (const TCHAR * temp_dir,
    const TCHAR * name_prefix, const guint8 * data, guint size);

static void clear_handle (HANDLE * handle);

extern const unsigned int zed_data_winjector_helper_32_size;
extern const unsigned char zed_data_winjector_helper_32_data[];

static void
zed_service_winjector_inject_async_co (
                                       ZedServiceWinjectorInjectAsyncData * data)
{
  zed_service_winjector_ensure_worker_running (data->self);
  zed_service_winjector_queue_request (data->self, data);
}

static void *
zed_service_winjector_worker (ZedServiceWinjector * self)
{
  OVERLAPPED conn_overlapped;
  gboolean pending_io;

  pending_io = create_pipe_and_connect (self, &conn_overlapped);

  return NULL;
}


static void
zed_service_winjector_ensure_helper_started (ZedServiceWinjector * self)
{
  ZedServiceWinjectorPrivate * priv = self->priv;
  ZedHelperExecutable helper32_executable;

  if (priv->helper_tempdir != NULL)
    return;

  priv->helper_tempdir = create_temp_directory ();
  if (priv->helper_tempdir == NULL)
    goto error;

  helper32_executable.name = _T ("winjector-helper-32");
  helper32_executable.data = zed_data_winjector_helper_32_data;
  helper32_executable.size = zed_data_winjector_helper_32_size;
  priv->helper32 = create_helper (&helper32_executable, priv->helper_tempdir);
  if (priv->helper32 == NULL)
    goto error;

  return;

error:
  clear_helper ((ZedWinjectorHelper **) &priv->helper32);
  clear_temp_directory ((TCHAR **) &priv->helper_tempdir);
}

static void
zed_service_winjector_ensure_helper_closed (ZedServiceWinjector* self)
{
  ZedServiceWinjectorPrivate * priv = self->priv;

  if (priv->helper_tempdir == NULL)
    return;

  clear_helper ((ZedWinjectorHelper **) &priv->helper32);

  clear_temp_directory ((TCHAR **) &priv->helper_tempdir);
}

static void
zed_service_winjector_process_request (ZedServiceWinjector * self,
    void * request)
{
  ZedServiceWinjectorInjectAsyncData * data = request;
  GSimpleAsyncResult * res;
  ZedWinjectorHelper * helper;
  GError * err = NULL;
  gboolean success;

  res = data->_async_result;

  zed_service_winjector_ensure_helper_started (self);

  helper = self->priv->helper32;

  send_inject_request (helper, data->target_pid, data->filename);

  success = receive_inject_response (helper, &err);
  if (success)
  {
    /* nothing for now */
  }
  else
  {
    g_simple_async_result_set_from_error (res, err);
    g_clear_error (&err);
  }

  g_simple_async_result_complete_in_idle (res);
  g_object_unref (res);
}

static gboolean
create_pipe_and_connect (ZedServiceWinjector * self, OVERLAPPED * overlapped)
{
  TCHAR * pipe_name;

  pipe_name = NULL;
  //pipe_name = generate_pipe_name ();

  /*
  self->priv->cur_pipe = CreateNamedPipe (pipe_name,
      PIPE_ACCESS_DUPLEX |
      FILE_FLAG_OVERLAPPED |
      PIPE_TYPE_MESSAGE |
      PIPE_READMODE_MESSAGE,
      PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      PIPE_BUFSIZE * sizeof (TCHAR),
      PIPE_BUFSIZE * sizeof (TCHAR),
      PIPE_TIMEOUT,
      NULL);*/

  return FALSE;
}

static ZedWinjectorHelper *
create_helper (const ZedHelperExecutable * executable, const TCHAR * temp_dir)
{
  ZedWinjectorHelper * helper = NULL;
  SECURITY_ATTRIBUTES sec_attrs = { 0, };
  STARTUPINFO startup_info = { 0, };
  PROCESS_INFORMATION process_info = { 0, };
  BOOL success;

  helper = g_new0 (ZedWinjectorHelper, 1);

  helper->tempfile = create_temp_executable (temp_dir,
      executable->name, executable->data, executable->size);
  if (helper->tempfile == NULL)
    goto error;

  sec_attrs.nLength = sizeof (sec_attrs);
  sec_attrs.bInheritHandle = TRUE;
  sec_attrs.lpSecurityDescriptor = NULL;

  CreatePipe (&helper->stdin_rd, &helper->stdin_wr, &sec_attrs, 0);
  SetHandleInformation (helper->stdin_wr, HANDLE_FLAG_INHERIT, FALSE);

  CreatePipe (&helper->stdout_rd, &helper->stdout_wr, &sec_attrs, 0);
  SetHandleInformation (helper->stdout_rd, HANDLE_FLAG_INHERIT, FALSE);

  startup_info.cb = sizeof (startup_info);
  startup_info.hStdInput = helper->stdin_rd;
  startup_info.hStdOutput = helper->stdout_wr;
  startup_info.hStdError = helper->stdout_wr;
  startup_info.dwFlags |= STARTF_USESTDHANDLES;

  success = CreateProcess (helper->tempfile, NULL, &sec_attrs, NULL, TRUE, 0,
      NULL, NULL, &startup_info, &process_info);
  if (!success)
    goto error;
  helper->process = process_info.hProcess;
  CloseHandle (process_info.hThread);

  return helper;

error:
  clear_helper (&helper);
  return NULL;
}

static void
clear_helper (ZedWinjectorHelper ** helper)
{
  if (*helper != NULL)
  {
    destroy_helper (*helper);
    *helper = NULL;
  }
}

static void
destroy_helper (ZedWinjectorHelper * helper)
{
  clear_handle (&helper->stdin_rd);
  clear_handle (&helper->stdin_wr);
  clear_handle (&helper->stdout_rd);
  clear_handle (&helper->stdout_wr);

  if (helper->process != NULL)
  {
    WaitForSingleObject (helper->process, INFINITE);
    CloseHandle (helper->process);
  }

  if (helper->tempfile != NULL)
  {
    DeleteFile (helper->tempfile);
    g_free (helper->tempfile);
  }

  g_free (helper);
}

static void
send_inject_request (ZedWinjectorHelper * helper, glong target_pid,
    const gchar * filename)
{
  gchar * line_utf8;
  CPINFOEXA cpi;
  gchar * line;
  gsize line_size;
  DWORD bytes_written;

  line_utf8 = g_strdup_printf ("%u %s\n", target_pid, filename);
  GetCPInfoExA (GetConsoleCP (), 0, &cpi);
  line = g_convert (line_utf8, -1, cpi.CodePageName, "utf-8", NULL, &line_size,
      NULL);
  g_free (line_utf8);

  WriteFile (helper->stdin_wr, line, line_size, &bytes_written, NULL);
  FlushFileBuffers (helper->stdin_wr);

  g_free (line);
}

static gboolean
receive_inject_response (ZedWinjectorHelper * helper, GError ** err)
{
  gboolean result;
  const guint line_size = 4096;
  gchar * line;
  DWORD bytes_read;
  gchar * line_utf8;
  CPINFOEXA cpi;

  line = g_malloc0 (line_size);
  ReadFile (helper->stdout_rd, line, line_size - 1, &bytes_read, NULL);

  GetCPInfoExA (GetConsoleOutputCP (), 0, &cpi);
  line_utf8 = g_convert (line, -1, "utf-8", cpi.CodePageName, NULL, NULL, NULL);
  g_free (line);

  g_strchomp (line_utf8);

  if (strcmp (line_utf8, "SUCCESS") == 0)
  {
    result = TRUE;
  }
  else
  {
    gchar ** tokens;
    gint error_code;
    gchar * error_message;

    result = FALSE;

    tokens = g_strsplit (line_utf8, " ", 3);
    g_assert (strcmp (tokens[0], "ERROR") == 0);
    error_code = atoi (tokens[1]);
    error_message = tokens[2];

    *err = g_error_new_literal (ZED_SERVICE_WINJECTOR_ERROR, error_code,
        error_message);

    g_strfreev (tokens);
  }

  g_free (line_utf8);

  return result;
}

static TCHAR *
generate_pipe_name (void)
{
  const guint max_chars = MAX_PATH;
  TCHAR * name;
  GUID id;
  guint len;

  name = g_new0 (TCHAR, max_chars);

  StringCchCat (name, max_chars, _T ("\\\\.\\pipe\\zed"));

  CoCreateGuid (&id);
  len = _tcslen (name);
  StringFromGUID2 (&id, name + len, max_chars - len - 1);
  name[len] = _T ('-');
  name[_tcslen (name) - 1] = _T ('\0');

  return name;
}

static TCHAR *
create_temp_directory (void)
{
  const guint max_chars = MAX_PATH;
  TCHAR * name;
  GUID id;
  guint len;

  name = g_new0 (TCHAR, max_chars);
  if (GetTempPath (max_chars, name) == 0)
    goto error;
  if (CoCreateGuid (&id) != S_OK)
    goto error;
  StringCchCat (name, max_chars, _T ("zed"));
  len = _tcslen (name);
  StringFromGUID2 (&id, name + len, max_chars - len - 1);
  name[len] = _T ('-');
  name[_tcslen (name) - 1] = _T ('\\');

  if (!CreateDirectory (name, NULL))
    goto error;

  return name;

error:
  g_free (name);
  return NULL;
}

static void
clear_temp_directory (TCHAR ** temp_dir)
{
  if (*temp_dir != NULL)
  {
    destroy_temp_directory (*temp_dir);
    *temp_dir = NULL;
  }
}

static void
destroy_temp_directory (TCHAR * temp_dir)
{
  RemoveDirectory (temp_dir);
  g_free (temp_dir);
}

static TCHAR *
create_temp_executable (const TCHAR * temp_dir, const TCHAR * name_prefix,
    const guint8 * data, guint size)
{
  const guint max_chars = MAX_PATH;
  TCHAR * temp_filename;
  HANDLE temp_file = INVALID_HANDLE_VALUE;
  guint offset;

  temp_filename = g_new0 (TCHAR, max_chars);
  StringCchCat (temp_filename, max_chars, temp_dir);
  StringCchCat (temp_filename, max_chars, name_prefix);
  StringCchCat (temp_filename, max_chars, _T (".exe"));

  temp_file = CreateFile (temp_filename, GENERIC_WRITE, 0, NULL, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL, NULL);
  if (temp_file == INVALID_HANDLE_VALUE)
    goto error;

  for (offset = 0; offset != zed_data_winjector_helper_32_size;)
  {
    DWORD bytes_written = 0;

    if (!WriteFile (temp_file, data + offset, size - offset, &bytes_written,
        NULL))
    {
      goto error;
    }

    offset += bytes_written;
  }

  CloseHandle (temp_file);

  return temp_filename;

error:
  if (temp_file != INVALID_HANDLE_VALUE)
    CloseHandle (temp_file);
  g_free (temp_filename);
  return NULL;
}

static void
clear_handle (HANDLE * handle)
{
  if (*handle != NULL)
  {
    CloseHandle (*handle);
    *handle = NULL;
  }
}

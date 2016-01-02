#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4028 4090 4100)
#endif
#include "pipe.c"
#ifdef _MSC_VER
# pragma warning (pop)
#endif

#include <windows.h>
#include <sddl.h>

#define PIPE_BUFSIZE (1024 * 1024)

#define CHECK_WINAPI_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_winapi_error; \
  }

typedef struct _FridaPipeBackend FridaPipeBackend;
typedef enum _FridaPipeRole FridaPipeRole;

struct _FridaPipeBackend
{
  FridaPipeRole role;
  HANDLE pipe;
  gboolean connected;
  HANDLE read_complete;
  HANDLE read_cancel;
  HANDLE write_complete;
  HANDLE write_cancel;
};

enum _FridaPipeRole
{
  FRIDA_PIPE_SERVER = 1,
  FRIDA_PIPE_CLIENT
};

static HANDLE frida_pipe_open (const gchar * name, FridaPipeRole role, GError ** error);
static gchar * frida_pipe_generate_name (void);
static WCHAR * frida_pipe_path_from_name (const gchar * name);

static gboolean frida_pipe_backend_await (FridaPipeBackend * self, HANDLE complete, HANDLE cancel, GCancellable * cancellable, GError ** error);
static void frida_pipe_backend_on_cancel (GCancellable * cancellable, gpointer user_data);

static BOOL frida_pipe_is_windows_version_or_greater (DWORD major, DWORD minor, DWORD service_pack);
static BOOL frida_pipe_is_windows_8_or_greater (void);
static BOOL frida_pipe_is_windows_vista_or_greater (void);
static LPCWSTR frida_pipe_get_sddl_string_for_os (void);

void
frida_pipe_transport_set_temp_directory (const gchar * path)
{
  (void) path;
}

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  gchar * name;

  (void) error;

  name = frida_pipe_generate_name ();

  *local_address = g_strdup_printf ("pipe:role=server,name=%s", name);
  *remote_address = g_strdup_printf ("pipe:role=client,name=%s", name);

  g_free (name);

  return NULL;
}

void
_frida_pipe_transport_destroy_backend (void * backend)
{
  (void) backend;
}

void *
_frida_pipe_create_backend (const gchar * address, GError ** error)
{
  FridaPipeBackend * backend;
  const gchar * role, * name;

  backend = g_slice_new0 (FridaPipeBackend);

  role = strstr (address, "role=") + 5;
  backend->role = role[0] == 's' ? FRIDA_PIPE_SERVER : FRIDA_PIPE_CLIENT;
  name = strstr (address, "name=") + 5;
  backend->pipe = frida_pipe_open (name, backend->role, error);
  if (backend->pipe != INVALID_HANDLE_VALUE)
  {
    backend->read_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->read_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->write_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->write_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  }
  else
  {
    _frida_pipe_destroy_backend (backend);
    backend = NULL;
  }

  return backend;
}

void
_frida_pipe_destroy_backend (void * b)
{
  FridaPipeBackend * backend = (FridaPipeBackend *) b;

  if (backend->read_complete != NULL)
    CloseHandle (backend->read_complete);
  if (backend->read_cancel != NULL)
    CloseHandle (backend->read_cancel);
  if (backend->write_complete != NULL)
    CloseHandle (backend->write_complete);
  if (backend->write_cancel != NULL)
    CloseHandle (backend->write_cancel);

  if (backend->pipe != INVALID_HANDLE_VALUE)
    CloseHandle (backend->pipe);

  g_slice_free (FridaPipeBackend, backend);
}

static gboolean
frida_pipe_backend_connect (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error)
{
  gboolean success = FALSE;
  HANDLE connect, cancel;
  OVERLAPPED overlapped = { 0, };
  BOOL ret, last_error;
  DWORD bytes_transferred;

  if (backend->connected)
  {
    return TRUE;
  }
  else if (backend->role == FRIDA_PIPE_CLIENT)
  {
    backend->connected = TRUE;
    return TRUE;
  }

  connect = CreateEvent (NULL, TRUE, FALSE, NULL);
  cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  overlapped.hEvent = connect;

  ret = ConnectNamedPipe (backend->pipe, &overlapped);
  last_error = GetLastError ();
  if (!ret && last_error != ERROR_IO_PENDING && last_error != ERROR_PIPE_CONNECTED)
    goto handle_error;

  if (last_error == ERROR_IO_PENDING)
  {
    if (!frida_pipe_backend_await (backend, connect, cancel, cancellable, error))
      goto beach;

    if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
      goto handle_error;
  }

  backend->connected = TRUE;
  success = TRUE;
  goto beach;

handle_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error opening named pipe");
    goto beach;
  }
beach:
  {
    CloseHandle (connect);
    CloseHandle (cancel);
    return success;
  }
}

static gboolean
frida_pipe_backend_await (FridaPipeBackend * self, HANDLE complete, HANDLE cancel, GCancellable * cancellable, GError ** error)
{
  gulong handler_id = 0;
  HANDLE events[2];

  if (cancellable != NULL)
  {
    handler_id = g_cancellable_connect (cancellable, G_CALLBACK (frida_pipe_backend_on_cancel), cancel, NULL);
  }

  events[0] = complete;
  events[1] = cancel;
  WaitForMultipleObjects (G_N_ELEMENTS (events), events, FALSE, INFINITE);

  if (cancellable != NULL)
  {
    g_cancellable_disconnect (cancellable, handler_id);
    if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      CancelIo (self->pipe);
      return FALSE;
    }
  }

  return TRUE;
}

static void
frida_pipe_backend_on_cancel (GCancellable * cancellable, gpointer user_data)
{
  HANDLE cancel = (HANDLE) user_data;

  (void) cancellable;

  SetEvent (cancel);
}

gboolean
_frida_pipe_close (FridaPipe * self, GError ** error)
{
  FridaPipeBackend * backend = (FridaPipeBackend *) self->_backend;

  if (!CloseHandle (backend->pipe))
    goto handle_error;
  backend->pipe = INVALID_HANDLE_VALUE;
  return TRUE;

handle_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error closing named pipe");
    return FALSE;
  }
}

static gssize
frida_pipe_input_stream_real_read (GInputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = (FridaPipeBackend *) self->_backend;
  gssize result = -1;
  OVERLAPPED overlapped = { 0, };
  BOOL ret;
  DWORD bytes_transferred;

  if (!frida_pipe_backend_connect (backend, cancellable, error))
    goto beach;

  overlapped.hEvent = backend->read_complete;
  ret = ReadFile (backend->pipe, buffer, buffer_length, NULL, &overlapped);
  if (!ret && GetLastError () != ERROR_IO_PENDING)
    goto handle_error;

  if (!frida_pipe_backend_await (backend, backend->read_complete, backend->read_cancel, cancellable, error))
    goto beach;

  if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
    goto handle_error;

  result = bytes_transferred;
  goto beach;

handle_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error reading from named pipe");
    goto beach;
  }
beach:
  {
    return result;
  }
}

static gssize
frida_pipe_output_stream_real_write (GOutputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeOutputStream * self = FRIDA_PIPE_OUTPUT_STREAM (base);
  FridaPipeBackend * backend = (FridaPipeBackend *) self->_backend;
  gssize result = -1;
  OVERLAPPED overlapped = { 0, };
  BOOL ret;
  DWORD bytes_transferred;

  if (!frida_pipe_backend_connect (backend, cancellable, error))
    goto beach;

  overlapped.hEvent = backend->write_complete;
  ret = WriteFile (backend->pipe, buffer, buffer_length, NULL, &overlapped);
  if (!ret && GetLastError () != ERROR_IO_PENDING)
    goto handle_error;

  if (!frida_pipe_backend_await (backend, backend->write_complete, backend->write_cancel, cancellable, error))
    goto beach;

  if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
    goto handle_error;

  result = bytes_transferred;
  goto beach;

handle_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error writing to named pipe");
    goto beach;
  }
beach:
  {
    return result;
  }
}

static HANDLE
frida_pipe_open (const gchar * name, FridaPipeRole role, GError ** error)
{
  HANDLE result = INVALID_HANDLE_VALUE;
  BOOL success;
  const gchar * failed_operation;
  WCHAR * path;
  LPCWSTR sddl;
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;

  path = frida_pipe_path_from_name (name);
  sddl = frida_pipe_get_sddl_string_for_os ();
  success = ConvertStringSecurityDescriptorToSecurityDescriptor (sddl, SDDL_REVISION_1, &sd, NULL);
  CHECK_WINAPI_RESULT (success, !=, FALSE, "ConvertStringSecurityDescriptorToSecurityDescriptor");

  sa.nLength = sizeof (sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;

  if (role == FRIDA_PIPE_SERVER)
  {
    result = CreateNamedPipeW (path,
        PIPE_ACCESS_DUPLEX |
        FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE |
        PIPE_READMODE_BYTE |
        PIPE_WAIT,
        1,
        PIPE_BUFSIZE,
        PIPE_BUFSIZE,
        0,
        &sa);
    CHECK_WINAPI_RESULT (result, !=, INVALID_HANDLE_VALUE, "CreateNamedPipe");
  }
  else
  {
    result = CreateFileW (path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        &sa,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);
    CHECK_WINAPI_RESULT (result, !=, INVALID_HANDLE_VALUE, "CreateFile");
  }

  goto beach;

handle_winapi_error:
  {
    DWORD last_error = GetLastError ();
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error opening named pipe (%s returned 0x%08lx)",
        failed_operation, last_error);
    goto beach;
  }

beach:
  {
    if (sd != NULL)
      LocalFree (sd);

    g_free (path);

    return result;
  }
}

static gchar *
frida_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new ("frida-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

static WCHAR *
frida_pipe_path_from_name (const gchar * name)
{
  gchar * path_utf8;
  WCHAR * path;

  path_utf8 = g_strconcat ("\\\\.\\pipe\\", name, NULL);
  path = (WCHAR *) g_utf8_to_utf16 (path_utf8, -1, NULL, NULL, NULL);
  g_free (path_utf8);

  return path;
}

static LPCWSTR
frida_pipe_get_sddl_string_for_os (void)
{
  #define DACL_START_NOINHERIT L"D:PAI"
  #define DACL_ACE_APPCONTAINER_RW L"(A;;GRGW;;;AC)"
  #define DACL_ACE_EVERYONE_RW L"(A;;GRGW;;;WD)"
  #define SACL_START L"S:"
  #define SACL_ACE_LOWINTEGRITY_NORW L"(ML;;NWNR;;;LW)"

  if (frida_pipe_is_windows_8_or_greater ())
  {
    return DACL_START_NOINHERIT DACL_ACE_APPCONTAINER_RW DACL_ACE_EVERYONE_RW SACL_START SACL_ACE_LOWINTEGRITY_NORW;
  }
  else if (frida_pipe_is_windows_vista_or_greater ())
  {
    return DACL_START_NOINHERIT DACL_ACE_EVERYONE_RW SACL_START SACL_ACE_LOWINTEGRITY_NORW;
  }
  else
  {
    return DACL_START_NOINHERIT DACL_ACE_EVERYONE_RW;
  }
}

static BOOL
frida_pipe_is_windows_vista_or_greater (void)
{
  return frida_pipe_is_windows_version_or_greater (6, 0, 0);
}

static BOOL
frida_pipe_is_windows_8_or_greater (void)
{
  return frida_pipe_is_windows_version_or_greater (6, 2, 0);
}

static BOOL
frida_pipe_is_windows_version_or_greater (DWORD major, DWORD minor, DWORD service_pack)
{
  OSVERSIONINFOEXW osvi;
  ULONGLONG condition_mask;

  ZeroMemory (&osvi, sizeof (osvi));
  osvi.dwOSVersionInfoSize = sizeof (osvi);

  condition_mask =
      VerSetConditionMask (
          VerSetConditionMask (
              VerSetConditionMask (0, VER_MAJORVERSION, VER_GREATER_EQUAL),
              VER_MINORVERSION, VER_GREATER_EQUAL),
          VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

  osvi.dwMajorVersion = major;
  osvi.dwMinorVersion = minor;
  osvi.wServicePackMajor = service_pack;

  return VerifyVersionInfoW (&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, condition_mask) != FALSE;
}
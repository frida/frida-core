typedef struct _WinIpcProxyWaitForOperationData WinIpcProxyWaitForOperationData;

static void win_ipc_proxy_wait_for_operation_co (
    WinIpcProxyWaitForOperationData * data);

#include "proxy.c"

#include "wait-handle-source.h"

#include <windows.h>

#define PIPE_BUFSIZE 4096
#define PIPE_TIMEOUT 5000

static gboolean win_ipc_proxy_wait_satisfied (gpointer data);

static void *
win_ipc_server_proxy_create_named_pipe (const char * name)
{
  HANDLE handle;
  gunichar2 * name_utf16;

  name_utf16 = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);
  handle = CreateNamedPipeW (name_utf16,
      PIPE_ACCESS_DUPLEX |
      FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE |
      PIPE_READMODE_MESSAGE |
      PIPE_WAIT,
      1,
      PIPE_BUFSIZE,
      PIPE_BUFSIZE,
      PIPE_TIMEOUT,
      NULL);
  g_free (name_utf16);

  return handle;
}

static void
win_ipc_server_proxy_destroy_named_pipe (void * pipe)
{
  DisconnectNamedPipe (pipe);

  CloseHandle (pipe);
}

static WinIpcConnectResult
win_ipc_server_proxy_connect_named_pipe (void * pipe, WinIpcPipeOperation * op)
{
  BOOL success;

  success = ConnectNamedPipe (pipe, win_ipc_pipe_operation_get_overlapped (op));
  if (!success)
  {
    switch (GetLastError ())
    {
      case ERROR_IO_PENDING:
        return WIN_IPC_CONNECT_RESULT_IO_PENDING;
      case ERROR_PIPE_CONNECTED:
        return WIN_IPC_CONNECT_RESULT_PIPE_CONNECTED;
      default:
        return WIN_IPC_CONNECT_RESULT_ERROR;
    }
  }

  return WIN_IPC_CONNECT_RESULT_PIPE_CONNECTED;
}

static void *
win_ipc_client_proxy_open_pipe (const char * name)
{
  HANDLE handle;
  gunichar2 * name_utf16;

  name_utf16 = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);

  handle = CreateFileW (name_utf16,
      GENERIC_READ | GENERIC_WRITE,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED,
      NULL);
  if (handle != INVALID_HANDLE_VALUE)
  {
    DWORD mode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    SetNamedPipeHandleState (handle, &mode, NULL, NULL);
  }
  else
  {
    handle = NULL;
  }

  g_free (name_utf16);

  return handle;
}

static void
win_ipc_client_proxy_close_pipe (void * pipe)
{
  CloseHandle (pipe);
}

static void
win_ipc_proxy_wait_for_operation_co (WinIpcProxyWaitForOperationData * data)
{
  HANDLE wait_handle;
  GSource * source;

  wait_handle = win_ipc_pipe_operation_get_wait_handle (data->op);
  source = win_ipc_wait_handle_source_new (wait_handle);
  g_source_set_callback (source,
      (GSourceFunc) win_ipc_proxy_wait_satisfied, data, NULL);
  g_source_attach (source, g_main_context_get_thread_default ());
  g_source_unref (source);
}

static gboolean
win_ipc_proxy_wait_satisfied (gpointer data)
{
  WinIpcProxyWaitForOperationData * operation_data = data;
  GSimpleAsyncResult * res;
  HANDLE pipe;
  OVERLAPPED * overlapped;
  DWORD bytes_transferred;
  BOOL success;

  res = operation_data->_async_result;

  pipe = win_ipc_pipe_operation_get_pipe_handle (operation_data->op);
  overlapped = win_ipc_pipe_operation_get_overlapped (operation_data->op);

  success = GetOverlappedResult (pipe, overlapped, &bytes_transferred, FALSE);
  g_assert (success); /* FIXME */

  g_simple_async_result_complete (res);
  g_object_unref (res);

  return FALSE;
}

static void
win_ipc_pipe_operation_create_resources (WinIpcPipeOperation * self)
{
  HANDLE wait_handle;
  OVERLAPPED * overlapped;

  wait_handle = CreateEvent (NULL, TRUE, FALSE, NULL);

  overlapped = g_new0 (OVERLAPPED, 1);
  overlapped->hEvent = wait_handle;

  win_ipc_pipe_operation_set_wait_handle (self, wait_handle);
  win_ipc_pipe_operation_set_overlapped (self, overlapped);
}

static void
win_ipc_pipe_operation_destroy_resources (WinIpcPipeOperation * self)
{
  HANDLE wait_handle;
  OVERLAPPED * overlapped;

  wait_handle = win_ipc_pipe_operation_get_wait_handle (self);
  win_ipc_pipe_operation_set_wait_handle (self, NULL);
  CloseHandle (wait_handle);

  overlapped = win_ipc_pipe_operation_get_overlapped (self);
  win_ipc_pipe_operation_set_overlapped (self, NULL);
  g_free (overlapped);
}

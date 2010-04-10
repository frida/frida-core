typedef struct _WinIpcProxyPopMessageData WinIpcProxyPopMessageData;
typedef struct _WinIpcProxyReadMessageData WinIpcProxyReadMessageData;
typedef struct _WinIpcProxyWriteMessageData WinIpcProxyWriteMessageData;
typedef struct _WinIpcProxyWaitForOperationData WinIpcProxyWaitForOperationData;

static void win_ipc_proxy_pop_message_co (WinIpcProxyPopMessageData * data);
static void win_ipc_proxy_read_message_co (WinIpcProxyReadMessageData * data);
static void win_ipc_proxy_write_message_co (WinIpcProxyWriteMessageData * data);
static void win_ipc_proxy_wait_for_operation_co (
    WinIpcProxyWaitForOperationData * data);

#include "proxy.c"

#include "wait-handle-source.h"

#include <windows.h>

#define PIPE_BUFSIZE 4096
#define PIPE_TIMEOUT 5000

static gboolean win_ipc_proxy_handle_message (const char * message,
    void * user_data);

static void CALLBACK win_ipc_proxy_read_completed (DWORD os_error,
    DWORD bytes_transferred, OVERLAPPED * overlapped);
static void CALLBACK win_ipc_proxy_write_completed (DWORD os_error,
    DWORD bytes_transferred, OVERLAPPED * overlapped);
static gboolean win_ipc_proxy_wait_satisfied (gpointer data);

static void complete_async_result_from_os_error (GSimpleAsyncResult * res,
    DWORD os_error, WinIpcPipeOperation * op);
static GIOErrorEnum io_error_from_os_error (DWORD os_error);

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

static WinIpcIOResult
win_ipc_server_proxy_connect_named_pipe (void * pipe, WinIpcPipeOperation * op,
    GError ** error)
{
  BOOL success;

  win_ipc_pipe_operation_set_function_name (op, "ConnectNamedPipe");

  success = ConnectNamedPipe (pipe, win_ipc_pipe_operation_get_overlapped (op));
  if (!success)
  {
    DWORD os_error;

    os_error = GetLastError ();

    switch (os_error)
    {
      case ERROR_IO_PENDING:
        return WIN_IPC_IO_RESULT_PENDING;
      case ERROR_PIPE_CONNECTED:
        return WIN_IPC_IO_RESULT_SUCCESS;
      default:
        g_set_error (error, G_IO_ERROR, io_error_from_os_error (os_error),
            "ConnectNamedPipe failed: %d", os_error);
        return WIN_IPC_IO_RESULT_INVALID;
    }
  }

  return WIN_IPC_IO_RESULT_SUCCESS;
}

static void *
win_ipc_client_proxy_open_pipe (const char * name, GError ** error)
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
    DWORD os_error;

    handle = NULL;

    os_error = GetLastError ();
    g_set_error (error, G_IO_ERROR, io_error_from_os_error (os_error),
        "CreateFile failed: %d", os_error);
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
win_ipc_proxy_pop_message_co (WinIpcProxyPopMessageData * data)
{
  WinIpcProxyMessageHandler * handler;

  handler =
      win_ipc_proxy_message_handler_new (win_ipc_proxy_handle_message, data);
  gee_abstract_list_insert (
      GEE_ABSTRACT_LIST (data->self->priv->message_handlers), 0, handler);
}

static gboolean
win_ipc_proxy_handle_message (const char * message, void * user_data)
{
  WinIpcProxyPopMessageData * data = user_data;
  GSimpleAsyncResult * res = data->_async_result;

  data->result = g_strdup (message);
  g_simple_async_result_complete (res);
  g_object_unref (res);

  return TRUE;
}

static void
win_ipc_proxy_read_message_co (WinIpcProxyReadMessageData * data)
{
  WinIpcPipeOperation * op;
  guint8 * buf;
  BOOL success;

  buf = g_malloc (PIPE_BUFSIZE);

  op = win_ipc_pipe_operation_new (data->self->pipe);
  win_ipc_pipe_operation_set_function_name (op, "ReadFileEx");
  win_ipc_pipe_operation_set_buffer (op, buf);
  win_ipc_pipe_operation_set_user_data (op, data);

  success = ReadFileEx (win_ipc_pipe_operation_get_pipe_handle (op),
      buf, PIPE_BUFSIZE,
      win_ipc_pipe_operation_get_overlapped (op),
      win_ipc_proxy_read_completed);
  if (!success)
  {
    complete_async_result_from_os_error (data->_async_result, GetLastError (),
        op);

    win_ipc_pipe_operation_unref (op);
    return;
  }
}

static void
win_ipc_proxy_write_message_co (WinIpcProxyWriteMessageData * data)
{
  WinIpcPipeOperation * op;
  BOOL success;

  op = win_ipc_pipe_operation_new (data->self->pipe);
  win_ipc_pipe_operation_set_function_name (op, "WriteFileEx");
  win_ipc_pipe_operation_set_user_data (op, data);

  success = WriteFileEx (win_ipc_pipe_operation_get_pipe_handle (op),
      data->message, strlen (data->message) + 1,
      win_ipc_pipe_operation_get_overlapped (op),
      win_ipc_proxy_write_completed);
  if (!success)
  {
    complete_async_result_from_os_error (data->_async_result, GetLastError (),
        op);

    win_ipc_pipe_operation_unref (op);
    return;
  }
}

static void CALLBACK
win_ipc_proxy_read_completed (DWORD os_error, DWORD bytes_transferred,
    OVERLAPPED * overlapped)
{
  WinIpcPipeOperation * op;
  WinIpcProxyReadMessageData * data;
  GSimpleAsyncResult * res;
  GError * err = NULL;
  guint length;

  op = win_ipc_pipe_operation_from_overlapped (overlapped);
  data = win_ipc_pipe_operation_get_user_data (op);

  res = data->_async_result;

  length = win_ipc_pipe_operation_consume_result (op, &err);

  if (err == NULL)
  {
    data->result = win_ipc_pipe_operation_steal_buffer (op);
  }
  else
  {
    g_simple_async_result_set_from_error (res, err);
    g_clear_error (&err);
  }

  g_simple_async_result_complete (res);
  g_object_unref (res);

  win_ipc_pipe_operation_unref (op);
}

static void CALLBACK
win_ipc_proxy_write_completed (DWORD os_error, DWORD bytes_transferred,
    OVERLAPPED * overlapped)
{
  WinIpcPipeOperation * op;
  WinIpcProxyWriteMessageData * data;
  GSimpleAsyncResult * res;
  GError * err = NULL;

  op = win_ipc_pipe_operation_from_overlapped (overlapped);
  data = win_ipc_pipe_operation_get_user_data (op);

  res = data->_async_result;

  win_ipc_pipe_operation_consume_result (op, &err);

  if (err != NULL)
  {
    g_simple_async_result_set_from_error (res, err);
    g_clear_error (&err);
  }

  g_simple_async_result_complete (res);
  g_object_unref (res);

  win_ipc_pipe_operation_unref (op);
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

  res = operation_data->_async_result;
  g_simple_async_result_complete (res);
  g_object_unref (res);

  return FALSE;
}

typedef struct _WinIpcPipeOverlapped WinIpcPipeOverlapped;

struct _WinIpcPipeOverlapped
{
  OVERLAPPED parent;

  WinIpcPipeOperation * operation;
};

WinIpcPipeOperation *
win_ipc_pipe_operation_from_overlapped (void * overlapped)
{
  return ((WinIpcPipeOverlapped *) overlapped)->operation;
}

guint
win_ipc_pipe_operation_consume_result (WinIpcPipeOperation * self,
    GError ** error)
{
  HANDLE pipe;
  OVERLAPPED * overlapped;
  DWORD bytes_transferred;
  BOOL success;

  pipe = win_ipc_pipe_operation_get_pipe_handle (self);
  overlapped = win_ipc_pipe_operation_get_overlapped (self);

  success = GetOverlappedResult (pipe, overlapped, &bytes_transferred, FALSE);
  if (!success)
  {
    DWORD os_error;

    os_error = GetLastError ();
    g_set_error (error, G_IO_ERROR, io_error_from_os_error (os_error),
        "%s failed: %d",
        win_ipc_pipe_operation_get_function_name (self), os_error);

    return 0;
  }

  return bytes_transferred;
}

static void
win_ipc_pipe_operation_create_resources (WinIpcPipeOperation * self)
{
  HANDLE wait_handle;
  WinIpcPipeOverlapped * overlapped;

  wait_handle = CreateEvent (NULL, TRUE, FALSE, NULL);

  overlapped = g_new0 (WinIpcPipeOverlapped, 1);
  overlapped->parent.hEvent = wait_handle;
  overlapped->operation = self;

  win_ipc_pipe_operation_set_wait_handle (self, wait_handle);
  win_ipc_pipe_operation_set_overlapped (self, overlapped);
}

static void
win_ipc_pipe_operation_destroy_resources (WinIpcPipeOperation * self)
{
  g_free (win_ipc_pipe_operation_get_buffer (self));
  win_ipc_pipe_operation_set_buffer (self, NULL);

  CloseHandle (win_ipc_pipe_operation_get_wait_handle (self));
  win_ipc_pipe_operation_set_wait_handle (self, NULL);

  g_free (win_ipc_pipe_operation_get_overlapped (self));
  win_ipc_pipe_operation_set_overlapped (self, NULL);
}

static void
complete_async_result_from_os_error (GSimpleAsyncResult * res, DWORD os_error,
    WinIpcPipeOperation * op)
{
  g_simple_async_result_set_error (res,
      G_IO_ERROR, io_error_from_os_error (os_error),
      "%s failed: %d", win_ipc_pipe_operation_get_function_name (op), os_error);
  g_simple_async_result_complete (res);
  g_object_unref (res);

  win_ipc_pipe_operation_unref (op);
}

static GIOErrorEnum
io_error_from_os_error (DWORD os_error)
{
  switch (os_error)
  {
    case ERROR_FILE_NOT_FOUND:
      return G_IO_ERROR_NOT_FOUND;
    case ERROR_ACCESS_DENIED:
      return G_IO_ERROR_PERMISSION_DENIED;
    default:
      return G_IO_ERROR_FAILED;
  }
}

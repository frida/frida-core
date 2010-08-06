#include "proxy.c"

#include "wait-handle-source.h"

#include <windows.h>

#define PIPE_BUFSIZE (1024 * 1024)
#define PIPE_TIMEOUT 5000

typedef struct _WinIpcPipeOverlapped WinIpcPipeOverlapped;

struct _WinIpcPipeOverlapped
{
  OVERLAPPED parent;

  WinIpcPipeOperation * operation;
};

typedef struct _WinIpcProxyWaitContext WinIpcProxyWaitContext;

struct _WinIpcProxyWaitContext
{
  GSource * wait_source;
  GSource * timeout_source;
  gboolean timed_out;
};

static gboolean win_ipc_proxy_handle_message (const char * message,
    void * user_data);

static void CALLBACK win_ipc_proxy_read_or_write_completed (DWORD os_error,
    DWORD bytes_transferred, OVERLAPPED * overlapped);
static void win_ipc_proxy_wait_context_free (WinIpcProxyWaitContext * ctx);
static gboolean win_ipc_proxy_wait_satisfied (gpointer data);
static gboolean win_ipc_proxy_wait_timed_out (gpointer data);

static WCHAR * pipe_path_from_name (const gchar * name);
static void complete_async_result_from_os_error (GSimpleAsyncResult * res,
    DWORD os_error);
static GIOErrorEnum io_error_from_os_error (DWORD os_error);

void *
win_ipc_server_proxy_create_named_pipe (const char * name)
{
  HANDLE handle;
  WCHAR * path;

  path = pipe_path_from_name (name);

  handle = CreateNamedPipeW (path,
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

  g_free (path);

  return handle;
}

void
win_ipc_server_proxy_destroy_named_pipe (void * pipe)
{
  DisconnectNamedPipe (pipe);

  CloseHandle (pipe);
}

WinIpcIOResult
win_ipc_server_proxy_connect_named_pipe (void * pipe, WinIpcPipeOperation * op,
    GError ** error)
{
  BOOL success;

  win_ipc_pipe_operation_set_function_name (op, "ConnectNamedPipe");

  success = ConnectNamedPipe (pipe, (LPOVERLAPPED)
      win_ipc_pipe_operation_get_overlapped (op));
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

void *
win_ipc_client_proxy_open_pipe (const char * name, GError ** error)
{
  HANDLE handle;
  WCHAR * path;

  path = pipe_path_from_name (name);

  handle = CreateFileW (path,
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

  g_free (path);

  return handle;
}

void
win_ipc_client_proxy_close_pipe (void * pipe)
{
  CloseHandle (pipe);
}

static void
win_ipc_proxy_read_blob (WinIpcProxy * self, GAsyncReadyCallback _callback_,
    gpointer _user_data_)
{
  guint8 * buf;
  WinIpcPipeOperation * op;
  GSimpleAsyncResult * res;
  BOOL success;

  buf = (guint8 *) g_malloc (PIPE_BUFSIZE);

  op = win_ipc_pipe_operation_new (self->pipe);
  win_ipc_pipe_operation_set_function_name (op, "ReadFileEx");
  win_ipc_pipe_operation_set_buffer (op, buf);

  res = g_simple_async_result_new (G_OBJECT (self), _callback_, _user_data_,
      win_ipc_proxy_read_blob);
  win_ipc_pipe_operation_set_user_data (op, res);
  g_simple_async_result_set_op_res_gpointer (res, op,
      win_ipc_pipe_operation_unref);

  success = ReadFileEx (win_ipc_pipe_operation_get_pipe_handle (op),
      buf, PIPE_BUFSIZE,
      (LPOVERLAPPED) win_ipc_pipe_operation_get_overlapped (op),
      win_ipc_proxy_read_or_write_completed);
  if (!success)
    complete_async_result_from_os_error (res, GetLastError ());
}

static guint8 *
win_ipc_proxy_read_blob_finish (WinIpcProxy * self, GAsyncResult * _res_,
    int * result_length1, GError ** error)
{
  guint8 * buffer;
  GSimpleAsyncResult * res;
  WinIpcPipeOperation * op;
  GError * err;
  guint length;

  res = G_SIMPLE_ASYNC_RESULT (_res_);
  op = WIN_IPC_PIPE_OPERATION (g_simple_async_result_get_op_res_gpointer (
      res));

  length = win_ipc_pipe_operation_consume_result (op, &err);
  if (err == NULL)
  {
    buffer = (guint8 *) win_ipc_pipe_operation_steal_buffer (op);
    *result_length1 = length;
  }
  else
  {
    buffer = NULL;
    *result_length1 = -1;

    g_simple_async_result_set_from_error (res, err);
    g_simple_async_result_propagate_error (res, error);
    g_clear_error (&err);
  }

  return buffer;
}

static void
win_ipc_proxy_write_blob (WinIpcProxy * self, guint8 * blob, int blob_length1,
    GAsyncReadyCallback _callback_, gpointer _user_data_)
{
  WinIpcPipeOperation * op;
  GSimpleAsyncResult * res;
  BOOL success;

  op = win_ipc_pipe_operation_new (self->pipe);
  win_ipc_pipe_operation_set_function_name (op, "WriteFileEx");

  res = g_simple_async_result_new (G_OBJECT (self), _callback_, _user_data_,
      win_ipc_proxy_write_blob);
  win_ipc_pipe_operation_set_user_data (op, res);
  g_simple_async_result_set_op_res_gpointer (res, op,
      win_ipc_pipe_operation_unref);

  success = WriteFileEx (win_ipc_pipe_operation_get_pipe_handle (op),
      blob, blob_length1,
      (LPOVERLAPPED) win_ipc_pipe_operation_get_overlapped (op),
      win_ipc_proxy_read_or_write_completed);
  if (!success)
    complete_async_result_from_os_error (res, GetLastError ());
}

static void
win_ipc_proxy_write_blob_finish (WinIpcProxy * self, GAsyncResult * _res_,
    GError ** error)
{
  GSimpleAsyncResult * res;
  WinIpcPipeOperation * op;
  GError * err;
  guint length;

  res = G_SIMPLE_ASYNC_RESULT (_res_);
  op = WIN_IPC_PIPE_OPERATION (g_simple_async_result_get_op_res_gpointer (
      res));

  win_ipc_pipe_operation_consume_result (op, &err);
  if (err != NULL)
  {
    g_simple_async_result_set_from_error (res, err);
    g_simple_async_result_propagate_error (res, error);
    g_clear_error (&err);
  }
}

static void CALLBACK
win_ipc_proxy_read_or_write_completed (DWORD os_error, DWORD bytes_transferred,
    OVERLAPPED * overlapped)
{
  WinIpcPipeOperation * op;
  GSimpleAsyncResult * res;

  op = win_ipc_pipe_operation_from_overlapped (overlapped);
  res = G_SIMPLE_ASYNC_RESULT (win_ipc_pipe_operation_get_user_data (op));
  g_simple_async_result_complete (res);
  g_object_unref (res);
}

static void
win_ipc_proxy_wait_for_operation (WinIpcProxy * self, WinIpcPipeOperation * op,
    guint timeout_msec, GAsyncReadyCallback _callback_, gpointer _user_data_)
{
  GSimpleAsyncResult * res;
  WinIpcProxyWaitContext * ctx;
  HANDLE wait_handle;

  res = g_simple_async_result_new (G_OBJECT (self), _callback_, _user_data_,
      win_ipc_proxy_wait_for_operation);

  ctx = g_new0 (WinIpcProxyWaitContext, 1);
  g_simple_async_result_set_op_res_gpointer (res, ctx,
      (GDestroyNotify) win_ipc_proxy_wait_context_free);

  wait_handle = win_ipc_pipe_operation_get_wait_handle (op);
  ctx->wait_source = win_ipc_wait_handle_source_new (wait_handle);
  g_source_set_callback (ctx->wait_source, win_ipc_proxy_wait_satisfied,
      res, NULL);
  g_source_attach (ctx->wait_source, g_main_context_get_thread_default ());

  if (timeout_msec != 0)
  {
    ctx->timeout_source = g_timeout_source_new (timeout_msec);
    g_source_set_callback (ctx->timeout_source, win_ipc_proxy_wait_timed_out,
        res, NULL);
    g_source_attach (ctx->timeout_source,
        g_main_context_get_thread_default ());
  }
}

static void
win_ipc_proxy_wait_for_operation_finish (WinIpcProxy * self,
    GAsyncResult * _res_, GError ** error)
{
  GSimpleAsyncResult * res;
  WinIpcProxyWaitContext * ctx;

  res = G_SIMPLE_ASYNC_RESULT (_res_);
  ctx = (WinIpcProxyWaitContext *)
      g_simple_async_result_get_op_res_gpointer (res);

  if (ctx->timed_out)
  {
    g_simple_async_result_set_error (res, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
        "Operation timed out");
    g_simple_async_result_propagate_error (res, error);
  }
}

static void
win_ipc_proxy_wait_context_free (WinIpcProxyWaitContext * ctx)
{
  g_source_unref (ctx->wait_source);
  if (ctx->timeout_source != NULL)
    g_source_unref (ctx->timeout_source);
  g_free (ctx);
}

static gboolean
win_ipc_proxy_wait_satisfied (gpointer data)
{
  GSimpleAsyncResult * res;
  WinIpcProxyWaitContext * ctx;

  res = G_SIMPLE_ASYNC_RESULT (data);
  ctx = (WinIpcProxyWaitContext *)
      g_simple_async_result_get_op_res_gpointer (res);

  ctx->timed_out = FALSE;

  if (ctx->timeout_source != NULL)
    g_source_destroy (ctx->timeout_source);

  g_simple_async_result_complete (res);
  g_object_unref (res);

  return FALSE;
}

static gboolean
win_ipc_proxy_wait_timed_out (gpointer data)
{
  GSimpleAsyncResult * res;
  WinIpcProxyWaitContext * ctx;

  res = G_SIMPLE_ASYNC_RESULT (data);
  ctx = (WinIpcProxyWaitContext *)
      g_simple_async_result_get_op_res_gpointer (res);

  ctx->timed_out = TRUE;

  g_source_destroy (ctx->wait_source);

  g_simple_async_result_complete (res);
  g_object_unref (res);

  return FALSE;
}

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
  overlapped = (OVERLAPPED *) win_ipc_pipe_operation_get_overlapped (self);

  if (error != NULL)
    *error = NULL;

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

void
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

void
win_ipc_pipe_operation_destroy_resources (WinIpcPipeOperation * self)
{
  g_free (win_ipc_pipe_operation_get_buffer (self));
  win_ipc_pipe_operation_set_buffer (self, NULL);

  CloseHandle (win_ipc_pipe_operation_get_wait_handle (self));
  win_ipc_pipe_operation_set_wait_handle (self, NULL);

  g_free (win_ipc_pipe_operation_get_overlapped (self));
  win_ipc_pipe_operation_set_overlapped (self, NULL);
}

static WCHAR *
pipe_path_from_name (const gchar * name)
{
  gchar * path_utf8;
  WCHAR * path;

  path_utf8 = g_strconcat ("\\\\.\\pipe\\", name, NULL);
  path = (WCHAR *) g_utf8_to_utf16 (path_utf8, -1, NULL, NULL, NULL);
  g_free (path_utf8);

  return path;
}

static void
complete_async_result_from_os_error (GSimpleAsyncResult * res, DWORD os_error)
{
  WinIpcPipeOperation * op;

  op = (WinIpcPipeOperation *) g_simple_async_result_get_op_res_gpointer (res);
  g_simple_async_result_set_error (res,
      G_IO_ERROR, io_error_from_os_error (os_error),
      "%s failed: %d",
      win_ipc_pipe_operation_get_function_name (op),
      os_error);
  g_simple_async_result_complete (res);
  g_object_unref (res);
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

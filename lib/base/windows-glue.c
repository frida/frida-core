#include "frida-base.h"

#include <windows.h>

#define FRIDA_TYPE_WINDOWS_HANDLE_STREAM (frida_windows_handle_stream_get_type ())
#define FRIDA_TYPE_WINDOWS_HANDLE_INPUT_STREAM (frida_windows_handle_input_stream_get_type ())
#define FRIDA_TYPE_WINDOWS_HANDLE_OUTPUT_STREAM (frida_windows_handle_output_stream_get_type ())

#define FRIDA_WINDOWS_HANDLE_STREAM(o) ((FridaWindowsHandleStream *) (o))
#define FRIDA_WINDOWS_HANDLE_INPUT_STREAM(o) ((FridaWindowsHandleInputStream *) (o))
#define FRIDA_WINDOWS_HANDLE_OUTPUT_STREAM(o) ((FridaWindowsHandleOutputStream *) (o))

typedef struct _FridaWindowsHandleStream FridaWindowsHandleStream;
typedef struct _FridaWindowsHandleStreamClass FridaWindowsHandleStreamClass;
typedef struct _FridaWindowsHandleInputStream FridaWindowsHandleInputStream;
typedef struct _FridaWindowsHandleInputStreamClass FridaWindowsHandleInputStreamClass;
typedef struct _FridaWindowsHandleOutputStream FridaWindowsHandleOutputStream;
typedef struct _FridaWindowsHandleOutputStreamClass FridaWindowsHandleOutputStreamClass;

struct _FridaWindowsHandleStream
{
  GIOStream parent;

  HANDLE handle;
  HANDLE read_complete;
  HANDLE read_cancel;
  HANDLE write_complete;
  HANDLE write_cancel;

  GInputStream * input;
  GOutputStream * output;
};

struct _FridaWindowsHandleStreamClass
{
  GIOStreamClass parent_class;
};

struct _FridaWindowsHandleInputStream
{
  GInputStream parent;

  FridaWindowsHandleStream * stream;
};

struct _FridaWindowsHandleInputStreamClass
{
  GInputStreamClass parent_class;
};

struct _FridaWindowsHandleOutputStream
{
  GOutputStream parent;

  FridaWindowsHandleStream * stream;
};

struct _FridaWindowsHandleOutputStreamClass
{
  GOutputStreamClass parent_class;
};

static GIOStream * frida_windows_handle_stream_new (HANDLE handle);

static void frida_windows_handle_stream_finalize (GObject * object);
static GInputStream * frida_windows_handle_stream_get_input_stream (GIOStream * stream);
static GOutputStream * frida_windows_handle_stream_get_output_stream (GIOStream * stream);
static gboolean frida_windows_handle_stream_close_fn (GIOStream * stream, GCancellable * cancellable, GError ** error);

static gssize frida_windows_handle_input_stream_read (GInputStream * base, void * buffer, gsize count,
    GCancellable * cancellable, GError ** error);
static gboolean frida_windows_handle_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error);

static gssize frida_windows_handle_output_stream_write (GOutputStream * base, const void * buffer, gsize count,
    GCancellable * cancellable, GError ** error);
static gboolean frida_windows_handle_output_stream_close (GOutputStream * base, GCancellable * cancellable,
    GError ** error);

static gboolean frida_windows_handle_stream_await (FridaWindowsHandleStream * self, HANDLE complete, HANDLE cancel,
    GCancellable * cancellable, GError ** error);
static void frida_windows_handle_stream_on_cancel (GCancellable * cancellable, gpointer user_data);

G_DEFINE_TYPE (FridaWindowsHandleStream, frida_windows_handle_stream, G_TYPE_IO_STREAM)
G_DEFINE_TYPE (FridaWindowsHandleInputStream, frida_windows_handle_input_stream, G_TYPE_INPUT_STREAM)
G_DEFINE_TYPE (FridaWindowsHandleOutputStream, frida_windows_handle_output_stream, G_TYPE_OUTPUT_STREAM)

GIOStream *
frida_windows_named_pipe_open_client (const gchar * path, GError ** error)
{
  HANDLE handle;
  WCHAR * path_utf16;
  DWORD last_error;

  path_utf16 = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (path_utf16 == NULL)
    goto invalid_path;

  handle = CreateFileW (path_utf16,
      GENERIC_READ | GENERIC_WRITE,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED,
      NULL);
  last_error = GetLastError ();
  g_free (path_utf16);

  if (handle == INVALID_HANDLE_VALUE)
    goto cannot_open;

  return frida_windows_handle_stream_new (handle);

invalid_path:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid pipe path");
    return NULL;
  }
cannot_open:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Unable to open %s (CreateFile returned 0x%08lx)",
        path, last_error);
    return NULL;
  }
}

static GIOStream *
frida_windows_handle_stream_new (HANDLE handle)
{
  FridaWindowsHandleStream * stream;
  FridaWindowsHandleInputStream * input;
  FridaWindowsHandleOutputStream * output;

  stream = g_object_new (FRIDA_TYPE_WINDOWS_HANDLE_STREAM, NULL);
  stream->handle = handle;
  stream->read_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
  stream->read_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  stream->write_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
  stream->write_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);

  input = g_object_new (FRIDA_TYPE_WINDOWS_HANDLE_INPUT_STREAM, NULL);
  input->stream = stream;
  stream->input = G_INPUT_STREAM (input);

  output = g_object_new (FRIDA_TYPE_WINDOWS_HANDLE_OUTPUT_STREAM, NULL);
  output->stream = stream;
  stream->output = G_OUTPUT_STREAM (output);

  return G_IO_STREAM (stream);
}

static void
frida_windows_handle_stream_class_init (FridaWindowsHandleStreamClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GIOStreamClass * stream_class = G_IO_STREAM_CLASS (klass);

  object_class->finalize = frida_windows_handle_stream_finalize;

  stream_class->get_input_stream = frida_windows_handle_stream_get_input_stream;
  stream_class->get_output_stream = frida_windows_handle_stream_get_output_stream;
  stream_class->close_fn = frida_windows_handle_stream_close_fn;
}

static void
frida_windows_handle_stream_init (FridaWindowsHandleStream * self)
{
  self->handle = INVALID_HANDLE_VALUE;
}

static void
frida_windows_handle_stream_finalize (GObject * object)
{
  FridaWindowsHandleStream * self = FRIDA_WINDOWS_HANDLE_STREAM (object);

  g_clear_object (&self->input);
  g_clear_object (&self->output);

  CloseHandle (self->read_complete);
  CloseHandle (self->read_cancel);
  CloseHandle (self->write_complete);
  CloseHandle (self->write_cancel);

  if (self->handle != INVALID_HANDLE_VALUE)
    CloseHandle (self->handle);

  G_OBJECT_CLASS (frida_windows_handle_stream_parent_class)->finalize (object);
}

static GInputStream *
frida_windows_handle_stream_get_input_stream (GIOStream * stream)
{
  return FRIDA_WINDOWS_HANDLE_STREAM (stream)->input;
}

static GOutputStream *
frida_windows_handle_stream_get_output_stream (GIOStream * stream)
{
  return FRIDA_WINDOWS_HANDLE_STREAM (stream)->output;
}

static gboolean
frida_windows_handle_stream_close_fn (GIOStream * stream, GCancellable * cancellable, GError ** error)
{
  FridaWindowsHandleStream * self = FRIDA_WINDOWS_HANDLE_STREAM (stream);

  SetEvent (self->read_cancel);
  SetEvent (self->write_cancel);

  if (self->handle != INVALID_HANDLE_VALUE)
  {
    CancelIo (self->handle);
    CloseHandle (self->handle);
    self->handle = INVALID_HANDLE_VALUE;
  }

  return TRUE;
}

static void
frida_windows_handle_input_stream_class_init (FridaWindowsHandleInputStreamClass * klass)
{
  GInputStreamClass * stream_class = G_INPUT_STREAM_CLASS (klass);

  stream_class->read_fn = frida_windows_handle_input_stream_read;
  stream_class->close_fn = frida_windows_handle_input_stream_close;
}

static void
frida_windows_handle_input_stream_init (FridaWindowsHandleInputStream * self)
{
}

static gssize
frida_windows_handle_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable,
    GError ** error)
{
  FridaWindowsHandleStream * stream = FRIDA_WINDOWS_HANDLE_INPUT_STREAM (base)->stream;
  OVERLAPPED overlapped = { 0, };
  DWORD bytes_transferred, last_error;

  if (stream->handle == INVALID_HANDLE_VALUE)
    return 0;

  overlapped.hEvent = stream->read_complete;
  if (!ReadFile (stream->handle, buffer, count, NULL, &overlapped) && GetLastError () != ERROR_IO_PENDING)
    goto failure;

  if (!frida_windows_handle_stream_await (stream, stream->read_complete, stream->read_cancel, cancellable, error))
    return -1;

  if (!GetOverlappedResult (stream->handle, &overlapped, &bytes_transferred, FALSE))
    goto failure;

  return bytes_transferred;

failure:
  {
    last_error = GetLastError ();
    if (last_error == ERROR_BROKEN_PIPE || last_error == ERROR_PIPE_NOT_CONNECTED)
      return 0;
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error reading from pipe");
    return -1;
  }
}

static gboolean
frida_windows_handle_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static void
frida_windows_handle_output_stream_class_init (FridaWindowsHandleOutputStreamClass * klass)
{
  GOutputStreamClass * stream_class = G_OUTPUT_STREAM_CLASS (klass);

  stream_class->write_fn = frida_windows_handle_output_stream_write;
  stream_class->close_fn = frida_windows_handle_output_stream_close;
}

static void
frida_windows_handle_output_stream_init (FridaWindowsHandleOutputStream * self)
{
}

static gssize
frida_windows_handle_output_stream_write (GOutputStream * base, const void * buffer, gsize count,
    GCancellable * cancellable, GError ** error)
{
  FridaWindowsHandleStream * stream = FRIDA_WINDOWS_HANDLE_OUTPUT_STREAM (base)->stream;
  OVERLAPPED overlapped = { 0, };
  DWORD bytes_transferred, last_error;

  if (stream->handle == INVALID_HANDLE_VALUE)
    goto closed;

  overlapped.hEvent = stream->write_complete;
  if (!WriteFile (stream->handle, buffer, count, NULL, &overlapped) && GetLastError () != ERROR_IO_PENDING)
    goto failure;

  if (!frida_windows_handle_stream_await (stream, stream->write_complete, stream->write_cancel, cancellable, error))
    return -1;

  if (!GetOverlappedResult (stream->handle, &overlapped, &bytes_transferred, FALSE))
    goto failure;

  return bytes_transferred;

closed:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED, "Pipe is closed");
    return -1;
  }
failure:
  {
    last_error = GetLastError ();
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error writing to pipe");
    return -1;
  }
}

static gboolean
frida_windows_handle_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static gboolean
frida_windows_handle_stream_await (FridaWindowsHandleStream * self, HANDLE complete, HANDLE cancel,
    GCancellable * cancellable, GError ** error)
{
  gulong handler_id = 0;
  HANDLE events[2];

  if (cancellable != NULL)
    handler_id = g_cancellable_connect (cancellable, G_CALLBACK (frida_windows_handle_stream_on_cancel), cancel, NULL);

  events[0] = complete;
  events[1] = cancel;
  WaitForMultipleObjects (G_N_ELEMENTS (events), events, FALSE, INFINITE);

  if (cancellable != NULL)
  {
    g_cancellable_disconnect (cancellable, handler_id);
    if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      CancelIo (self->handle);
      return FALSE;
    }
  }

  if (WaitForSingleObject (cancel, 0) == WAIT_OBJECT_0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_CLOSED, "Pipe is closed");
    return FALSE;
  }

  return TRUE;
}

static void
frida_windows_handle_stream_on_cancel (GCancellable * cancellable, gpointer user_data)
{
  HANDLE cancel = (HANDLE) user_data;

  SetEvent (cancel);
}

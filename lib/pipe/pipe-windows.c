#include "zed-pipe.h"

#include <windows.h>

#define PIPE_BUFSIZE (1024 * 1024)

typedef struct _ZedPipeTransportBackend ZedPipeTransportBackend;
typedef struct _ZedPipeBackend ZedPipeBackend;

struct _ZedPipeTransportBackend
{
  HANDLE pipe;
};

struct _ZedPipeBackend
{
  gboolean placeholder;
};

static gchar * zed_pipe_generate_name (void);
static WCHAR * zed_pipe_path_from_name (const gchar * name);

void
_zed_pipe_transport_create_backend (ZedPipeTransport * self, gulong pid, GError ** error)
{
  ZedPipeTransportBackend * backend;
  gchar * name;
  WCHAR * path;

  (void) pid;

  backend = g_slice_new0 (ZedPipeTransportBackend);
  self->_backend = backend;

  name = zed_pipe_generate_name ();
  path = zed_pipe_path_from_name (name);

  backend->pipe = CreateNamedPipeW (path,
      PIPE_ACCESS_DUPLEX |
      FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE |
      PIPE_READMODE_BYTE |
      PIPE_WAIT,
      1,
      PIPE_BUFSIZE,
      PIPE_BUFSIZE,
      0,
      NULL);
  if (backend->pipe == INVALID_HANDLE_VALUE)
    goto handle_create_error;

  self->local_address = g_strdup_printf ("pipe:role=server,name=%s", name);
  self->remote_address = g_strdup_printf ("pipe:role=client,name=%s", name);

  goto beach;

handle_create_error:
  {
    _zed_pipe_transport_destroy_backend (self);
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "CreateNamedPipe failed: 0x%08x", GetLastError ());
    goto beach;
  }

beach:
  {
    g_free (path);
    g_free (name);
    return;
  }
}

void
_zed_pipe_transport_destroy_backend (ZedPipeTransport * self)
{
  ZedPipeTransportBackend * backend = (ZedPipeTransportBackend *) self->_backend;

  if (backend->pipe != INVALID_HANDLE_VALUE)
    CloseHandle (backend->pipe);

  g_slice_free (ZedPipeTransportBackend, backend);
}

void
_zed_pipe_create_backend (ZedPipe * self)
{
  ZedPipeBackend * backend;

  backend = g_slice_new (ZedPipeBackend);

  self->_backend = backend;
}

void
_zed_pipe_destroy_backend (ZedPipe * self)
{
  ZedPipeBackend * backend = (ZedPipeBackend *) self->_backend;

  g_slice_free (ZedPipeBackend, backend);
}

gboolean
_zed_pipe_close (ZedPipe * self, GError ** error)
{
  ZedPipeBackend * backend = (ZedPipeBackend *) self->_backend;

  return TRUE;
}

gssize
_zed_pipe_input_stream_read (ZedPipeInputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not yet implemented");
  return 0;
}

gssize
_zed_pipe_output_stream_write (ZedPipeOutputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not yet implemented");
  return 0;
}

static gchar *
zed_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new ("zed-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

static WCHAR *
zed_pipe_path_from_name (const gchar * name)
{
  gchar * path_utf8;
  WCHAR * path;

  path_utf8 = g_strconcat ("\\\\.\\pipe\\", name, NULL);
  path = (WCHAR *) g_utf8_to_utf16 (path_utf8, -1, NULL, NULL, NULL);
  g_free (path_utf8);

  return path;
}

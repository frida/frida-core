#include "zed-pipe.h"

#include <errno.h>
#include <fcntl.h>
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* FIXME: this transport is not secure */

#define PIPE_CONNECT_INTERVAL 50

#define CHECK_POSIX_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_posix_error; \
  }

typedef struct _ZedPipeTransportBackend ZedPipeTransportBackend;
typedef struct _ZedPipeBackend ZedPipeBackend;
typedef guint ZedPipeRole;

struct _ZedPipeTransportBackend
{
  gchar * local_name;
  gchar * remote_name;
};

struct _ZedPipeBackend
{
  GMutex * mutex;
  ZedPipeRole role;
  gchar * rx_name;
  gchar * tx_name;
  GInputStream * input;
  GOutputStream * output;
  volatile gboolean connecting;
};

enum _ZedPipeRole
{
  ZED_PIPE_SERVER = 1,
  ZED_PIPE_CLIENT
};

static gboolean zed_pipe_backend_connect (ZedPipeBackend * backend, GCancellable * cancellable, GError ** error);
static void zed_pipe_fd_enable_blocking (int fd);
static gchar * zed_pipe_generate_name (void);

void *
_zed_pipe_transport_create_backend (guint pid, gchar ** local_address, gchar ** remote_address, GError ** error)
{
  ZedPipeTransportBackend * backend;
  int ret;
  const gchar * failed_operation;
  mode_t saved_umask;

  backend = g_slice_new (ZedPipeTransportBackend);

  backend->local_name = zed_pipe_generate_name ();
  backend->remote_name = zed_pipe_generate_name ();

  saved_umask = umask (0);

  ret = mkfifo (backend->local_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  CHECK_POSIX_RESULT (ret, ==, 0, "mkfifo");

  ret = mkfifo (backend->remote_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  CHECK_POSIX_RESULT (ret, ==, 0, "mkfifo");

  *local_address = g_strdup_printf ("pipe:role=server,rx=%s,tx=%s", backend->local_name, backend->remote_name);
  *remote_address = g_strdup_printf ("pipe:role=client,rx=%s,tx=%s", backend->remote_name, backend->local_name);

  goto beach;

handle_posix_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "%s failed: %s (%d)", failed_operation, strerror (errno), errno);
    _zed_pipe_transport_destroy_backend (backend);
    backend = NULL;
    goto beach;
  }
beach:
  {
    umask (saved_umask);

    return backend;
  }
}

void
_zed_pipe_transport_destroy_backend (void * b)
{
  ZedPipeTransportBackend * backend = (ZedPipeTransportBackend *) b;

  unlink (backend->local_name);
  g_free (backend->local_name);

  unlink (backend->remote_name);
  g_free (backend->remote_name);

  g_slice_free (ZedPipeTransportBackend, backend);
}

void *
_zed_pipe_create_backend (const gchar * address, GError ** error)
{
  ZedPipeBackend * backend;
  gchar ** tokens;
  int fd;
  const gchar * failed_operation;

  backend = g_slice_new0 (ZedPipeBackend);

  backend->mutex = g_mutex_new ();

  tokens = g_regex_split_simple ("^pipe:role=(.+?),rx=(.+?),tx=(.+?)$", address, 0, 0);
  g_assert_cmpuint (g_strv_length (tokens), ==, 5);

  backend->role = strcmp (tokens[1], "server") == 0 ? ZED_PIPE_SERVER : ZED_PIPE_CLIENT;
  backend->rx_name = g_strdup (tokens[2]);
  backend->tx_name = g_strdup (tokens[3]);

  fd = open (backend->rx_name, O_RDONLY | O_NONBLOCK);
  CHECK_POSIX_RESULT (fd, !=, -1, "open rx");
  zed_pipe_fd_enable_blocking (fd);
  backend->input = G_INPUT_STREAM (g_unix_input_stream_new (fd, TRUE));

  if (backend->role == ZED_PIPE_CLIENT)
  {
    fd = open (backend->tx_name, O_WRONLY | O_NONBLOCK);
    CHECK_POSIX_RESULT (fd, !=, -1, "open tx");
    zed_pipe_fd_enable_blocking (fd);
    backend->output = G_OUTPUT_STREAM (g_unix_output_stream_new (fd, TRUE));
    unlink (backend->tx_name);
  }

  backend->connecting = FALSE;

  goto beach;

handle_posix_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "%s failed: %s (%d)", failed_operation, strerror (errno), errno);
    _zed_pipe_destroy_backend (backend);
    backend = NULL;
    goto beach;
  }
beach:
  {
    g_strfreev (tokens);

    return backend;
  }
}

void
_zed_pipe_destroy_backend (void * b)
{
  ZedPipeBackend * backend = (ZedPipeBackend *) b;

  if (backend->input != NULL)
    g_object_unref (backend->input);
  if (backend->output != NULL)
    g_object_unref (backend->output);

  g_free (backend->rx_name);
  g_free (backend->tx_name);

  g_mutex_free (backend->mutex);

  g_slice_free (ZedPipeBackend, backend);
}

gboolean
_zed_pipe_close (ZedPipe * self, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;

  if (!g_input_stream_close (backend->input, NULL, error))
    return FALSE;

  if (backend->output != NULL)
    return g_output_stream_close (backend->output, NULL, error);

  return TRUE;
}

gssize
_zed_pipe_input_stream_read (ZedPipeInputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;

  if (!zed_pipe_backend_connect (backend, cancellable, error))
    return 0;

  return g_input_stream_read (backend->input, buffer, buffer_length, cancellable, error);
}

gssize
_zed_pipe_output_stream_write (ZedPipeOutputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;

  if (!zed_pipe_backend_connect (backend, cancellable, error))
    return 0;

  return g_output_stream_write (backend->output, buffer, buffer_length, cancellable, error);
}

static gboolean
zed_pipe_backend_connect (ZedPipeBackend * backend, GCancellable * cancellable, GError ** error)
{
  gboolean connected, is_master;
  GPollFD cancel;
  gboolean have_cancel_pollfd;

  if (backend->output != NULL)
    return TRUE;

  connected = FALSE;

  g_mutex_lock (backend->mutex);
  is_master = !backend->connecting;
  backend->connecting = TRUE;
  g_mutex_unlock (backend->mutex);

  have_cancel_pollfd = cancellable != NULL ? g_cancellable_make_pollfd (cancellable, &cancel) : FALSE;

  do
  {
    if (is_master)
    {
      int fd = open (backend->tx_name, O_WRONLY | O_NONBLOCK);
      if (fd != -1)
      {
        zed_pipe_fd_enable_blocking (fd);
        g_mutex_lock (backend->mutex);
        backend->output = G_OUTPUT_STREAM (g_unix_output_stream_new (fd, TRUE));
        g_mutex_unlock (backend->mutex);
        unlink (backend->tx_name);
      }
    }

    g_mutex_lock (backend->mutex);
    connected = backend->output != NULL;
    g_mutex_unlock (backend->mutex);

    if (!connected)
    {
      if (have_cancel_pollfd)
        g_poll (&cancel, 1, PIPE_CONNECT_INTERVAL);
      else
        g_usleep (PIPE_CONNECT_INTERVAL * 1000);
    }

    if (g_cancellable_set_error_if_cancelled (cancellable, error))
      return FALSE;
  }
  while (!connected);

  return TRUE;
}

static void
zed_pipe_fd_enable_blocking (int fd)
{
  int flags = fcntl (fd, F_GETFL);
  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

static gchar *
zed_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new ("/tmp/zed-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

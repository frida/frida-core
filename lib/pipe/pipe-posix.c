#include "frida-pipe.h"

#include <errno.h>
#include <fcntl.h>
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* FIXME: this transport is not secure */

#ifdef HAVE_ANDROID
# define FRIDA_TEMP_PATH "/data/local/tmp"
#else
# define FRIDA_TEMP_PATH "/tmp"
#endif
#define FRIDA_PIPE_CONNECT_INTERVAL 50

#define CHECK_POSIX_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_posix_error; \
  }

typedef struct _FridaPipeTransportBackend FridaPipeTransportBackend;
typedef struct _FridaPipeBackend FridaPipeBackend;
typedef guint FridaPipeRole;

struct _FridaPipeTransportBackend
{
  gchar * local_name;
  gchar * remote_name;
};

struct _FridaPipeBackend
{
  GMutex * mutex;
  FridaPipeRole role;
  gchar * rx_name;
  gchar * tx_name;
  GInputStream * input;
  GOutputStream * output;
  volatile gboolean connecting;
};

enum _FridaPipeRole
{
  FRIDA_PIPE_SERVER = 1,
  FRIDA_PIPE_CLIENT
};

static gboolean frida_pipe_backend_connect (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error);
static void frida_pipe_fd_enable_blocking (int fd);
static gchar * frida_pipe_generate_name (void);

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  FridaPipeTransportBackend * backend;
  int ret;
  const gchar * failed_operation;
  mode_t saved_umask;

  backend = g_slice_new (FridaPipeTransportBackend);

  backend->local_name = frida_pipe_generate_name ();
  backend->remote_name = frida_pipe_generate_name ();

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
    _frida_pipe_transport_destroy_backend (backend);
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
_frida_pipe_transport_destroy_backend (void * b)
{
  FridaPipeTransportBackend * backend = (FridaPipeTransportBackend *) b;

  unlink (backend->local_name);
  g_free (backend->local_name);

  unlink (backend->remote_name);
  g_free (backend->remote_name);

  g_slice_free (FridaPipeTransportBackend, backend);
}

void *
_frida_pipe_create_backend (const gchar * address, GError ** error)
{
  FridaPipeBackend * backend;
  gchar ** tokens;
  int fd;
  const gchar * failed_operation;

  backend = g_slice_new0 (FridaPipeBackend);

  backend->mutex = g_mutex_new ();

  tokens = g_regex_split_simple ("^pipe:role=(.+?),rx=(.+?),tx=(.+?)$", address, 0, 0);
  g_assert_cmpuint (g_strv_length (tokens), ==, 5);

  backend->role = strcmp (tokens[1], "server") == 0 ? FRIDA_PIPE_SERVER : FRIDA_PIPE_CLIENT;
  backend->rx_name = g_strdup (tokens[2]);
  backend->tx_name = g_strdup (tokens[3]);

  fd = open (backend->rx_name, O_RDONLY | O_NONBLOCK);
  CHECK_POSIX_RESULT (fd, !=, -1, "open rx");
  frida_pipe_fd_enable_blocking (fd);
  backend->input = G_INPUT_STREAM (g_unix_input_stream_new (fd, TRUE));

  if (backend->role == FRIDA_PIPE_CLIENT)
  {
    fd = open (backend->tx_name, O_WRONLY | O_NONBLOCK);
    CHECK_POSIX_RESULT (fd, !=, -1, "open tx");
    frida_pipe_fd_enable_blocking (fd);
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
    _frida_pipe_destroy_backend (backend);
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
_frida_pipe_destroy_backend (void * b)
{
  FridaPipeBackend * backend = (FridaPipeBackend *) b;

  if (backend->input != NULL)
    g_object_unref (backend->input);
  if (backend->output != NULL)
    g_object_unref (backend->output);

  g_free (backend->rx_name);
  g_free (backend->tx_name);

  g_mutex_free (backend->mutex);

  g_slice_free (FridaPipeBackend, backend);
}

gboolean
_frida_pipe_close (FridaPipe * self, GError ** error)
{
  FridaPipeBackend * backend = self->_backend;

  if (!g_input_stream_close (backend->input, NULL, error))
    return FALSE;

  if (backend->output != NULL)
    return g_output_stream_close (backend->output, NULL, error);

  return TRUE;
}

gssize
_frida_pipe_input_stream_read (FridaPipeInputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeBackend * backend = self->_backend;

  if (!frida_pipe_backend_connect (backend, cancellable, error))
    return -1;

  return g_input_stream_read (backend->input, buffer, buffer_length, cancellable, error);
}

gssize
_frida_pipe_output_stream_write (FridaPipeOutputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeBackend * backend = self->_backend;

  if (!frida_pipe_backend_connect (backend, cancellable, error))
    return -1;

  return g_output_stream_write (backend->output, buffer, buffer_length, cancellable, error);
}

static gboolean
frida_pipe_backend_connect (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error)
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
        frida_pipe_fd_enable_blocking (fd);
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
        g_poll (&cancel, 1, FRIDA_PIPE_CONNECT_INTERVAL);
      else
        g_usleep (FRIDA_PIPE_CONNECT_INTERVAL * 1000);
    }

    if (g_cancellable_set_error_if_cancelled (cancellable, error))
      return FALSE;
  }
  while (!connected);

  return TRUE;
}

static void
frida_pipe_fd_enable_blocking (int fd)
{
  int flags = fcntl (fd, F_GETFL);
  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

static gchar *
frida_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new (FRIDA_TEMP_PATH "/frida-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

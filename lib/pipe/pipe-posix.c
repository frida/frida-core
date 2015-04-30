#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wincompatible-pointer-types"
#endif
#include "pipe.c"
#ifdef __clang__
# pragma clang diagnostic pop
#endif

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
#ifdef HAVE_QNX
# define FRIDA_TEMP_PATH "/fs/tmpfs"
#else
# define FRIDA_TEMP_PATH "/tmp"
#endif
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
  GMutex mutex;
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

static gchar * temp_directory = NULL;

static const gchar *
frida_pipe_transport_get_temp_directory (void)
{
  if (temp_directory != NULL)
    return temp_directory;
  else
    return FRIDA_TEMP_PATH;
}

void
frida_pipe_transport_set_temp_directory (const gchar * path)
{
  g_free (temp_directory);
  temp_directory = g_strdup (path);
}

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  FridaPipeTransportBackend * backend;
  const int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  int ret;
  const gchar * failed_operation;

  backend = g_slice_new (FridaPipeTransportBackend);

  backend->local_name = frida_pipe_generate_name ();
  backend->remote_name = frida_pipe_generate_name ();

  ret = mkfifo (backend->local_name, mode);
  CHECK_POSIX_RESULT (ret, ==, 0, "mkfifo");

  ret = chmod (backend->local_name, mode);
  CHECK_POSIX_RESULT (ret, ==, 0, "chmod");

  ret = mkfifo (backend->remote_name, mode);
  CHECK_POSIX_RESULT (ret, ==, 0, "mkfifo");

  ret = chmod (backend->remote_name, mode);
  CHECK_POSIX_RESULT (ret, ==, 0, "chmod");

  *local_address = g_strdup_printf ("pipe:role=server,rx=%s,tx=%s", backend->local_name, backend->remote_name);
  *remote_address = g_strdup_printf ("pipe:role=client,rx=%s,tx=%s", backend->remote_name, backend->local_name);

  goto beach;

handle_posix_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_errno (errno),
        "Error creating FIFO with %s: %s",
        failed_operation, g_strerror (errno));
    _frida_pipe_transport_destroy_backend (backend);
    backend = NULL;
    goto beach;
  }
beach:
  {
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

  g_mutex_init (&backend->mutex);

  tokens = g_regex_split_simple ("^pipe:role=(.+?),rx=(.+?),tx=(.+?)$", address, 0, 0);
  g_assert_cmpuint (g_strv_length (tokens), ==, 5);

  backend->role = strcmp (tokens[1], "server") == 0 ? FRIDA_PIPE_SERVER : FRIDA_PIPE_CLIENT;
  backend->rx_name = g_strdup (tokens[2]);
  backend->tx_name = g_strdup (tokens[3]);

  fd = open (backend->rx_name, O_RDONLY | O_NONBLOCK);
  CHECK_POSIX_RESULT (fd, !=, -1, "rx");
  frida_pipe_fd_enable_blocking (fd);
  backend->input = G_INPUT_STREAM (g_unix_input_stream_new (fd, TRUE));

  if (backend->role == FRIDA_PIPE_CLIENT)
  {
    fd = open (backend->tx_name, O_WRONLY | O_NONBLOCK);
    CHECK_POSIX_RESULT (fd, !=, -1, "tx");
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
        g_io_error_from_errno (errno),
        "Error opening %s FIFO: %s",
        failed_operation, g_strerror (errno));
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

  g_mutex_clear (&backend->mutex);

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

static gssize
frida_pipe_input_stream_real_read (GInputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = self->_backend;

  if (!frida_pipe_backend_connect (backend, cancellable, error))
    return -1;

  return g_input_stream_read (backend->input, buffer, buffer_length, cancellable, error);
}

static gssize
frida_pipe_output_stream_real_write (GOutputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeOutputStream * self = FRIDA_PIPE_OUTPUT_STREAM (base);
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

  g_mutex_lock (&backend->mutex);
  is_master = !backend->connecting;
  backend->connecting = TRUE;
  g_mutex_unlock (&backend->mutex);

  have_cancel_pollfd = cancellable != NULL ? g_cancellable_make_pollfd (cancellable, &cancel) : FALSE;

  do
  {
    if (is_master)
    {
      int fd = open (backend->tx_name, O_WRONLY | O_NONBLOCK);
      if (fd != -1)
      {
        frida_pipe_fd_enable_blocking (fd);
        g_mutex_lock (&backend->mutex);
        backend->output = G_OUTPUT_STREAM (g_unix_output_stream_new (fd, TRUE));
        g_mutex_unlock (&backend->mutex);
        unlink (backend->tx_name);
      }
    }

    g_mutex_lock (&backend->mutex);
    connected = backend->output != NULL;
    g_mutex_unlock (&backend->mutex);

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

  s = g_string_new (frida_pipe_transport_get_temp_directory ());
  g_string_append (s, "/pipe-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

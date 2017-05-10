#include "pipe-impl.h"

#include <gio/gunixsocketaddress.h>
#ifdef HAVE_ANDROID
# include <selinux/selinux.h>
#endif
#include <string.h>
#include <sys/stat.h>

/* FIXME: this transport is not secure */

#if defined (HAVE_ANDROID)
# define FRIDA_TEMP_PATH "/data/local/tmp"
#elif defined (HAVE_QNX)
# define FRIDA_TEMP_PATH "/fs/tmpfs"
#else
# define FRIDA_TEMP_PATH "/tmp"
#endif

typedef struct _FridaPipeTransportBackend FridaPipeTransportBackend;
typedef struct _FridaPipeBackend FridaPipeBackend;
typedef guint FridaPipeRole;
typedef guint FridaPipeState;

struct _FridaPipeTransportBackend
{
  gchar * path;
};

struct _FridaPipeBackend
{
  GMutex mutex;
  GCond cond;
  FridaPipeRole role;
  GSocketAddress * address;
  GSocket * socket;
  GError * error;
  volatile FridaPipeState state;
};

enum _FridaPipeRole
{
  FRIDA_ROLE_SERVER = 1,
  FRIDA_ROLE_CLIENT
};

enum _FridaPipeState
{
  FRIDA_STATE_CREATED,
  FRIDA_STATE_CONNECTING,
  FRIDA_STATE_CONNECTED,
  FRIDA_STATE_ERROR
};

struct _FridaPipeInputStream
{
  GInputStream parent;

  FridaPipeBackend * backend;

  gpointer rx_buffer;
  guint8 * rx_buffer_cur;
  guint rx_buffer_length;
};

struct _FridaPipeOutputStream
{
  GOutputStream parent;

  FridaPipeBackend * backend;
};

static gssize frida_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean frida_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error);

static gssize frida_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean frida_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error);

static gchar * frida_pipe_generate_name (void);

G_DEFINE_TYPE (FridaPipeInputStream, frida_pipe_input_stream, G_TYPE_INPUT_STREAM)
G_DEFINE_TYPE (FridaPipeOutputStream, frida_pipe_output_stream, G_TYPE_OUTPUT_STREAM)

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

  backend = g_slice_new (FridaPipeTransportBackend);
  backend->path = frida_pipe_generate_name ();

  *local_address = g_strdup_printf ("pipe:role=server,path=%s", backend->path);
  *remote_address = g_strdup_printf ("pipe:role=client,path=%s", backend->path);

  return backend;
}

void
_frida_pipe_transport_destroy_backend (void * opaque_backend)
{
  FridaPipeTransportBackend * backend = opaque_backend;

  unlink (backend->path);
  g_free (backend->path);

  g_slice_free (FridaPipeTransportBackend, backend);
}

void *
_frida_pipe_create_backend (const gchar * address, GError ** error)
{
  FridaPipeBackend * backend;
  gchar ** tokens;

  backend = g_slice_new0 (FridaPipeBackend);

  g_mutex_init (&backend->mutex);
  g_cond_init (&backend->cond);

  tokens = g_regex_split_simple ("^pipe:role=(.+?),path=(.+?)$", address, 0, 0);
  g_assert_cmpuint (g_strv_length (tokens), ==, 4);

  backend->role = strcmp (tokens[1], "server") == 0 ? FRIDA_ROLE_SERVER : FRIDA_ROLE_CLIENT;
  backend->address = g_unix_socket_address_new (tokens[2]);
  backend->socket = g_socket_new (G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, error);
  if (backend->socket == NULL)
    goto handle_error;

  if (backend->role == FRIDA_ROLE_SERVER)
  {
    if (!g_socket_bind (backend->socket, backend->address, TRUE, error))
      goto handle_error;

    if (!g_socket_listen (backend->socket, error))
      goto handle_error;

    chmod (tokens[2], S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#ifdef HAVE_ANDROID
    setfilecon (tokens[2], "u:object_r:frida_file:s0");
#endif
  }

  backend->state = FRIDA_STATE_CREATED;

  goto beach;

handle_error:
  {
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
_frida_pipe_destroy_backend (void * opaque_backend)
{
  FridaPipeBackend * backend = opaque_backend;

  if (backend->error != NULL)
    g_error_free (backend->error);
  if (backend->socket != NULL)
    g_object_unref (backend->socket);
  g_object_unref (backend->address);

  g_cond_clear (&backend->cond);
  g_mutex_clear (&backend->mutex);

  g_slice_free (FridaPipeBackend, backend);
}

gboolean
_frida_pipe_close_backend (void * opaque_backend, GError ** error)
{
  FridaPipeBackend * backend = opaque_backend;

  return g_socket_close (backend->socket, error);
}

static gboolean
frida_pipe_backend_establish (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error)
{
  gboolean success = TRUE;

  g_mutex_lock (&backend->mutex);
  switch (backend->state)
  {
    case FRIDA_STATE_CREATED:
    {
      GError * e = NULL;

      backend->state = FRIDA_STATE_CONNECTING;
      if (backend->role == FRIDA_ROLE_SERVER)
      {
        GSocket * client;

        g_mutex_unlock (&backend->mutex);
        client = g_socket_accept (backend->socket, cancellable, &e);
        g_mutex_lock (&backend->mutex);
        if (client != NULL)
        {
          backend->state = FRIDA_STATE_CONNECTED;
          g_object_unref (backend->socket);
          backend->socket = client;
        }
      }
      else
      {
        gboolean connected;

        g_mutex_unlock (&backend->mutex);
        connected = g_socket_connect (backend->socket, backend->address, cancellable, &e);
        g_mutex_lock (&backend->mutex);
        if (connected)
        {
          backend->state = FRIDA_STATE_CONNECTED;
        }
      }

      if (e != NULL)
      {
        if (!g_cancellable_is_cancelled (cancellable))
        {
          backend->state = FRIDA_STATE_ERROR;
          backend->error = g_error_copy (e);
        }
        else
        {
          backend->state = FRIDA_STATE_CREATED;
        }
        g_propagate_error (error, e);
      }

      g_cond_broadcast (&backend->cond);
      g_mutex_unlock (&backend->mutex);

      return e == NULL;
    }
    case FRIDA_STATE_CONNECTING:
      while (backend->state == FRIDA_STATE_CONNECTING)
        g_cond_wait (&backend->cond, &backend->mutex);
      g_mutex_unlock (&backend->mutex);
      return frida_pipe_backend_establish (backend, cancellable, error);
    case FRIDA_STATE_CONNECTED:
      break;
    case FRIDA_STATE_ERROR:
      if (error != NULL)
        *error = g_error_copy (backend->error);
      success = FALSE;
      break;
  }
  g_mutex_unlock (&backend->mutex);

  return success;
}

GInputStream *
_frida_pipe_make_input_stream (void * backend)
{
  FridaPipeInputStream * stream;

  stream = g_object_new (FRIDA_TYPE_PIPE_INPUT_STREAM, NULL);
  stream->backend = backend;

  return G_INPUT_STREAM (stream);
}

GOutputStream *
_frida_pipe_make_output_stream (void * backend)
{
  FridaPipeOutputStream * stream;

  stream = g_object_new (FRIDA_TYPE_PIPE_OUTPUT_STREAM, NULL);
  stream->backend = backend;

  return G_OUTPUT_STREAM (stream);
}

static void
frida_pipe_input_stream_class_init (FridaPipeInputStreamClass * klass)
{
  GInputStreamClass * stream_class = G_INPUT_STREAM_CLASS (klass);

  stream_class->read_fn = frida_pipe_input_stream_read;
  stream_class->close_fn = frida_pipe_input_stream_close;
}

static void
frida_pipe_input_stream_init (FridaPipeInputStream * self)
{
}

static gssize
frida_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = self->backend;

  if (!frida_pipe_backend_establish (backend, cancellable, error))
    return -1;

  return g_socket_receive (backend->socket, buffer, count, cancellable, error);
}

static gboolean
frida_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static void
frida_pipe_output_stream_class_init (FridaPipeOutputStreamClass * klass)
{
  GOutputStreamClass * stream_class = G_OUTPUT_STREAM_CLASS (klass);

  stream_class->write_fn = frida_pipe_output_stream_write;
  stream_class->close_fn = frida_pipe_output_stream_close;
}

static void
frida_pipe_output_stream_init (FridaPipeOutputStream * self)
{
}

static gssize
frida_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  FridaPipeOutputStream * self = FRIDA_PIPE_OUTPUT_STREAM (base);
  FridaPipeBackend * backend = self->backend;

  if (!frida_pipe_backend_establish (backend, cancellable, error))
    return -1;

  return g_socket_send (backend->socket, buffer, count, cancellable, error);
}

static gboolean
frida_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
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

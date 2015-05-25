#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wincompatible-pointer-types"
#endif
#include "pipe.c"
#ifdef __clang__
# pragma clang diagnostic pop
#endif

#include <gio/gunixsocketaddress.h>
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
  FRIDA_PIPE_SERVER = 1,
  FRIDA_PIPE_CLIENT
};

enum _FridaPipeState
{
  FRIDA_PIPE_CREATED,
  FRIDA_PIPE_CONNECTING,
  FRIDA_PIPE_CONNECTED,
  FRIDA_PIPE_ERROR
};

static gboolean frida_pipe_backend_establish (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error);
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

  backend = g_slice_new (FridaPipeTransportBackend);
  backend->path = frida_pipe_generate_name ();

  *local_address = g_strdup_printf ("pipe:role=server,path=%s", backend->path);
  *remote_address = g_strdup_printf ("pipe:role=client,path=%s", backend->path);

  return backend;
}

void
_frida_pipe_transport_destroy_backend (void * b)
{
  FridaPipeTransportBackend * backend = (FridaPipeTransportBackend *) b;

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

  backend->role = strcmp (tokens[1], "server") == 0 ? FRIDA_PIPE_SERVER : FRIDA_PIPE_CLIENT;
  backend->address = g_unix_socket_address_new (tokens[2]);
  backend->socket = g_socket_new (G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, error);
  if (backend->socket == NULL)
    goto handle_error;

  if (backend->role == FRIDA_PIPE_SERVER)
  {
    if (!g_socket_bind (backend->socket, backend->address, TRUE, error))
      goto handle_error;

    if (!g_socket_listen (backend->socket, error))
      goto handle_error;

    chmod (tokens[2], S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  }

  backend->state = FRIDA_PIPE_CREATED;

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
_frida_pipe_destroy_backend (void * b)
{
  FridaPipeBackend * backend = (FridaPipeBackend *) b;

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
_frida_pipe_close (FridaPipe * self, GError ** error)
{
  FridaPipeBackend * backend = self->_backend;

  return g_socket_close (backend->socket, error);
}

static gssize
frida_pipe_input_stream_real_read (GInputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = self->_backend;

  if (!frida_pipe_backend_establish (backend, cancellable, error))
    return -1;

  return g_socket_receive (backend->socket, (gchar *) buffer, buffer_length, cancellable, error);
}

static gssize
frida_pipe_output_stream_real_write (GOutputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeOutputStream * self = FRIDA_PIPE_OUTPUT_STREAM (base);
  FridaPipeBackend * backend = self->_backend;

  if (!frida_pipe_backend_establish (backend, cancellable, error))
    return -1;

  return g_socket_send (backend->socket, (gchar *) buffer, buffer_length, cancellable, error);
}

static gboolean
frida_pipe_backend_establish (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error)
{
  gboolean success = TRUE;

  g_mutex_lock (&backend->mutex);
  switch (backend->state)
  {
    case FRIDA_PIPE_CREATED:
    {
      GError * e = NULL;

      backend->state = FRIDA_PIPE_CONNECTING;
      if (backend->role == FRIDA_PIPE_SERVER)
      {
        GSocket * client;

        g_mutex_unlock (&backend->mutex);
        client = g_socket_accept (backend->socket, cancellable, &e);
        g_mutex_lock (&backend->mutex);
        if (client != NULL)
        {
          backend->state = FRIDA_PIPE_CONNECTED;
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
          backend->state = FRIDA_PIPE_CONNECTED;
        }
      }

      if (e != NULL)
      {
        if (!g_cancellable_is_cancelled (cancellable))
        {
          backend->state = FRIDA_PIPE_ERROR;
          backend->error = e;
        }
        else
        {
          backend->state = FRIDA_PIPE_CREATED;
          g_propagate_error (error, e);
        }
      }

      g_cond_broadcast (&backend->cond);
      g_mutex_unlock (&backend->mutex);

      return e == NULL;
    }
    case FRIDA_PIPE_CONNECTING:
      while (backend->state == FRIDA_PIPE_CONNECTING)
        g_cond_wait (&backend->cond, &backend->mutex);
      g_mutex_unlock (&backend->mutex);
      return frida_pipe_backend_establish (backend, cancellable, error);
    case FRIDA_PIPE_CONNECTED:
      break;
    case FRIDA_PIPE_ERROR:
      if (error != NULL)
        *error = g_error_copy (backend->error);
      success = FALSE;
      break;
  }
  g_mutex_unlock (&backend->mutex);

  return success;
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

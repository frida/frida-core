#include "pipe-impl.h"

#include <stdio.h>
#include <mach/mach.h>

#define FRIDA_PIPE_MAX_WRITE_SIZE (10 * 1024 * 1024)

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _FridaPipeBackend FridaPipeBackend;
typedef struct _FridaInitMessage FridaInitMessage;
typedef struct _FridaPipeMessage FridaPipeMessage;

struct _FridaPipeBackend
{
  mach_port_t rx_set;
  mach_port_t rx_port;
  mach_port_t tx_port;
  mach_port_t notify_port;

  gboolean eof;
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

struct _FridaInitMessage
{
  mach_msg_header_t header;
  mach_msg_trailer_t trailer;
};

struct _FridaPipeMessage
{
  mach_msg_header_t header;
  guint size;
  guint8 payload[0];
};

static gboolean frida_pipe_backend_close_ports (FridaPipeBackend * self, GError ** error);

static void frida_pipe_input_stream_finalize (GObject * object);
static gssize frida_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static void frida_pipe_input_stream_on_cancel (GCancellable * cancellable, gpointer user_data);
static gboolean frida_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error);

static gssize frida_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean frida_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error);

G_DEFINE_TYPE (FridaPipeInputStream, frida_pipe_input_stream, G_TYPE_INPUT_STREAM)
G_DEFINE_TYPE (FridaPipeOutputStream, frida_pipe_output_stream, G_TYPE_OUTPUT_STREAM)

void
frida_pipe_transport_set_temp_directory (const gchar * path)
{
  (void) path;
}

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  mach_port_t self_task;
  mach_port_t local_rx = MACH_PORT_NULL;
  mach_port_t local_tx = MACH_PORT_NULL;
  mach_port_t remote_rx = MACH_PORT_NULL;
  mach_port_t remote_tx = MACH_PORT_NULL;
  kern_return_t ret;
  const gchar * failed_operation;
  mach_msg_type_name_t acquired_type;

  self_task = mach_task_self ();

  ret = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate local_rx");

  ret = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate remote_rx");

  ret = mach_port_extract_right (self_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &remote_tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_extract_right remote_tx");

  ret = mach_port_extract_right (self_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &local_tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_extract_right local_tx");

  *local_address = g_strdup_printf ("pipe:rx=%d,tx=%d", local_rx, local_tx);
  *remote_address = g_strdup_printf ("pipe:rx=%d,tx=%d", remote_rx, remote_tx);

  return NULL;

handle_mach_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Unexpected error while setting up mach ports (%s returned '%s')",
        failed_operation, mach_error_string (ret));

    if (remote_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_tx);
    if (local_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_tx);
    if (remote_rx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
    if (local_rx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    return NULL;
  }
}

void
_frida_pipe_transport_destroy_backend (void * backend)
{
  (void) backend;
}

void *
_frida_pipe_create_backend (const gchar * address, GError ** error)
{
  int rx, tx, assigned;
  FridaPipeBackend * backend;
  mach_port_t self_task, prev_notify_port;

  assigned = sscanf (address, "pipe:rx=%d,tx=%d", &rx, &tx);

  if (assigned == 1)
  {
    FridaInitMessage init;
    kern_return_t kr;

    bzero (&init, sizeof (init));
    init.header.msgh_size = sizeof (init);
    init.header.msgh_local_port = rx;

    kr = mach_msg_receive (&init.header);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);

    tx = init.header.msgh_remote_port;
  }
  else
  {
    g_assert_cmpint (assigned, ==, 2);
  }

  backend = g_slice_new (FridaPipeBackend);

  self_task = mach_task_self ();

  mach_port_allocate (self_task, MACH_PORT_RIGHT_PORT_SET, &backend->rx_set);

  backend->rx_port = rx;
  mach_port_move_member (self_task, backend->rx_port, backend->rx_set);

  backend->tx_port = tx;

  mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &backend->notify_port);
  mach_port_insert_right (self_task, backend->notify_port, backend->notify_port, MACH_MSG_TYPE_MAKE_SEND);
  mach_port_request_notification (self_task, backend->tx_port, MACH_NOTIFY_DEAD_NAME, TRUE,
      backend->notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev_notify_port);
  mach_port_move_member (self_task, backend->notify_port, backend->rx_set);

  backend->eof = FALSE;

  return backend;
}

void
_frida_pipe_destroy_backend (void * backend)
{
  g_slice_free (FridaPipeBackend, backend);
}

gboolean
_frida_pipe_close_backend (void * backend, GError ** error)
{
  return frida_pipe_backend_close_ports (backend, error);
}

static gboolean
frida_pipe_backend_close_ports (FridaPipeBackend * self, GError ** error)
{
  mach_port_t self_task;

  self_task = mach_task_self ();

  if (self->notify_port != MACH_PORT_NULL)
  {
    mach_port_mod_refs (self_task, self->notify_port, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs (self_task, self->notify_port, MACH_PORT_RIGHT_RECEIVE, -1);
    self->notify_port = MACH_PORT_NULL;
  }

  if (self->tx_port != MACH_PORT_NULL)
  {
    mach_port_deallocate (self_task, self->tx_port);
    self->tx_port = MACH_PORT_NULL;
  }

  if (self->rx_port != MACH_PORT_NULL)
  {
    mach_port_mod_refs (self_task, self->rx_port, MACH_PORT_RIGHT_RECEIVE, -1);
    self->rx_port = MACH_PORT_NULL;
  }

  if (self->rx_set != MACH_PORT_NULL)
  {
    mach_port_mod_refs (self_task, self->rx_set, MACH_PORT_RIGHT_PORT_SET, -1);
    self->rx_set = MACH_PORT_NULL;
  }

  return TRUE;
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
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GInputStreamClass * stream_class = G_INPUT_STREAM_CLASS (klass);

  object_class->finalize = frida_pipe_input_stream_finalize;

  stream_class->read_fn = frida_pipe_input_stream_read;
  stream_class->close_fn = frida_pipe_input_stream_close;
}

static void
frida_pipe_input_stream_init (FridaPipeInputStream * self)
{
}

static void
frida_pipe_input_stream_finalize (GObject * object)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (object);

  g_free (self->rx_buffer);

  G_OBJECT_CLASS (frida_pipe_input_stream_parent_class)->finalize (object);
}

static gssize
frida_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = self->backend;
  FridaPipeMessage * msg = NULL;
  kern_return_t ret;
  gssize n;

  if (backend->eof)
    goto handle_eof;

  if (self->rx_buffer == NULL)
  {
    gulong handler_id = 0;
    gulong msg_size;

    if (cancellable != NULL)
    {
      handler_id = g_cancellable_connect (cancellable, G_CALLBACK (frida_pipe_input_stream_on_cancel), self, NULL);
    }

    msg_size = 256;
    msg = g_realloc (NULL, msg_size);
    do
    {
      ret = mach_msg (&msg->header, MACH_RCV_MSG | MACH_RCV_LARGE, 0, msg_size, backend->rx_set, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
      if (ret == MACH_RCV_TOO_LARGE)
      {
        msg_size = msg->header.msgh_size + sizeof (mach_msg_trailer_t);
        msg = g_realloc (msg, msg_size);
      }
    }
    while (ret == MACH_RCV_TOO_LARGE);

    if (cancellable != NULL)
    {
      g_cancellable_disconnect (cancellable, handler_id);
    }

    if (ret != 0)
      goto handle_error;

    if (msg->header.msgh_local_port == backend->rx_port)
    {
      if (msg->header.msgh_id == 1)
      {
        self->rx_buffer = msg;
        self->rx_buffer_cur = msg->payload;
        self->rx_buffer_length = msg->size;
      }
      else
      {
        g_free (msg);
      }
    }
    else
    {
      g_assert_cmpuint (msg->header.msgh_local_port, ==, backend->notify_port);
      g_assert_cmpuint (msg->header.msgh_id, ==, MACH_NOTIFY_DEAD_NAME);

      backend->eof = TRUE;
    }

    if (cancellable != NULL && g_cancellable_set_error_if_cancelled (cancellable, error))
      goto handle_cancel;

    if (backend->eof)
      goto handle_eof;
  }

  n = MIN (count, self->rx_buffer_length);
  memcpy (buffer, self->rx_buffer_cur, n);
  self->rx_buffer_cur += n;
  self->rx_buffer_length -= n;
  if (self->rx_buffer_length == 0)
  {
    g_free (self->rx_buffer);
    self->rx_buffer = NULL;
    self->rx_buffer_cur = NULL;
    self->rx_buffer_length = 0;
  }

  return n;

handle_error:
  {
    g_free (msg);
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Error reading from mach port: %s",
        mach_error_string (ret));
    return -1;
  }

handle_eof:
  {
    return 0;
  }

handle_cancel:
  {
    return -1;
  }
}

static void
frida_pipe_input_stream_on_cancel (GCancellable * cancellable, gpointer user_data)
{
  FridaPipeInputStream * self = user_data;
  FridaPipeMessage msg;

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_remote_port = self->backend->rx_port;
  msg.header.msgh_local_port = MACH_PORT_NULL;
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 2;
  msg.size = 0;
  mach_msg_send (&msg.header);
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
  gint len;
  guint msg_size;
  FridaPipeMessage * msg;
  kern_return_t ret;

  len = MIN (count, FRIDA_PIPE_MAX_WRITE_SIZE);
  msg_size = (guint) (sizeof (FridaPipeMessage) + len + 3) & ~3;
  msg = g_malloc (msg_size);
  msg->header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0);
  msg->header.msgh_size = msg_size;
  msg->header.msgh_remote_port = self->backend->tx_port;
  msg->header.msgh_local_port = MACH_PORT_NULL;
  msg->header.msgh_reserved = 0;
  msg->header.msgh_id = 1;
  msg->size = len;
  memcpy (msg->payload, buffer, len);
  ret = mach_msg_send (&msg->header);
  g_free (msg);
  if (ret != 0)
    goto handle_error;

  return len;

handle_error:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Error writing to mach port: %s",
        mach_error_string (ret));
    return -1;
  }
}

static gboolean
frida_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

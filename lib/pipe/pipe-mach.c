#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wincompatible-pointer-types"
#endif
#include "pipe.c"
#ifdef __clang__
# pragma clang diagnostic pop
#endif

#include <stdio.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _FridaPipeBackend FridaPipeBackend;
typedef struct _FridaPipeMessage FridaPipeMessage;

struct _FridaPipeBackend
{
  dispatch_queue_t dispatch_queue;
  mach_port_name_t rx_port;
  mach_port_name_t tx_port;
  gpointer rx_buffer;
  guint8 * rx_buffer_cur;
  guint rx_buffer_length;
  dispatch_source_t monitor_source;
};

struct _FridaPipeMessage
{
  mach_msg_header_t header;
  guint size;
  guint8 payload[0];
};

static void frida_pipe_backend_demonitor (FridaPipeBackend * backend);
static void frida_pipe_backend_on_tx_port_dead (void * context);

static void frida_pipe_input_stream_on_cancel (GCancellable * cancellable, gpointer user_data);

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  mach_port_t self_task;
  mach_port_name_t local_rx = MACH_PORT_NULL;
  mach_port_name_t local_tx = MACH_PORT_NULL;
  mach_port_name_t remote_rx = MACH_PORT_NULL;
  mach_port_name_t remote_tx = MACH_PORT_NULL;
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
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed while trying to make pipe transport: %s (%d)", failed_operation, mach_error_string (ret), ret);

    if (remote_tx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, remote_tx, MACH_PORT_RIGHT_SEND, -1);
    if (local_tx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, local_tx, MACH_PORT_RIGHT_SEND, -1);
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
  FridaPipeBackend * backend;
  int rx, tx, assigned;
  dispatch_source_t source;

  backend = g_slice_new (FridaPipeBackend);
  backend->dispatch_queue = dispatch_queue_create ("org.boblycat.frida.pipe.queue", NULL);
  assigned = sscanf (address, "pipe:rx=%d,tx=%d", &rx, &tx);
  g_assert_cmpint (assigned, ==, 2);
  backend->rx_port = rx;
  backend->tx_port = tx;
  backend->rx_buffer = NULL;
  backend->rx_buffer_cur = NULL;
  backend->rx_buffer_length = 0;

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, backend->tx_port, DISPATCH_MACH_SEND_DEAD, backend->dispatch_queue);
  backend->monitor_source = source;
  dispatch_set_context (source, backend);
  dispatch_source_set_event_handler_f (source, frida_pipe_backend_on_tx_port_dead);
  dispatch_resume (source);

  return backend;
}

void
_frida_pipe_destroy_backend (void * b)
{
  FridaPipeBackend * backend = (FridaPipeBackend *) b;

  frida_pipe_backend_demonitor (backend);

  g_free (backend->rx_buffer);
  dispatch_release (backend->dispatch_queue);

  g_slice_free (FridaPipeBackend, backend);
}

static void
frida_pipe_backend_demonitor (FridaPipeBackend * self)
{
  if (self->monitor_source != NULL)
  {
    dispatch_release (self->monitor_source);
    self->monitor_source = NULL;
  }
}

static gboolean
frida_pipe_backend_close_ports (FridaPipeBackend * self, GError ** error)
{
  kern_return_t ret_tx = 0, ret_rx = 0, ret;

  if (self->tx_port != MACH_PORT_NULL)
  {
    ret_tx = mach_port_mod_refs (mach_task_self (), self->tx_port, MACH_PORT_RIGHT_SEND, -1);
    self->tx_port = MACH_PORT_NULL;
  }

  if (self->rx_port != MACH_PORT_NULL)
  {
    ret_rx = mach_port_mod_refs (mach_task_self (), self->rx_port, MACH_PORT_RIGHT_RECEIVE, -1);
    self->rx_port = MACH_PORT_NULL;
  }

  ret = ret_tx != 0 ? ret_tx : ret_rx;
  if (ret != 0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "mach_port_mod_refs failed: %s (%d)", mach_error_string (ret), ret);
    return FALSE;
  }

  return TRUE;
}

gboolean
_frida_pipe_close (FridaPipe * self, GError ** error)
{
  FridaPipeBackend * backend = self->_backend;

  frida_pipe_backend_demonitor (backend);

  return frida_pipe_backend_close_ports (backend, error);
}

static void
frida_pipe_backend_on_tx_port_dead (void * context)
{
  FridaPipeBackend * self = context;

  mach_port_mod_refs (mach_task_self (), self->tx_port, MACH_PORT_RIGHT_DEAD_NAME, -1);
  self->tx_port = MACH_PORT_NULL;

  frida_pipe_backend_close_ports (self, NULL);
}

static gssize
frida_pipe_input_stream_real_read (GInputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeInputStream * self = FRIDA_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = self->_backend;
  FridaPipeMessage * msg = NULL;
  kern_return_t ret;
  gssize n;

  if (backend->rx_buffer == NULL)
  {
    gulong handler_id = 0;
    gulong msg_size;

    if (cancellable != NULL)
    {
      handler_id = g_cancellable_connect (cancellable, G_CALLBACK (frida_pipe_input_stream_on_cancel), self, NULL);
    }

    msg_size = sizeof (mach_msg_empty_rcv_t);
    msg = g_realloc (NULL, msg_size);
    do
    {
      ret = mach_msg (&msg->header, MACH_RCV_MSG | MACH_RCV_LARGE, 0, msg_size, backend->rx_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
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

    if (msg->header.msgh_id == 1)
    {
      backend->rx_buffer = msg;
      backend->rx_buffer_cur = msg->payload;
      backend->rx_buffer_length = msg->size;
    }
    else
    {
      g_free (msg);
    }

    if (cancellable != NULL && g_cancellable_set_error_if_cancelled (cancellable, error))
      goto handle_cancel;
  }

  n = MIN (buffer_length, backend->rx_buffer_length);
  memcpy (buffer, backend->rx_buffer_cur, n);
  backend->rx_buffer_cur += n;
  backend->rx_buffer_length -= n;
  if (backend->rx_buffer_length == 0)
  {
    g_free (backend->rx_buffer);
    backend->rx_buffer = NULL;
    backend->rx_buffer_cur = NULL;
    backend->rx_buffer_length = 0;
  }

  return n;

handle_error:
  {
    g_free (msg);
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "mach_msg failed: %s (%d)", mach_error_string (ret), ret);
    return -1;
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
  FridaPipeBackend * backend = self->_backend;
  FridaPipeMessage msg;

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_remote_port = backend->rx_port;
  msg.header.msgh_local_port = MACH_PORT_NULL;
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 2;
  msg.size = 0;
  mach_msg_send (&msg.header);
}

static gssize
frida_pipe_output_stream_real_write (GOutputStream * base, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  FridaPipeOutputStream * self = FRIDA_PIPE_OUTPUT_STREAM (base);
  FridaPipeBackend * backend = self->_backend;
  guint msg_size;
  FridaPipeMessage * msg;
  kern_return_t ret;

  msg_size = (sizeof (FridaPipeMessage) + buffer_length + 3) & ~3;
  msg = g_malloc (msg_size);
  msg->header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0);
  msg->header.msgh_size = msg_size;
  msg->header.msgh_remote_port = backend->tx_port;
  msg->header.msgh_local_port = MACH_PORT_NULL;
  msg->header.msgh_reserved = 0;
  msg->header.msgh_id = 1;
  msg->size = buffer_length;
  memcpy (msg->payload, buffer, buffer_length);
  ret = mach_msg_send (&msg->header);
  g_free (msg);
  if (ret != 0)
    goto handle_error;

  return buffer_length;

handle_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "mach_msg_send failed: %s (%d)", mach_error_string (ret), ret);
    return -1;
  }
}

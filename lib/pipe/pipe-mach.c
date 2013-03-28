#include "zed-pipe.h"

#include <stdio.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _ZedPipeTransportBackend ZedPipeTransportBackend;
typedef struct _ZedPipeBackend ZedPipeBackend;
typedef struct _ZedPipeMessage ZedPipeMessage;

struct _ZedPipeTransportBackend
{
  mach_port_t task;
  mach_port_name_t local_rx;
  mach_port_name_t local_tx;
  mach_port_name_t remote_rx;
  mach_port_name_t remote_tx;
};

struct _ZedPipeBackend
{
  dispatch_queue_t dispatch_queue;
  mach_port_name_t rx_port;
  mach_port_name_t tx_port;
  gpointer rx_buffer;
  guint8 * rx_buffer_cur;
  guint rx_buffer_length;
  dispatch_source_t monitor_source;
};

struct _ZedPipeMessage
{
  mach_msg_header_t header;
  guint size;
  guint8 payload[0];
};

static void zed_pipe_demonitor (ZedPipe * self);
static void zed_pipe_on_tx_port_dead (void * context);
static gboolean zed_pipe_on_tx_port_dead_idle (gpointer user_data);

static void zed_pipe_input_stream_on_cancel (GCancellable * cancellable, gpointer user_data);

void
_zed_pipe_transport_create_backend (ZedPipeTransport * self, gulong pid, GError ** error)
{
  ZedPipeTransportBackend * backend;
  const gchar * failed_operation;
  kern_return_t ret;
  mach_msg_type_name_t acquired_type;

  backend = g_slice_new (ZedPipeTransportBackend);
  backend->task = MACH_PORT_NULL;
  backend->local_rx = MACH_PORT_NULL;
  backend->local_tx = MACH_PORT_NULL;
  backend->remote_rx = MACH_PORT_NULL;
  backend->remote_tx = MACH_PORT_NULL;
  self->_backend = backend;

  ret = task_for_pid (mach_task_self (), pid, &backend->task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");

  ret = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &backend->local_rx);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate local_rx");

  ret = mach_port_allocate (backend->task, MACH_PORT_RIGHT_RECEIVE, &backend->remote_rx);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate remote_rx");

  ret = mach_port_extract_right (backend->task, backend->remote_rx, MACH_MSG_TYPE_MAKE_SEND, &backend->local_tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_extract_right local_tx");

  backend->remote_tx = backend->local_rx - 1;
  do
  {
    backend->remote_tx++;
    ret = mach_port_insert_right (backend->task, backend->remote_tx, backend->local_rx, MACH_MSG_TYPE_MAKE_SEND);
  }
  while ((ret == KERN_NAME_EXISTS || ret == KERN_FAILURE) && backend->remote_tx < backend->local_rx + 10000);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_insert_right remote_tx");

  self->local_address = g_strdup_printf ("pipe:rx=%d,tx=%d", backend->local_rx, backend->local_tx);
  self->remote_address = g_strdup_printf ("pipe:rx=%d,tx=%d", backend->remote_rx, backend->remote_tx);

  return;

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %s (%d)", failed_operation, mach_error_string (ret), ret);
    _zed_pipe_transport_destroy_backend (self);
  }
}

void
_zed_pipe_transport_destroy_backend (ZedPipeTransport * self)
{
  ZedPipeTransportBackend * backend = self->_backend;
  task_t self_task = mach_task_self ();

  if (backend->remote_tx != MACH_PORT_NULL)
    mach_port_mod_refs (backend->task, backend->remote_tx, MACH_PORT_RIGHT_SEND, -1);
  if (backend->local_tx != MACH_PORT_NULL)
    mach_port_mod_refs (self_task, backend->local_tx, MACH_PORT_RIGHT_SEND, -1);
  if (backend->remote_rx != MACH_PORT_NULL)
    mach_port_mod_refs (backend->task, backend->remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
  if (backend->local_rx != MACH_PORT_NULL)
    mach_port_mod_refs (self_task, backend->local_rx, MACH_PORT_RIGHT_RECEIVE, -1);
  if (backend->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, backend->task);

  g_slice_free (ZedPipeTransportBackend, backend);
}

void
_zed_pipe_create_backend (ZedPipe * self)
{
  ZedPipeBackend * backend;
  int rx, tx, assigned;
  dispatch_source_t source;

  backend = g_slice_new (ZedPipeBackend);
  backend->dispatch_queue = dispatch_queue_create ("org.boblycat.frida.pipe.queue", NULL);
  assigned = sscanf (zed_pipe_get_address (self), "pipe:rx=%d,tx=%d", &rx, &tx);
  g_assert_cmpint (assigned, ==, 2);
  backend->rx_port = rx;
  backend->tx_port = tx;
  backend->rx_buffer = NULL;
  backend->rx_buffer_cur = NULL;
  backend->rx_buffer_length = 0;

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, backend->tx_port, DISPATCH_MACH_SEND_DEAD, backend->dispatch_queue);
  backend->monitor_source = source;
  dispatch_set_context (source, self);
  dispatch_source_set_event_handler_f (source, zed_pipe_on_tx_port_dead);
  dispatch_resume (source);

  self->_backend = backend;
}

void
_zed_pipe_destroy_backend (ZedPipe * self)
{
  ZedPipeBackend * backend = self->_backend;

  zed_pipe_demonitor (self);

  g_free (backend->rx_buffer);
  dispatch_release (backend->dispatch_queue);

  g_slice_free (ZedPipeBackend, backend);
}

static void
zed_pipe_demonitor (ZedPipe * self)
{
  ZedPipeBackend * backend = self->_backend;

  if (backend->monitor_source != NULL)
  {
    dispatch_release (backend->monitor_source);
    backend->monitor_source = NULL;
  }
}

gboolean
_zed_pipe_close (ZedPipe * self, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;
  task_t self_task = mach_task_self ();
  kern_return_t ret_tx, ret_rx, ret;

  zed_pipe_demonitor (self);

  ret_tx = mach_port_mod_refs (self_task, backend->tx_port, MACH_PORT_RIGHT_SEND, -1);
  ret_rx = mach_port_mod_refs (self_task, backend->rx_port, MACH_PORT_RIGHT_RECEIVE, -1);
  ret = ret_tx != 0 ? ret_tx : ret_rx;
  if (ret != 0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "mach_port_mod_refs failed: %s (%d)", mach_error_string (ret), ret);
    return FALSE;
  }

  return TRUE;
}

static void
zed_pipe_on_tx_port_dead (void * context)
{
  ZedPipe * pipe = context;
  GSource * source;

  source = g_idle_source_new ();
  g_source_set_callback (source, zed_pipe_on_tx_port_dead_idle, g_object_ref (pipe), g_object_unref);
  g_source_attach (source, pipe->_main_context);
  g_source_unref (source);
}

static gboolean
zed_pipe_on_tx_port_dead_idle (gpointer user_data)
{
  ZedPipe * pipe = user_data;

  g_io_stream_close (G_IO_STREAM (pipe), NULL, NULL);

  return FALSE;
}

gssize
_zed_pipe_input_stream_read (ZedPipeInputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;
  ZedPipeMessage * msg = NULL;
  kern_return_t ret;
  gssize n;

  if (backend->rx_buffer == NULL)
  {
    gulong handler_id;
    gulong msg_size;

    handler_id = g_cancellable_connect (cancellable, G_CALLBACK (zed_pipe_input_stream_on_cancel), self, NULL);

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

    g_cancellable_disconnect (cancellable, handler_id);

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

    if (g_cancellable_set_error_if_cancelled (cancellable, error))
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
    return 0;
  }

handle_cancel:
  {
    return -1;
  }
}

static void
zed_pipe_input_stream_on_cancel (GCancellable * cancellable, gpointer user_data)
{
  ZedPipeInputStream * self = user_data;
  ZedPipeBackend * backend = self->_backend;
  ZedPipeMessage msg;

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_remote_port = backend->rx_port;
  msg.header.msgh_local_port = MACH_PORT_NULL;
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 2;
  msg.size = 0;
  mach_msg_send (&msg.header);
}

gssize
_zed_pipe_output_stream_write (ZedPipeOutputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;
  guint msg_size;
  ZedPipeMessage * msg;
  kern_return_t ret;

  msg_size = (sizeof (ZedPipeMessage) + buffer_length + 3) & ~3;
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
    return 0;
  }
}

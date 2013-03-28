#include "zed-pipe.h"

#include <stdio.h>
#include <mach/mach.h>

typedef struct _ZedPipeBackend ZedPipeBackend;
typedef struct _ZedPipeMessage ZedPipeMessage;

struct _ZedPipeBackend
{
  mach_port_name_t rx_port;
  mach_port_name_t tx_port;
  gpointer rx_buffer;
  guint8 * rx_buffer_cur;
  guint rx_buffer_length;
};

struct _ZedPipeMessage
{
  mach_msg_header_t header;
  guint size;
  guint8 payload[0];
};

void
_zed_pipe_create_backend (ZedPipe * self)
{
  ZedPipeBackend * backend;
  int rx, tx, assigned;

  backend = g_slice_new (ZedPipeBackend);
  assigned = sscanf (zed_pipe_get_address (self), "pipe:rx=%d,tx=%d", &rx, &tx);
  g_assert_cmpint (assigned, ==, 2);
  backend->rx_port = rx;
  backend->tx_port = tx;
  backend->rx_buffer = NULL;
  backend->rx_buffer_cur = NULL;
  backend->rx_buffer_length = 0;

  self->_backend = backend;
}

void
_zed_pipe_destroy_backend (ZedPipe * self)
{
  ZedPipeBackend * backend = self->_backend;
  g_free (backend->rx_buffer);
  g_slice_free (ZedPipeBackend, self->_backend);
}

gssize
_zed_pipe_input_stream_read (ZedPipeInputStream * self, guint8 * buffer, int buffer_length, GCancellable * cancellable, GError ** error)
{
  ZedPipeBackend * backend = self->_backend;
  kern_return_t ret;
  gssize n;

  if (backend->rx_buffer == NULL)
  {
    gulong msg_size;
    ZedPipeMessage * msg;

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
    if (ret != 0)
      goto handle_error;

    backend->rx_buffer = msg;
    backend->rx_buffer_cur = msg->payload;
    backend->rx_buffer_length = msg->size;
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
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "mach_msg failed: %s (%d)", mach_error_string (ret), ret);
    return 0;
  }
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

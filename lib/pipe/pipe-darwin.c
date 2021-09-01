#include "pipe-glue.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <mach/mach.h>

#define CHECK_BOOTSTRAP_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto bootstrap_failure; \
  }
#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto mach_failure; \
  }
#define CHECK_BSD_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto bsd_failure; \
  }

typedef struct _FridaInitMessage FridaInitMessage;

struct _FridaInitMessage
{
  mach_msg_header_t header;
  mach_msg_trailer_t trailer;
};

typedef char frida_pipe_uuid_t[36 + 1];
#include "piped-client.c"

extern kern_return_t bootstrap_look_up (mach_port_t bootstrap_port, const char * service_name, mach_port_t * service_port);
extern const char *bootstrap_strerror (kern_return_t r);
extern int fileport_makeport (int fd, mach_port_t * port);
extern int fileport_makefd (mach_port_t port);
extern int64_t sandbox_extension_consume (const char * extension_token);
extern int sandbox_extension_release (int64_t extension_handle);

void
frida_pipe_transport_set_temp_directory (const gchar * path)
{
}

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  mach_port_t self_task;
  int status, sockets[2] = { -1, -1 };
  kern_return_t kr;
  const gchar * failed_operation;
  mach_port_t local_wrapper = MACH_PORT_NULL;
  mach_port_t remote_wrapper = MACH_PORT_NULL;
  mach_port_t local_rx = MACH_PORT_NULL;
  mach_port_t local_tx = MACH_PORT_NULL;
  mach_port_t remote_rx = MACH_PORT_NULL;
  mach_port_t remote_tx = MACH_PORT_NULL;
  mach_msg_type_name_t acquired_type;
  mach_msg_header_t init;

  self_task = mach_task_self ();

  status = socketpair (AF_UNIX, SOCK_STREAM, 0, sockets);
  CHECK_BSD_RESULT (status, ==, 0, "socketpair");

  status = fileport_makeport (sockets[0], &local_wrapper);
  CHECK_BSD_RESULT (status, ==, 0, "fileport_makeport local");

  status = fileport_makeport (sockets[1], &remote_wrapper);
  CHECK_BSD_RESULT (status, ==, 0, "fileport_makeport remote");

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate local_rx");

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate remote_rx");

  kr = mach_port_extract_right (self_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &remote_tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right remote_tx");

  kr = mach_port_extract_right (self_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &local_tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right local_tx");

  init.msgh_size = sizeof (init);
  init.msgh_reserved = 0;
  init.msgh_id = 3;

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_remote_port = local_tx;
  init.msgh_local_port = local_wrapper;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send local_tx");
  local_tx = MACH_PORT_NULL;
  local_wrapper = MACH_PORT_NULL;

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_remote_port = remote_tx;
  init.msgh_local_port = remote_wrapper;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send remote_tx");
  remote_tx = MACH_PORT_NULL;
  remote_wrapper = MACH_PORT_NULL;

  *local_address = g_strdup_printf ("pipe:port=0x%x", local_rx);
  *remote_address = g_strdup_printf ("pipe:port=0x%x", remote_rx);
  local_rx = MACH_PORT_NULL;
  remote_rx = MACH_PORT_NULL;

  goto beach;

mach_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while setting up mach ports (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    goto beach;
  }
bsd_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while setting up mach ports (%s returned '%s')",
        failed_operation, strerror (errno));
    goto beach;
  }
beach:
  {
    guint i;

    if (remote_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_tx);
    if (local_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_tx);

    if (remote_rx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
    if (local_rx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    if (remote_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_wrapper);
    if (local_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_wrapper);

    for (i = 0; i != G_N_ELEMENTS (sockets); i++)
    {
      int fd = sockets[i];
      if (fd != -1)
        close (fd);
    }

    return NULL;
  }
}

void
_frida_pipe_transport_destroy_backend (void * backend)
{
}

gint
_frida_unix_pipe_consume_stashed_file_descriptor (mach_port_t port, GError ** error)
{
  gint fd = -1;
  FridaInitMessage init = { { 0, }, { 0, } };
  kern_return_t kr;
  const gchar * failed_operation;
  mach_port_t wrapper;

  kr = mach_msg (&init.header, MACH_RCV_MSG, 0, sizeof (init), port, 1, MACH_PORT_NULL);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg");
  wrapper = init.header.msgh_remote_port;

  fd = fileport_makefd (wrapper);
  CHECK_BSD_RESULT (fd, !=, -1, "fileport_makefd");

  goto beach;

mach_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while setting up pipe (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    goto beach;
  }
bsd_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while setting up pipe (%s returned '%s')",
        failed_operation, strerror (errno));
    goto beach;
  }
beach:
  {
    mach_msg_destroy (&init.header);

    mach_port_mod_refs (mach_task_self (), port, MACH_PORT_RIGHT_RECEIVE, -1);

    return fd;
  }
}

gint
_frida_unix_pipe_fetch_file_descriptor_from_service (const gchar * service, const gchar * uuid, const gchar * token, GError ** error)
{
  gint fd = -1;
  int64_t extension_handle = -1;
  kern_return_t kr;
  const gchar * failed_operation;
  mach_port_t server = MACH_PORT_NULL;
  frida_pipe_uuid_t uuid_buf;
  mach_port_t wrapper = MACH_PORT_NULL;

  if (token != NULL)
    extension_handle = sandbox_extension_consume (token);

  kr = bootstrap_look_up (bootstrap_port, service, &server);
  CHECK_BOOTSTRAP_RESULT (kr, ==, KERN_SUCCESS, "bootstrap_look_up");

  g_strlcpy (uuid_buf, uuid, sizeof (uuid_buf));

  kr = frida_piped_fetch_file_descriptor (server, uuid_buf, &wrapper);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "fetch_file_descriptor");

  fd = fileport_makefd (wrapper);
  CHECK_BSD_RESULT (fd, !=, -1, "fileport_makefd");

  goto beach;

bootstrap_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to fetch file descriptor from %s (%s returned '%s')",
        service, failed_operation, bootstrap_strerror (kr));
    goto beach;
  }
mach_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to fetch file descriptor from %s (%s returned '%s')",
        service, failed_operation, mach_error_string (kr));
    goto beach;
  }
bsd_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to fetch file descriptor from %s (%s returned '%s')",
        service, failed_operation, strerror (errno));
    goto beach;
  }
beach:
  {
    if (wrapper != MACH_PORT_NULL)
      mach_port_deallocate (mach_task_self (), wrapper);

    if (server != MACH_PORT_NULL)
      mach_port_deallocate (mach_task_self (), server);

    if (extension_handle != -1)
      sandbox_extension_release (extension_handle);

    return fd;
  }
}

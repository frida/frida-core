#include "frida-helper-backend.h"

#include <errno.h>
#include <mach/mach.h>
#include <sys/socket.h>

#define BOOTSTRAP_MAX_NAME_LEN 128

typedef struct _FridaHandshakeMessageOut FridaHandshakeMessageOut;
typedef struct _FridaHandshakeMessageIn FridaHandshakeMessageIn;

struct _FridaHandshakeMessageOut
{
  mach_msg_base_t base;
  mach_msg_port_descriptor_t task;
  mach_msg_port_descriptor_t socket;
};

struct _FridaHandshakeMessageIn
{
  mach_msg_base_t base;
  mach_msg_port_descriptor_t task;
  mach_msg_port_descriptor_t socket;
  mach_msg_audit_trailer_t trailer;
};

static pid_t frida_audit_token_to_pid (audit_token_t atoken);

typedef char name_t[BOOTSTRAP_MAX_NAME_LEN];

extern kern_return_t bootstrap_register2 (mach_port_t bp, const name_t service_name, mach_port_t sp, uint64_t flags);
extern kern_return_t bootstrap_look_up2 (mach_port_t bp, const name_t service_name, mach_port_t * sp, pid_t target_pid, uint64_t flags);

#ifdef HAVE_MACOS
extern pid_t audit_token_to_pid (audit_token_t atoken);
#endif

extern int fileport_makeport (int fd, mach_port_t * port);
extern int fileport_makefd (mach_port_t port);

guint
_frida_handshake_port_create_local (FridaHandshakePort * self, const gchar * name, GError ** error)
{
  mach_port_t self_task, bootstrap, local_rx;
  kern_return_t kr;

  self_task = mach_task_self ();

  task_get_bootstrap_port (self_task, &bootstrap);

  mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);

  kr = bootstrap_register2 (bootstrap, name, local_rx, 0);
  if (kr != KERN_SUCCESS)
    goto register_failed;

  return local_rx;

register_failed:
  {
    mach_port_mod_refs (self_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to register port \"%s\": %s",
        name, mach_error_string (kr));
    return 0;
  }
}

guint
_frida_handshake_port_create_remote (FridaHandshakePort * self, const gchar * name, GError ** error)
{
  mach_port_t bootstrap, local_tx;
  kern_return_t kr;

  task_get_bootstrap_port (mach_task_self (), &bootstrap);

  kr = bootstrap_look_up2 (bootstrap, name, &local_tx, 0, 0);
  if (kr != KERN_SUCCESS)
    goto lookup_failed;

  return local_tx;

lookup_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to lookup port \"%s\": %s",
        name, mach_error_string (kr));
    return 0;
  }
}

void
_frida_handshake_port_deallocate (FridaHandshakePort * self)
{
  if (self->mach_port == MACH_PORT_NULL)
    return;

  if (self->is_sender)
    mach_port_deallocate (mach_task_self (), self->mach_port);
  else
    mach_port_mod_refs (mach_task_self (), self->mach_port, MACH_PORT_RIGHT_RECEIVE, -1);
}

void
_frida_handshake_port_perform_exchange_as_sender (FridaHandshakePort * self, guint * task_port, gint * fd, GError ** error)
{
  mach_port_t self_task, local_rx;
  FridaHandshakeMessageOut msg_out;
  FridaHandshakeMessageIn msg_in;
  mach_msg_header_t * header_out, * header_in;
  int sockets[2] = { -1, -1 };
  mach_port_t remote_wrapper;
  kern_return_t kr;

  self_task = mach_task_self ();

  mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);

  bzero (&msg_out, sizeof (msg_out));
  bzero (&msg_in, sizeof (msg_in));
  header_out = &msg_out.base.header;
  header_in = &msg_in.base.header;

  header_out->msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND) | MACH_MSGH_BITS_COMPLEX;
  header_out->msgh_size = sizeof (msg_out);
  header_out->msgh_remote_port = self->mach_port;
  header_out->msgh_local_port = local_rx;
  header_out->msgh_reserved = 0;
  header_out->msgh_id = 1;

  msg_out.base.body.msgh_descriptor_count = 2;

  msg_out.task.name = self_task;
  msg_out.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  msg_out.task.type = MACH_MSG_PORT_DESCRIPTOR;

  socketpair (AF_UNIX, SOCK_STREAM, 0, sockets);

  fileport_makeport (sockets[1], &remote_wrapper);

  msg_out.socket.name = remote_wrapper;
  msg_out.socket.disposition = MACH_MSG_TYPE_MOVE_SEND;
  msg_out.socket.type = MACH_MSG_PORT_DESCRIPTOR;

  kr = mach_msg_send (header_out);
  if (kr != KERN_SUCCESS)
    goto mach_failure;

  remote_wrapper = MACH_PORT_NULL;

  header_in->msgh_size = sizeof (msg_in);
  header_in->msgh_local_port = local_rx;

  kr = mach_msg_receive (header_in);
  if (kr != KERN_SUCCESS)
    goto mach_failure;

  *task_port = msg_in.task.name;
  msg_in.task.name = MACH_PORT_NULL;

  *fd = sockets[0];
  sockets[0] = -1;

  goto beach;

mach_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_TRANSPORT,
        "Unable to perform handshake: %s",
        mach_error_string (kr));
    goto beach;
  }
beach:
  {
    guint i;

    mach_msg_destroy (header_in);

    if (remote_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_wrapper);

    for (i = 0; i != G_N_ELEMENTS (sockets); i++)
    {
      int fd = sockets[i];
      if (fd != -1)
        close (fd);
    }

    mach_port_mod_refs (self_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    return;
  }
}

void
_frida_handshake_port_perform_exchange_as_receiver (FridaHandshakePort * self, guint peer_pid, guint * task_port, gint * fd, GError ** error)
{
  mach_port_t self_task, local_rx;
  FridaHandshakeMessageIn msg_in;
  FridaHandshakeMessageOut msg_out;
  mach_msg_header_t * header_in, * header_out;
  const mach_msg_timeout_t poll_interval_msec = 10;
  kern_return_t kr;

  self_task = mach_task_self ();

  mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);

  bzero (&msg_in, sizeof (msg_in));
  bzero (&msg_out, sizeof (msg_out));
  header_in = &msg_in.base.header;
  header_out = &msg_out.base.header;

  do
  {
    kr = mach_msg (header_in,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_TYPE (MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS (MACH_RCV_TRAILER_AUDIT),
        0,
        sizeof (msg_in),
        self->mach_port,
        poll_interval_msec,
        MACH_PORT_NULL);
    if (kr != KERN_SUCCESS && kill (peer_pid, 0) == -1 && errno == ESRCH)
      goto process_died;
  }
  while (kr == MACH_RCV_TIMED_OUT);
  if (kr != KERN_SUCCESS)
    goto mach_failure;

  if (header_in->msgh_size != sizeof (FridaHandshakeMessageOut))
    goto handshake_failed;
  if (frida_audit_token_to_pid (msg_in.trailer.msgh_audit) != peer_pid)
    goto handshake_failed;

  header_out->msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND) | MACH_MSGH_BITS_COMPLEX;
  header_out->msgh_size = sizeof (msg_out);
  header_out->msgh_remote_port = header_in->msgh_remote_port;
  header_out->msgh_local_port = local_rx;
  header_out->msgh_reserved = 0;
  header_out->msgh_id = 1;

  msg_out.base.body.msgh_descriptor_count = 1;

  msg_out.task.name = self_task;
  msg_out.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  msg_out.task.type = MACH_MSG_PORT_DESCRIPTOR;

  kr = mach_msg_send (header_out);
  if (kr != KERN_SUCCESS)
    goto mach_failure;

  *task_port = msg_in.task.name;
  msg_in.task.name = MACH_PORT_NULL;

  *fd = fileport_makefd (msg_in.socket.name);

  goto beach;

process_died:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PROCESS_NOT_FOUND,
        "Peer process died unexpectedly");
    goto beach;
  }
handshake_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_TRANSPORT,
        "Unable to perform handshake due to an unexpected message");
    goto beach;
  }
mach_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_TRANSPORT,
        "Unable to perform handshake: %s",
        mach_error_string (kr));
    goto beach;
  }
beach:
  {
    mach_msg_destroy (header_in);

    mach_port_mod_refs (self_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    return;
  }
}

void
_frida_task_port_deallocate (FridaTaskPort * self)
{
  mach_port_deallocate (mach_task_self (), frida_task_port_get_mach_port (self));
}

static pid_t
frida_audit_token_to_pid (audit_token_t atoken)
{
#ifdef HAVE_MACOS
  return audit_token_to_pid (atoken);
#else
  return atoken.val[5];
#endif
}

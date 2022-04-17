typedef struct _FridaPipeWorker FridaPipeWorker;
typedef struct _FridaPipeDevice FridaPipeDevice;
typedef struct _FridaPipeHandle FridaPipeHandle;
#define RESMGR_HANDLE_T FridaPipeDevice
#define IOFUNC_ATTR_T FridaPipeDevice
#define IOFUNC_OCB_T FridaPipeHandle

#include "pipe-glue.h"

#include <devctl.h>
#include <fcntl.h>
#include <share.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <sys/netmgr.h>
#include <sys/un.h>

#define FRIDA_PIPE_SESSION_ID_LENGTH 36

#define FRIDA_DEVCTL_GETSOCKNAME __DIOF (_DCMD_IP, 0x00, struct sockaddr)
#define FRIDA_DEVCTL_GETPEERNAME __DIOF (_DCMD_IP, 0x02, struct sockaddr)

typedef struct _FridaIOConnectRequest FridaIOConnectRequest;
typedef struct _FridaIOConnectReply FridaIOConnectReply;
typedef struct _FridaRecvfromRequest FridaRecvfromRequest;
typedef struct _FridaRecvfromReply FridaRecvfromReply;
typedef struct _FridaRecvmsgRequest FridaRecvmsgRequest;
typedef struct _FridaRecvmsgReply FridaRecvmsgReply;
typedef struct _FridaRecvmsg2Request FridaRecvmsg2Request;
typedef struct _FridaRecvmsg2Reply FridaRecvmsg2Reply;
typedef struct _FridaSendtoRequest FridaSendtoRequest;
typedef struct _FridaSendmsgRequest FridaSendmsgRequest;
typedef struct _FridaGetSockNameReply FridaGetSockNameReply;
typedef struct _FridaGetSockOptRequest FridaGetSockOptRequest;

struct _FridaPipeWorker
{
  GMutex mutex;
  gboolean stopping;
  GHashTable * sessions;
  int channel_id;
  dispatch_t * dispatch_iface;
  resmgr_context_t * dispatch_ctx;
  resmgr_attr_t resmgr_attr;
  int link_id;
  resmgr_connect_funcs_t connect_funcs;
  resmgr_io_funcs_t io_funcs;
  FridaPipeDevice * device;
  GThread * thread;
};

struct _FridaPipeDevice
{
  iofunc_attr_t attr;
  FridaPipeWorker * worker;
};

struct _FridaPipeHandle
{
  iofunc_ocb_t ocb;
  FridaQnxPipeSession * session;
  iofunc_notify_t notify[3];
};

struct _FridaIOConnectRequest
{
  struct _io_connect msg;
  char session_id[FRIDA_PIPE_SESSION_ID_LENGTH];
};

struct _FridaIOConnectReply
{
  struct _io_connect_link_reply reply;
  struct _io_connect_entry entry;
  char path[PATH_MAX + 1];
};

struct _FridaRecvfromRequest
{
  struct _io_read io;
  uint16_t flags;
  uint16_t from_len;
};

struct _FridaRecvfromReply
{
  uint16_t from_len;
};

struct _FridaRecvmsgRequest
{
  struct _io_read io;
  uint32_t flags;
  uint32_t name_len;
  uint32_t control_len;
};

struct _FridaRecvmsgReply
{
  uint32_t name_len;
  uint32_t control_len;
};

struct _FridaRecvmsg2Request
{
  struct _io_read io;
  uint32_t flags;
  uint32_t name_len;
  uint32_t control_len;
  uint32_t unknown;
};

struct _FridaRecvmsg2Reply
{
  uint32_t flags;
  uint32_t name_len;
  uint32_t control_len_processed;
  uint32_t control_len_full;
  uint32_t unknown;
};

struct _FridaSendtoRequest
{
  struct _io_write io;
  uint16_t flags;
  uint16_t to_len;
};

struct _FridaSendmsgRequest
{
  struct _io_write io;
  uint16_t unknown;
  uint16_t flags;
  uint16_t name_len;
  uint16_t control_len;
};

struct _FridaGetSockNameReply
{
  struct _io_devctl_reply io;
  struct sockaddr_un addr;
};

struct _FridaGetSockOptRequest
{
  struct _io_msg io;
  int32_t level;
  int32_t optname;
  uint32_t optlen;
  uint32_t unknown;
};

static FridaPipeWorker * frida_pipe_worker_new (void);
static void frida_pipe_worker_free (FridaPipeWorker * worker);
static gpointer frida_pipe_worker_process_messages (FridaPipeWorker * self);
static int frida_pipe_device_on_open (resmgr_context_t * ctp, io_open_t * msg, FridaPipeDevice * device, void * extra);
static FridaPipeHandle * frida_pipe_handle_new (resmgr_context_t * ctp, FridaPipeDevice * device);
static void frida_pipe_handle_free (FridaPipeHandle * handle);
static int frida_pipe_handle_on_read (resmgr_context_t * ctp, io_read_t * msg, FridaPipeHandle * handle);
static int frida_pipe_handle_on_write (resmgr_context_t * ctp, io_write_t * msg, FridaPipeHandle * handle);
static int frida_pipe_handle_on_close_ocb (resmgr_context_t * ctp, void * reserved, FridaPipeHandle * handle);
static int frida_pipe_handle_on_notify (resmgr_context_t * ctp, io_notify_t * msg, FridaPipeHandle * handle);
static int frida_pipe_handle_on_devctl (resmgr_context_t * ctp, io_devctl_t * msg, FridaPipeHandle * handle);
static int frida_pipe_handle_on_msg (resmgr_context_t * ctp, io_msg_t * msg, FridaPipeHandle * handle);

G_LOCK_DEFINE_STATIC (frida_worker);
static FridaPipeWorker * frida_worker = NULL;

static iofunc_funcs_t frida_pipe_ocb_funcs = {
  _IOFUNC_NFUNCS,
  frida_pipe_handle_new,
  frida_pipe_handle_free
};

static iofunc_mount_t frida_pipe_mountpoint = {
  .funcs = &frida_pipe_ocb_funcs,
};

void
frida_pipe_transport_set_temp_directory (const gchar * path)
{
}

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  gchar * session_id;

  G_LOCK (frida_worker);

  if (frida_worker == NULL)
    frida_worker = frida_pipe_worker_new ();

  session_id = g_uuid_string_random ();
  g_hash_table_replace (frida_worker->sessions, session_id, frida_qnx_pipe_session_new ());

  *local_address = g_strdup_printf ("pipe:pid=%u,chid=%d,lnid=%d,sid=%s",
      getpid (),
      frida_worker->channel_id,
      frida_worker->link_id,
      session_id);
  *remote_address = g_strdup (*local_address);

  G_UNLOCK (frida_worker);

  return session_id;
}

void
_frida_pipe_transport_destroy_backend (void * opaque_backend)
{
  const gchar * session_id = opaque_backend;

  G_LOCK (frida_worker);

  g_hash_table_remove (frida_worker->sessions, session_id);
  if (g_hash_table_size (frida_worker->sessions) == 0)
  {
    frida_pipe_worker_free (frida_worker);
    frida_worker = NULL;
  }

  G_UNLOCK (frida_worker);
}

static FridaPipeWorker *
frida_pipe_worker_new (void)
{
  FridaPipeWorker * worker;
  resmgr_attr_t * resmgr_attr;
  FridaPipeDevice * device;
  iofunc_attr_t * io_attr;

  worker = g_slice_new0 (FridaPipeWorker);

  g_mutex_init (&worker->mutex);
  worker->stopping = FALSE;
  worker->sessions = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

  worker->channel_id = ChannelCreate_r (_NTO_CHF_UNBLOCK | _NTO_CHF_DISCONNECT);

  worker->dispatch_iface = dispatch_create_channel (worker->channel_id, 0);

  resmgr_attr = &worker->resmgr_attr;
  resmgr_attr->flags = RESMGR_FLAG_ATTACH_LOCAL;
  resmgr_attr->nparts_max = 1;
  resmgr_attr->msg_max_size = 2048;

  iofunc_func_init (
      _RESMGR_CONNECT_NFUNCS, &worker->connect_funcs,
      _RESMGR_IO_NFUNCS, &worker->io_funcs);
  worker->connect_funcs.open = frida_pipe_device_on_open;
  worker->io_funcs.read = frida_pipe_handle_on_read;
  worker->io_funcs.write = frida_pipe_handle_on_write;
  worker->io_funcs.close_ocb = frida_pipe_handle_on_close_ocb;
  worker->io_funcs.notify = frida_pipe_handle_on_notify;
  worker->io_funcs.devctl = frida_pipe_handle_on_devctl;
  worker->io_funcs.msg = frida_pipe_handle_on_msg;

  device = g_slice_new (FridaPipeDevice);
  worker->device = device;
  io_attr = &device->attr;
  iofunc_attr_init (io_attr, S_IFSOCK, NULL, NULL);
  io_attr->mount = &frida_pipe_mountpoint;
  io_attr->nbytes = 2048;
  device->worker = worker;

  worker->link_id = resmgr_attach (
      worker->dispatch_iface,
      resmgr_attr,
      NULL,
      _FTYPE_SOCKET,
      0,
      &worker->connect_funcs,
      &worker->io_funcs,
      device);
  g_assert (worker->link_id != -1);

  worker->dispatch_ctx = resmgr_context_alloc (worker->dispatch_iface);

  worker->thread = g_thread_new ("frida-pipe-worker", (GThreadFunc) frida_pipe_worker_process_messages, worker);

  return worker;
}

static void
frida_pipe_worker_free (FridaPipeWorker * worker)
{
  g_mutex_lock (&worker->mutex);

  resmgr_detach (worker->dispatch_iface, worker->link_id, _RESMGR_DETACH_CLOSE);

  worker->stopping = TRUE;
  g_hash_table_unref (worker->sessions);

  ChannelDestroy_r (worker->channel_id);

  g_mutex_unlock (&worker->mutex);

  g_thread_join (worker->thread);

  resmgr_context_free (worker->dispatch_ctx);
  g_slice_free (FridaPipeDevice, worker->device);
  dispatch_destroy (worker->dispatch_iface);

  g_mutex_clear (&worker->mutex);

  g_slice_free (FridaPipeWorker, worker);
}

static gpointer
frida_pipe_worker_process_messages (FridaPipeWorker * self)
{
  resmgr_context_t * ctp = self->dispatch_ctx;

  while (TRUE)
  {
    if ((ctp = resmgr_block (self->dispatch_ctx)) == NULL)
      return NULL;

    g_mutex_lock (&self->mutex);

    self->dispatch_ctx = ctp;

    if (self->stopping)
      goto stopping;

    resmgr_handler (ctp);

    g_mutex_unlock (&self->mutex);
  }

  return NULL;

stopping:
  {
    g_mutex_unlock (&self->mutex);

    return NULL;
  }
}

static int
frida_pipe_device_on_open (resmgr_context_t * ctp, io_open_t * msg, FridaPipeDevice * device, void * extra)
{
  FridaQnxPipeSession * session;
  int status;
  FridaPipeHandle * handle;

  session = g_hash_table_lookup (device->worker->sessions, msg->connect.path);
  if (session == NULL)
    return ENOENT;

  if (frida_qnx_pipe_session_has_both_endpoints (session))
    return EBUSY;

  if ((status = iofunc_open_default (ctp, msg, &device->attr, extra)) != EOK)
    return status;

  handle = resmgr_ocb (ctp);
  handle->session = session;

  frida_qnx_pipe_session_add (session, handle);

  return EOK;
}

static FridaPipeHandle *
frida_pipe_handle_new (resmgr_context_t * ctp, FridaPipeDevice * device)
{
  FridaPipeHandle * handle;

  handle = g_slice_new0 (FridaPipeHandle);
  IOFUNC_NOTIFY_INIT (handle->notify);

  return handle;
}

static void
frida_pipe_handle_free (FridaPipeHandle * handle)
{
  g_slice_free (FridaPipeHandle, handle);
}

static int
frida_pipe_handle_on_read (resmgr_context_t * ctp, io_read_t * msg, FridaPipeHandle * handle)
{
  const struct _io_read * io = &msg->i;
  FridaPipeDevice * device = handle->ocb.attr;
  int status;
  guint8 * data;
  gint data_len;
  FridaQnxPipeEndpointState state;

  if ((status = iofunc_read_verify (ctp, msg, &handle->ocb, NULL)) != EOK)
    return status;

  switch (io->xtype & _IO_XTYPE_MASK)
  {
    case _IO_XTYPE_TCPIP:
    {
      const FridaRecvfromRequest * r = (const FridaRecvfromRequest *) &msg->i;

      if (io->combine_len != sizeof (FridaRecvfromRequest) || ctp->info.srcmsglen != sizeof (FridaRecvfromRequest))
        return EINVAL;

      data = frida_qnx_pipe_session_read (handle->session, handle, io->nbytes, r->flags, &state, &data_len);
      if (data_len > 0)
      {
        FridaRecvfromReply reply = { 0, };
        iov_t riov[2];

        riov[0].iov_base = &reply;
        riov[0].iov_len = sizeof (reply);

        riov[1].iov_base = data;
        riov[1].iov_len = data_len;

        MsgReplyv_r (ctp->rcvid, data_len, riov, G_N_ELEMENTS (riov));
      }

      break;
    }
    case _IO_XTYPE_TCPIP_MSG:
    {
      const FridaRecvmsgRequest * r = (const FridaRecvmsgRequest *) &msg->i;

      if (io->combine_len != sizeof (FridaRecvmsgRequest) || ctp->info.srcmsglen != sizeof (FridaRecvmsgRequest))
        return EINVAL;

      data = frida_qnx_pipe_session_read (handle->session, handle, io->nbytes, r->flags, &state, &data_len);
      if (data_len > 0)
      {
        FridaRecvmsgReply reply = { 0, };
        iov_t riov[2];

        riov[0].iov_base = &reply;
        riov[0].iov_len = sizeof (reply);

        riov[1].iov_base = data;
        riov[1].iov_len = data_len;

        MsgReplyv_r (ctp->rcvid, data_len, riov, G_N_ELEMENTS (riov));
      }

      break;
    }
    case _IO_XTYPE_TCPIP_MSG2:
    {
      const FridaRecvmsg2Request * r = (const FridaRecvmsg2Request *) &msg->i;

      if (io->combine_len != sizeof (FridaRecvmsg2Request) || ctp->info.srcmsglen != sizeof (FridaRecvmsg2Request))
        return EINVAL;

      data = frida_qnx_pipe_session_read (handle->session, handle, io->nbytes, r->flags, &state, &data_len);
      if (data_len > 0)
      {
        FridaRecvmsg2Reply reply = { 0, };
        iov_t riov[2];

        riov[0].iov_base = &reply;
        riov[0].iov_len = sizeof (reply);

        riov[1].iov_base = data;
        riov[1].iov_len = data_len;

        MsgReplyv_r (ctp->rcvid, data_len, riov, G_N_ELEMENTS (riov));
      }

      break;
    }
    default:
      return ENOSYS;
  }

  g_free (data);

  device->attr.flags |= IOFUNC_ATTR_ATIME;

  if (data_len == 0 && state == FRIDA_QNX_PIPE_ENDPOINT_STATE_CLOSED)
  {
    _IO_SET_READ_NBYTES (ctp, 0);

    return EOK;
  }

  if (data_len == 0)
    return EWOULDBLOCK;

  _IO_SET_READ_NBYTES (ctp, data_len);

  return _RESMGR_NOREPLY;
}

static int
frida_pipe_handle_on_write (resmgr_context_t * ctp, io_write_t * msg, FridaPipeHandle * handle)
{
  const struct _io_write * io = &msg->i;
  FridaPipeDevice * device = handle->ocb.attr;
  int status;
  gsize metadata_len, payload_len;

  if ((status = iofunc_write_verify (ctp, msg, &handle->ocb, NULL)) != EOK)
    return status;

  switch (io->xtype & _IO_XTYPE_MASK)
  {
    case _IO_XTYPE_TCPIP:
    {
      if (io->combine_len != sizeof (FridaSendtoRequest))
        return EINVAL;

      metadata_len = sizeof (FridaSendtoRequest);

      break;
    }
    case _IO_XTYPE_TCPIP_MSG:
    {
      const FridaSendmsgRequest * r = (const FridaSendmsgRequest *) &msg->i;

      if (io->combine_len != sizeof (FridaSendmsgRequest))
        return EINVAL;

      metadata_len = sizeof (FridaSendmsgRequest) + r->name_len + r->control_len;

      break;
    }
    default:
      return ENOSYS;
  }

  payload_len = io->nbytes;
  if (payload_len > (gsize) ctp->info.srcmsglen - metadata_len)
    return EBADMSG;

  if (payload_len > 0)
  {
    guint8 * data;

    data = g_malloc (payload_len);
    resmgr_msgread (ctp, data, payload_len, metadata_len);

    frida_qnx_pipe_session_write (handle->session, handle, data, payload_len);

    device->attr.flags |= IOFUNC_ATTR_MTIME | IOFUNC_ATTR_CTIME;
  }

  _IO_SET_WRITE_NBYTES (ctp, payload_len);

  return EOK;
}

static int
frida_pipe_handle_on_close_ocb (resmgr_context_t * ctp, void * reserved, FridaPipeHandle * handle)
{
  frida_qnx_pipe_session_remove (handle->session, handle);

  return iofunc_close_ocb_default (ctp, reserved, &handle->ocb);
}

static int
frida_pipe_handle_on_notify (resmgr_context_t * ctp, io_notify_t * msg, FridaPipeHandle * handle)
{
  int trig;

  trig = _NOTIFY_COND_OUTPUT;
  if (frida_qnx_pipe_session_has_pending_data_for (handle->session, handle))
    trig |= _NOTIFY_COND_INPUT;

  return iofunc_notify (ctp, msg, handle->notify, trig, NULL, NULL);
}

static int
frida_pipe_handle_on_devctl (resmgr_context_t * ctp, io_devctl_t * msg, FridaPipeHandle * handle)
{
  const struct _io_devctl * ctl = &msg->i;
  int status;

  if ((status = iofunc_devctl_default (ctp, msg, &handle->ocb)) != _RESMGR_DEFAULT)
    return status;

  switch (ctl->dcmd)
  {
    case FRIDA_DEVCTL_GETSOCKNAME:
    case FRIDA_DEVCTL_GETPEERNAME:
    {
      FridaGetSockNameReply reply;
      struct _io_devctl_reply * io = &reply.io;
      struct sockaddr_un * addr = &reply.addr;

      bzero (&reply, sizeof (reply));

      io->ret_val = sizeof (reply.addr);
      io->nbytes = sizeof (reply.addr);

      addr->sun_len = sizeof (struct sockaddr_un);
      addr->sun_family = AF_LOCAL;
      strcpy (addr->sun_path, "/");

      MsgReply_r (ctp->rcvid, 0, &reply, sizeof (reply));

      return _RESMGR_NOREPLY;
    }
    default:
      return ENOSYS;
  }
}

static int
frida_pipe_handle_on_msg (resmgr_context_t * ctp, io_msg_t * msg, FridaPipeHandle * handle)
{
  FridaGetSockOptRequest req;
  const struct _io_msg * io = &req.io;
  gboolean is_getsockopt;

  if (MsgRead_r (ctp->rcvid, &req, sizeof (req), 0) != sizeof (req))
    return ENOSYS;

  is_getsockopt = io->mgrid == _IOMGR_TCPIP && io->subtype == 6 && io->combine_len == sizeof (req);
  if (!is_getsockopt)
    return ENOSYS;

  if (req.level == SOL_SOCKET && req.optname == SO_TYPE)
  {
    const int our_type = SOCK_STREAM;

    if (req.optlen != sizeof (int))
      return EINVAL;

    MsgReply_r (ctp->rcvid, 0, &our_type, sizeof (our_type));

    return _RESMGR_NOREPLY;
  }

  return ENOPROTOOPT;
}

void
frida_qnx_pipe_session_endpoint_notify (FridaQnxPipeSessionEndpoint * self)
{
  FridaPipeHandle * handle = self->handle;

  if (IOFUNC_NOTIFY_INPUT_CHECK (handle->notify, 1, 0))
    iofunc_notify_trigger (handle->notify, 1, IOFUNC_NOTIFY_INPUT);
}

gint
_frida_qnx_pipe_connect_to_channel (const gchar * address, GError ** error)
{
  gint fd, assigned;
  gchar session_id[FRIDA_PIPE_SESSION_ID_LENGTH + 1];
  pid_t process_id;
  int channel_id, link_id;
  FridaIOConnectRequest request;
  struct _io_connect * msg;
  FridaIOConnectReply reply;

  assigned = sscanf (address, "pipe:pid=%u,chid=%d,lnid=%d,sid=%" G_STRINGIFY (FRIDA_PIPE_SESSION_ID_LENGTH) "s",
      &process_id,
      &channel_id,
      &link_id,
      session_id);
  g_assert (assigned == 4);

  fd = ConnectAttach_r (ND_LOCAL_NODE, process_id, channel_id, 3, _NTO_COF_CLOEXEC);
  if (fd < 0)
    goto failure;

  msg = &request.msg;
  msg->type = _IO_CONNECT;
  msg->subtype = _IO_CONNECT_OPEN;
  msg->file_type = _FTYPE_SOCKET;
  msg->reply_max = sizeof (reply);
  msg->entry_max = 1;
  msg->key = 0;
  msg->handle = link_id;
  msg->ioflag = _IO_FLAG_RD | _IO_FLAG_WR | O_NONBLOCK;
  msg->mode = S_IFSOCK;
  msg->sflag = SH_DENYNO;
  msg->access = _IO_FLAG_RD | _IO_FLAG_WR;
  msg->path_len = 1 + 1;
  msg->eflag = 0;
  msg->extra_type = _IO_CONNECT_EXTRA_NONE;
  msg->extra_len = 0;
  strcpy (msg->path, session_id);
  if (MsgSend_r (fd, &request, sizeof (request), &reply, sizeof (reply)) != 0)
    goto failure;

  return fd;

failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to connect to channel");
    return -1;
  }
}

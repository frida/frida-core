#include "wait-handle-source.h"

#include <windows.h>

#define WIN_IPC_WAIT_HANDLE_SOURCE(s) ((WinIpcWaitHandleSource *) (s))

typedef struct _WinIpcWaitHandleSource WinIpcWaitHandleSource;

struct _WinIpcWaitHandleSource
{
  GSource source;

  HANDLE handle;
  GPollFD handle_poll_fd;
};

static gboolean win_ipc_wait_handle_source_prepare (GSource * source,
    gint * timeout);
static gboolean win_ipc_wait_handle_source_check (GSource * source);
static gboolean win_ipc_wait_handle_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data);

static GSourceFuncs win_ipc_wait_handle_source_funcs = {
  win_ipc_wait_handle_source_prepare,
  win_ipc_wait_handle_source_check,
  win_ipc_wait_handle_source_dispatch,
  NULL
};

GSource *
win_ipc_wait_handle_source_new (void * handle)
{
  GSource * source;
  GPollFD * pfd;

  source = g_source_new (&win_ipc_wait_handle_source_funcs,
      sizeof (WinIpcWaitHandleSource));
  WIN_IPC_WAIT_HANDLE_SOURCE (source)->handle = handle;

  pfd = &WIN_IPC_WAIT_HANDLE_SOURCE (source)->handle_poll_fd;
#if GLIB_SIZEOF_VOID_P == 8
  pfd->fd = (gint64) handle;
#else
  pfd->fd = (gint) handle;
#endif
  pfd->events = G_IO_IN | G_IO_OUT | G_IO_HUP | G_IO_ERR;
  pfd->revents = 0;
  g_source_add_poll (source, pfd);

  return source;
}

static gboolean
win_ipc_wait_handle_source_prepare (GSource * source, gint * timeout)
{
  WinIpcWaitHandleSource * self = WIN_IPC_WAIT_HANDLE_SOURCE (source);

  *timeout = -1;

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
win_ipc_wait_handle_source_check (GSource * source)
{
  WinIpcWaitHandleSource * self = WIN_IPC_WAIT_HANDLE_SOURCE (source);

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
win_ipc_wait_handle_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  WinIpcWaitHandleSource * self = WIN_IPC_WAIT_HANDLE_SOURCE (source);

  g_assert (WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0);

  return callback (user_data);
}

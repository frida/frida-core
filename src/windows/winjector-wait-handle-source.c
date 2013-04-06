#include "winjector-helper.h"

#include <windows.h>

#define WINJECTOR_WAIT_HANDLE_SOURCE(s) ((WinjectorWaitHandleSource *) (s))

typedef struct _WinjectorWaitHandleSource WinjectorWaitHandleSource;

struct _WinjectorWaitHandleSource
{
  GSource source;

  HANDLE handle;
  gboolean owns_handle;
  GPollFD handle_poll_fd;
};

static void winjector_wait_handle_source_finalize (GSource * source);

static gboolean winjector_wait_handle_source_prepare (GSource * source,
    gint * timeout);
static gboolean winjector_wait_handle_source_check (GSource * source);
static gboolean winjector_wait_handle_source_dispatch (GSource * source,
    GSourceFunc callback, gpointer user_data);

static GSourceFuncs winjector_wait_handle_source_funcs = {
  winjector_wait_handle_source_prepare,
  winjector_wait_handle_source_check,
  winjector_wait_handle_source_dispatch,
  winjector_wait_handle_source_finalize
};

GSource *
winjector_wait_handle_source_new (void * handle, gboolean owns_handle)
{
  GSource * source;
  GPollFD * pfd;
  WinjectorWaitHandleSource * whsrc;

  source = g_source_new (&winjector_wait_handle_source_funcs,
      sizeof (WinjectorWaitHandleSource));
  whsrc = WINJECTOR_WAIT_HANDLE_SOURCE (source);
  whsrc->handle = handle;
  whsrc->owns_handle = owns_handle;

  pfd = &WINJECTOR_WAIT_HANDLE_SOURCE (source)->handle_poll_fd;
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

static void
winjector_wait_handle_source_finalize (GSource * source)
{
  WinjectorWaitHandleSource * self = WINJECTOR_WAIT_HANDLE_SOURCE (source);

  if (self->owns_handle)
    CloseHandle (self->handle);
}

static gboolean
winjector_wait_handle_source_prepare (GSource * source, gint * timeout)
{
  WinjectorWaitHandleSource * self = WINJECTOR_WAIT_HANDLE_SOURCE (source);

  *timeout = -1;

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
winjector_wait_handle_source_check (GSource * source)
{
  WinjectorWaitHandleSource * self = WINJECTOR_WAIT_HANDLE_SOURCE (source);

  return WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0;
}

static gboolean
winjector_wait_handle_source_dispatch (GSource * source, GSourceFunc callback,
    gpointer user_data)
{
  WinjectorWaitHandleSource * self = WINJECTOR_WAIT_HANDLE_SOURCE (source);

  g_assert (WaitForSingleObject (self->handle, 0) == WAIT_OBJECT_0);

  return callback (user_data);
}

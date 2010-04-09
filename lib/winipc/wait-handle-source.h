#ifndef __WIN_IPC_WAIT_HANDLE_SOURCE_H__
#define __WIN_IPC_WAIT_HANDLE_SOURCE_H__

#include <glib.h>

GSource * win_ipc_wait_handle_source_new (void * handle);

#endif
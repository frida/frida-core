#ifndef __FRIDA_FORK_MONITOR_GLUE_H__
#define __FRIDA_FORK_MONITOR_GLUE_H__

#include <glib.h>

G_BEGIN_DECLS

gboolean _frida_fork_monitor_flags_create_process (gsize flags);
gboolean _frida_fork_monitor_syscall_creates_process (gssize number,
    gsize arg0, gsize arg1, gsize * flags);
gboolean _frida_fork_monitor_clone3_creates_process (void * args, gsize size,
    gsize * flags);

void _frida_fork_monitor_install_atfork (void);
void * _frida_fork_monitor_child_pack_new (void * fn, void * arg);
int _frida_fork_monitor_child_trampoline (void * data);

G_END_DECLS

#endif

#include "fork-monitor-glue.h"

#ifdef HAVE_LINUX
# include <stdint.h>
# include <string.h>
# include <sys/syscall.h>
# ifndef CLONE_VM
#  define CLONE_VM 0x00000100
# endif
#endif

#if defined (HAVE_LINUX) || defined (HAVE_DARWIN)
# include <pthread.h>
#endif

gboolean
_frida_fork_monitor_flags_create_process (gsize flags)
{
#ifdef HAVE_LINUX
  return (flags & CLONE_VM) == 0;
#else
  return FALSE;
#endif
}

gboolean
_frida_fork_monitor_syscall_creates_process (gssize number,
                                             gsize arg0,
                                             gsize arg1,
                                             gsize * flags)
{
  *flags = 0;

#ifdef HAVE_LINUX
# ifdef SYS_fork
  if (number == SYS_fork)
    return TRUE;
# endif
# ifdef SYS_vfork
  if (number == SYS_vfork)
    return TRUE;
# endif
# ifdef SYS_clone
  if (number == SYS_clone)
  {
    *flags = arg0;
    return (arg0 & CLONE_VM) == 0;
  }
# endif
# ifdef SYS_clone3
  if (number == SYS_clone3)
  {
    guint64 clone_flags = 0;
    const void * src;

    src = (const void *) arg0;
    if (src == NULL || arg1 < sizeof (clone_flags))
      return FALSE;

    memcpy (&clone_flags, src, sizeof (clone_flags));
    *flags = (gsize) clone_flags;
    return (clone_flags & CLONE_VM) == 0;
  }
# endif
#endif

  return FALSE;
}

gboolean
_frida_fork_monitor_clone3_creates_process (void * args,
                                            gsize size,
                                            gsize * flags)
{
#ifdef HAVE_LINUX
# ifdef SYS_clone3
  return _frida_fork_monitor_syscall_creates_process (SYS_clone3, (gsize) args,
      size, flags);
# endif
#endif
  *flags = 0;
  return FALSE;
}

#if defined (HAVE_LINUX) || defined (HAVE_DARWIN)

extern void _frida_fork_monitor_on_atfork_prepare (void);
extern void _frida_fork_monitor_on_atfork_parent (void);
extern void _frida_fork_monitor_on_atfork_child (void);
extern void _frida_fork_monitor_on_clone_fn_child (void);

static gboolean frida_atfork_installed = FALSE;

void
_frida_fork_monitor_install_atfork (void)
{
  if (frida_atfork_installed)
    return;

  pthread_atfork (_frida_fork_monitor_on_atfork_prepare,
      _frida_fork_monitor_on_atfork_parent,
      _frida_fork_monitor_on_atfork_child);
  frida_atfork_installed = TRUE;
}

typedef struct _FridaCloneChildPack FridaCloneChildPack;

struct _FridaCloneChildPack
{
  int (* fn) (void *);
  void * arg;
};

void *
_frida_fork_monitor_child_pack_new (void * fn,
                                    void * arg)
{
  FridaCloneChildPack * pack;

  pack = g_new (FridaCloneChildPack, 1);
  pack->fn = (int (*) (void *)) fn;
  pack->arg = arg;
  return pack;
}

int
_frida_fork_monitor_child_trampoline (void * data)
{
  FridaCloneChildPack pack;

  pack = *(FridaCloneChildPack *) data;
  g_free (data);

  _frida_fork_monitor_on_clone_fn_child ();

  if (pack.fn != NULL)
    return pack.fn (pack.arg);

  return 0;
}

#else

void
_frida_fork_monitor_install_atfork (void)
{
}

void *
_frida_fork_monitor_child_pack_new (void * fn,
                                    void * arg)
{
  return NULL;
}

int
_frida_fork_monitor_child_trampoline (void * data)
{
  return 0;
}

#endif

/*
 * TODO:
 * - Add authentication or restrict to root.
 * - Fix unload while /dev/frida is open.
 */

#include <kern/clock.h>
#include <kern/task.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSMalloc.h>
#include <mach/task.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <miscfs/devfs/devfs.h>

#define FRIDA_DEVICE_NAME "frida"
#define FRIDA_TAG_NAME "re.frida.Agent"
#define FRIDA_IOBASE 'R'

#define FRIDA_ENABLE_SPAWN_GATING  _IO   (FRIDA_IOBASE, 1)
#define FRIDA_DISABLE_SPAWN_GATING _IO   (FRIDA_IOBASE, 2)
#define FRIDA_RESUME               _IOW  (FRIDA_IOBASE, 3, pid_t)
#define FRIDA_TASK_FOR_PID         _IOWR (FRIDA_IOBASE, 4, mach_port_t)

#define FRIDA_LOCK() lck_mtx_lock (frida_lock)
#define FRIDA_UNLOCK() lck_mtx_unlock (frida_lock)

#ifndef POLLIN
# define POLLIN 0x0001
#endif
#ifndef POLLRDNORM
# define POLLRDNORM 0x0040
#endif

typedef struct _FridaSpawnEntry FridaSpawnEntry;
typedef struct _FridaSpawnNotification FridaSpawnNotification;
typedef struct _FridaPrivateApi FridaPrivateApi;
typedef struct _FridaMachODetails FridaMachODetails;

struct _FridaSpawnEntry
{
  pid_t pid;
  task_t task;
  char executable_path[MAXPATHLEN];
  uint64_t deadline;

  STAILQ_ENTRY (_FridaSpawnEntry) entries;
};

struct _FridaSpawnNotification
{
  char data[11 + 1 + MAXPATHLEN + 1 + 9 + 1 + 1];
  uint16_t offset;
  uint16_t length;

  STAILQ_ENTRY (_FridaSpawnNotification) notifications;
};

struct _FridaPrivateApi
{
  kern_return_t (* task_pidsuspend) (task_t task);
  kern_return_t (* task_pidresume) (task_t task);
  ipc_port_t (* convert_task_to_port) (task_t task);
  boolean_t (* is_corpsetask) (task_t task);
  ipc_space_t (* get_task_ipcspace) (task_t task);

  void (* thread_set_thread_name) (thread_t th, const char * name);
  kern_return_t (* thread_policy_get) (thread_t thread,
      thread_policy_flavor_t flavor, thread_policy_t policy_info,
      mach_msg_type_number_t * count, boolean_t * get_default);

  mach_port_name_t (* ipc_port_copyout_send) (ipc_port_t send_right,
      ipc_space_t space);
  void (* ipc_port_release_send) (ipc_port_t port);

  task_t (* proc_task) (proc_t proc);
  int (* proc_pidpathinfo_internal) (proc_t proc, uint64_t arg, char * buf,
      uint32_t buffer_size, int32_t * retval);

  void (** dtrace_proc_waitfor_exec_ptr) (proc_t proc);

  int (* cdevsw_setkqueueok) (int maj, struct cdevsw * csw, int extra_flags);
};

struct _FridaMachODetails
{
  const struct mach_header_64 * header;
  const void * linkedit;
  const struct symtab_command * symtab;
};

kern_return_t frida_kernel_agent_start (kmod_info_t * ki, void * d);
kern_return_t frida_kernel_agent_stop (kmod_info_t * ki, void * d);
static void frida_kernel_agent_start_watchdog (void);
static void frida_kernel_agent_stop_watchdog (void);
static void frida_kernel_agent_watchdog (void * parameter,
    wait_result_t wait_result);

static int frida_device_open (dev_t dev, int flags, int devtype,
    struct proc * p);
static int frida_device_close (dev_t dev, int flags, int devtype,
    struct proc * p);
static int frida_device_read (dev_t dev, struct uio * uio, int ioflag);
static int frida_device_ioctl (dev_t dev, u_long cmd, caddr_t data, int fflag,
    struct proc * p);
static int frida_device_select (dev_t dev, int which, void * wql,
    struct proc * p);

static void frida_on_exec (proc_t proc);

static void frida_clear_pending (void);

static void frida_clear_notifications (void);
static void frida_emit_notification (const FridaSpawnEntry * entry);

static FridaSpawnEntry * frida_spawn_entry_alloc (void);
static void frida_spawn_entry_free (FridaSpawnEntry * self);
static void frida_spawn_entry_resume (FridaSpawnEntry * self);

static FridaSpawnNotification * frida_spawn_notification_alloc (void);
static void frida_spawn_notification_free (FridaSpawnNotification * self);

static bool frida_try_enable_exec_hook (void);
static void frida_disable_exec_hook (void);
static void frida_enable_spawn_gating (void);
static void frida_disable_spawn_gating (void);
static void frida_disable_spawn_gating_unlocked (void);
static int frida_resume (pid_t pid);
static int frida_task_for_pid (pid_t pid, mach_port_name_t * port);

static bool frida_find_private_api (FridaPrivateApi * api);
static void frida_find_kernel_mach_o_details (FridaMachODetails * details);
static const struct mach_header_64 * frida_find_kernel_header (void);

static struct cdevsw frida_device =
{
  .d_open = frida_device_open,
  .d_close = frida_device_close,
  .d_read = frida_device_read,
  .d_write = eno_rdwrt,
  .d_ioctl = frida_device_ioctl,
  .d_stop = eno_stop,
  .d_reset = eno_reset,
  .d_ttys = NULL,
  .d_select = frida_device_select,
  .d_mmap = eno_mmap,
  .d_strategy = eno_strat,
  .d_reserved_1 = eno_getc,
  .d_reserved_2 = eno_putc,
  .d_type = 0
};

static bool frida_is_stopping = false;
static int frida_num_operations = 0;
static bool frida_is_open = false;
static bool frida_is_gating = false;
static bool frida_is_nonblocking = false;
static struct selinfo * frida_selinfo = NULL;
static void * frida_selinfo_storage[512];
static STAILQ_HEAD (, _FridaSpawnEntry) frida_pending =
    STAILQ_HEAD_INITIALIZER (frida_pending);
static STAILQ_HEAD (, _FridaSpawnNotification) frida_notifications =
    STAILQ_HEAD_INITIALIZER (frida_notifications);
static int frida_notifications_length = 0;

static thread_t frida_watchdog_thread;

static FridaPrivateApi frida_private_api;

static int frida_device_major;
static void * frida_device_node;

static lck_grp_t * frida_lock_group;
static lck_grp_attr_t * frida_lock_group_attr;

static lck_mtx_t * frida_lock;
static lck_attr_t * frida_lock_attr;

static OSMallocTag frida_tag;

kern_return_t
frida_kernel_agent_start (kmod_info_t * ki,
                          void * d)
{
  dev_t dev;

  if (!frida_find_private_api (&frida_private_api))
    return KERN_FAILURE;

  frida_lock_group_attr = lck_grp_attr_alloc_init ();
  frida_lock_group = lck_grp_alloc_init ("frida", frida_lock_group_attr);

  frida_lock_attr = lck_attr_alloc_init ();
  frida_lock = lck_mtx_alloc_init (frida_lock_group, frida_lock_attr);

  frida_tag = OSMalloc_Tagalloc (FRIDA_TAG_NAME, OSMT_DEFAULT);

  frida_device_major = cdevsw_add (-1, &frida_device);
  frida_private_api.cdevsw_setkqueueok (frida_device_major, &frida_device, 0);
  dev = makedev (frida_device_major, 0);
  frida_device_node = devfs_make_node (dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL,
      0666, FRIDA_DEVICE_NAME);

  frida_kernel_agent_start_watchdog ();

  return KERN_SUCCESS;
}

kern_return_t
frida_kernel_agent_stop (kmod_info_t * ki,
                         void * d)
{
  FRIDA_LOCK ();
  frida_is_stopping = true;
  frida_disable_exec_hook ();
  wakeup_one ((caddr_t) &frida_is_stopping);
  FRIDA_UNLOCK ();

  frida_kernel_agent_stop_watchdog ();

  devfs_remove (frida_device_node);
  cdevsw_remove (frida_device_major, &frida_device);

  frida_disable_spawn_gating ();

  FRIDA_LOCK ();

  frida_is_open = false;

  while (frida_num_operations > 0)
  {
    if (frida_selinfo != NULL)
    {
      selwakeup (frida_selinfo);
      frida_selinfo = NULL;
    }
    wakeup_one ((caddr_t) &frida_notifications_length);

    FRIDA_UNLOCK ();
    FRIDA_LOCK ();
  }

  frida_clear_pending ();
  frida_clear_notifications ();

  FRIDA_UNLOCK ();

  OSMalloc_Tagfree (frida_tag);

  lck_mtx_destroy (frida_lock, frida_lock_group);
  lck_attr_free (frida_lock_attr);

  lck_grp_free (frida_lock_group);
  lck_grp_attr_free (frida_lock_group_attr);

  return KERN_SUCCESS;
}

static void
frida_kernel_agent_start_watchdog (void)
{
  kernel_thread_start (frida_kernel_agent_watchdog, NULL,
      &frida_watchdog_thread);
  frida_private_api.thread_set_thread_name (frida_watchdog_thread,
      "FridaWatchdogThread");
}

static void
frida_kernel_agent_stop_watchdog (void)
{
  kern_return_t kr;

  do
  {
    thread_affinity_policy_data_t policy;
    mach_msg_type_number_t count;
    boolean_t get_default;

    count = THREAD_AFFINITY_POLICY_COUNT;
    get_default = FALSE;

    kr = frida_private_api.thread_policy_get (frida_watchdog_thread,
        THREAD_AFFINITY_POLICY, (thread_policy_t) &policy, &count,
        &get_default);
    if (kr == KERN_SUCCESS)
    {
      struct timespec delay = { 0, 50000000 };

      FRIDA_LOCK ();
      msleep (&frida_watchdog_thread, frida_lock, PRIBIO | PCATCH, "frida",
          &delay);
      FRIDA_UNLOCK ();
    }
  }
  while (kr != KERN_TERMINATED);

  thread_deallocate (frida_watchdog_thread);
  frida_watchdog_thread = NULL;
}

static void
frida_kernel_agent_watchdog (void * parameter,
                             wait_result_t wait_result)
{
  struct timespec check_interval = { 5, 0 };

  FRIDA_LOCK ();

  while (!frida_is_stopping)
  {
    int status;
    uint64_t now;
    boolean_t have_stale_entry;
    FridaSpawnEntry * entry;

    status = msleep (&frida_is_stopping, frida_lock, PRIBIO | PCATCH, "frida",
        &check_interval);
    if (status == 0)
      continue;

    clock_get_uptime (&now);

    have_stale_entry = FALSE;

    STAILQ_FOREACH (entry, &frida_pending, entries)
    {
      if (now > entry->deadline)
      {
        have_stale_entry = TRUE;
        break;
      }
    }

    if (have_stale_entry)
    {
      frida_disable_spawn_gating_unlocked ();
    }
  }

  FRIDA_UNLOCK ();
}

static int
frida_device_open (dev_t dev,
                   int flags,
                   int devtype,
                   struct proc * p)
{
  FRIDA_LOCK ();

  if (frida_is_open)
    goto busy;

  if (!frida_try_enable_exec_hook ())
    goto busy;
  frida_is_open = true;
  frida_is_gating = false;
  frida_is_nonblocking = false;

  FRIDA_UNLOCK ();

  return 0;

busy:
  {
    FRIDA_UNLOCK ();

    return EBUSY;
  }
}

static int
frida_device_close (dev_t dev,
                    int flags,
                    int devtype,
                    struct proc * p)
{
  FRIDA_LOCK ();

  frida_disable_exec_hook ();
  frida_is_open = false;
  frida_is_gating = false;
  frida_is_nonblocking = false;

  frida_clear_pending ();
  frida_clear_notifications ();

  FRIDA_UNLOCK ();

  return 0;
}

static int
frida_device_read (dev_t dev,
                   struct uio * uio,
                   int ioflag)
{
  int error;
  user_ssize_t space_remaining;

  FRIDA_LOCK ();

  frida_num_operations++;

  while (frida_notifications_length == 0 && !frida_is_stopping)
  {
    if (frida_is_nonblocking)
      goto would_block;

    error = msleep (&frida_notifications_length, frida_lock, PRIBIO | PCATCH,
        "frida", NULL);
    if (error != 0)
      goto propagate_error;
  }

  if (frida_is_stopping)
    goto stopping;

  while ((space_remaining = uio_resid (uio)) > 0)
  {
    FridaSpawnNotification * notification;
    int n;

    notification = STAILQ_FIRST (&frida_notifications);
    if (notification == NULL)
      break;

    n = (int) MIN ((user_ssize_t) (notification->length - notification->offset),
        space_remaining);

    error = uiomove (notification->data + notification->offset, n, uio);
    if (error != 0)
      goto propagate_error;

    notification->offset += n;
    if (notification->offset == notification->length)
    {
      STAILQ_REMOVE_HEAD (&frida_notifications, notifications);

      frida_spawn_notification_free (notification);
    }

    frida_notifications_length -= n;
  }

  frida_num_operations--;

  FRIDA_UNLOCK ();

  return 0;

would_block:
  {
    error = EWOULDBLOCK;

    goto propagate_error;
  }
stopping:
  {
    error = ENOENT;

    goto propagate_error;
  }
propagate_error:
  {
    frida_num_operations--;

    FRIDA_UNLOCK ();

    return error;
  }
}

static int
frida_device_ioctl (dev_t dev,
                    u_long cmd,
                    caddr_t data,
                    int fflag,
                    struct proc * p)
{
  int error = 0;

  switch (cmd)
  {
    case FIONBIO:
    {
      FRIDA_LOCK ();
      frida_is_nonblocking = !!(*(int *) data);
      FRIDA_UNLOCK ();

      break;
    }
    case FIOASYNC:
    {
      if (*(int *) data)
        error = EINVAL;

      break;
    }
    case FIONREAD:
    {
      FRIDA_LOCK ();
      *(int *) data = frida_notifications_length;
      FRIDA_UNLOCK ();

      break;
    }
    case FRIDA_ENABLE_SPAWN_GATING:
    {
      frida_enable_spawn_gating ();

      break;
    }
    case FRIDA_DISABLE_SPAWN_GATING:
    {
      frida_disable_spawn_gating ();

      break;
    }
    case FRIDA_RESUME:
    {
      pid_t pid = *(pid_t *) data;

      error = frida_resume (pid);

      break;
    }
    case FRIDA_TASK_FOR_PID:
    {
      pid_t pid = *(pid_t *) data;
      mach_port_name_t port;

      error = frida_task_for_pid (pid, &port);
      if (error == 0)
      {
        *(mach_port_name_t *) data = port;
      }

      break;
    }
    default:
    {
      error = ENOTTY;

      break;
    }
  }

  return error;
}

static int
frida_device_select (dev_t dev,
                     int which,
                     void * wql,
                     struct proc * p)
{
  int res = 0;

  if ((which & (POLLIN | POLLRDNORM)) != 0)
  {
    FRIDA_LOCK ();

    if (frida_notifications_length == 0)
    {
      frida_selinfo = (struct selinfo *) &frida_selinfo_storage;
      selrecord (p, frida_selinfo, wql);
    }
    else
    {
      res = 1;
    }

    FRIDA_UNLOCK ();
  }

  return res;
}

static void
frida_on_exec (proc_t proc)
{
  FridaSpawnEntry * entry;

  FRIDA_LOCK ();

  if (!frida_is_open)
    goto not_open;

  entry = frida_spawn_entry_alloc ();

  entry->pid = proc_pid (proc);

  if (frida_is_gating)
  {
    entry->task = frida_private_api.proc_task (proc);
    task_reference (entry->task);
    frida_private_api.task_pidsuspend (entry->task);
  }
  else
  {
    entry->task = NULL;
  }

  entry->executable_path[0] = '\0';
  frida_private_api.proc_pidpathinfo_internal (proc, 0, entry->executable_path,
      sizeof (entry->executable_path), NULL);

  clock_interval_to_deadline (20, 1000 * 1000 * 1000 /* seconds */,
      &entry->deadline);

  frida_emit_notification (entry);

  if (frida_is_gating)
  {
    STAILQ_INSERT_TAIL (&frida_pending, entry, entries);
  }
  else
  {
    frida_spawn_entry_free (entry);
  }

  FRIDA_UNLOCK ();

  return;

not_open:
  {
    FRIDA_UNLOCK ();

    return;
  }
}

static void
frida_clear_pending (void)
{
  FridaSpawnEntry * entry;

  while ((entry = STAILQ_FIRST (&frida_pending)) != NULL)
  {
    STAILQ_REMOVE_HEAD (&frida_pending, entries);

    frida_spawn_entry_resume (entry);
    frida_spawn_entry_free (entry);
  }
}

static void
frida_clear_notifications (void)
{
  FridaSpawnNotification * notification;

  while ((notification = STAILQ_FIRST (&frida_notifications)) != NULL)
  {
    STAILQ_REMOVE_HEAD (&frida_notifications, notifications);

    frida_spawn_notification_free (notification);
  }
}

static void
frida_emit_notification (const FridaSpawnEntry * entry)
{
  FridaSpawnNotification * notification;

  notification = frida_spawn_notification_alloc ();
  snprintf (notification->data, sizeof (notification->data),
      "%d:%s:%s\n", entry->pid, entry->executable_path,
      (entry->task == NULL) ? "running" : "suspended");
  notification->offset = 0;
  notification->length = (int) strlen (notification->data);

  STAILQ_INSERT_TAIL (&frida_notifications, notification, notifications);

  frida_notifications_length += notification->length;

  if (frida_selinfo != NULL)
  {
    selwakeup (frida_selinfo);
    frida_selinfo = NULL;
  }
  wakeup_one ((caddr_t) &frida_notifications_length);
}

static FridaSpawnEntry *
frida_spawn_entry_alloc (void)
{
  return OSMalloc (sizeof (FridaSpawnEntry), frida_tag);
}

static void
frida_spawn_entry_free (FridaSpawnEntry * self)
{
  OSFree (self, sizeof (FridaSpawnEntry), frida_tag);
}

static void
frida_spawn_entry_resume (FridaSpawnEntry * self)
{
  frida_private_api.task_pidresume (self->task);
  task_deallocate (self->task);
  self->task = NULL;
}

static FridaSpawnNotification *
frida_spawn_notification_alloc (void)
{
  return OSMalloc (sizeof (FridaSpawnNotification), frida_tag);
}

static void
frida_spawn_notification_free (FridaSpawnNotification * self)
{
  OSFree (self, sizeof (FridaSpawnNotification), frida_tag);
}

static bool
frida_try_enable_exec_hook (void)
{
  return OSCompareAndSwapPtr (NULL, frida_on_exec,
      frida_private_api.dtrace_proc_waitfor_exec_ptr);
}

static void
frida_disable_exec_hook (void)
{
  OSCompareAndSwapPtr (frida_on_exec, NULL,
      frida_private_api.dtrace_proc_waitfor_exec_ptr);
}

static void
frida_enable_spawn_gating (void)
{
  FRIDA_LOCK ();

  frida_is_gating = true;

  FRIDA_UNLOCK ();
}

static void
frida_disable_spawn_gating (void)
{
  FRIDA_LOCK ();

  frida_disable_spawn_gating_unlocked ();

  FRIDA_UNLOCK ();
}

static void
frida_disable_spawn_gating_unlocked (void)
{
  frida_is_gating = false;
  frida_clear_pending ();
}

static int
frida_resume (pid_t pid)
{
  int error;
  FridaSpawnEntry * entry;

  error = ESRCH;

  FRIDA_LOCK ();

  STAILQ_FOREACH (entry, &frida_pending, entries)
  {
    if (entry->pid == pid)
    {
      STAILQ_REMOVE (&frida_pending, entry, _FridaSpawnEntry, entries);

      frida_spawn_entry_resume (entry);
      frida_spawn_entry_free (entry);

      error = 0;
      break;
    }
  }

  FRIDA_UNLOCK ();

  return error;
}

static int
frida_task_for_pid (pid_t pid,
                    mach_port_name_t * port)
{
  proc_t proc;
  task_t task;
  void * send_right;

  proc = proc_find (pid);
  if (proc == NULL)
    goto not_found;

  task = frida_private_api.proc_task (proc);
  task_reference (task);

  send_right = frida_private_api.convert_task_to_port (task);

  if (frida_private_api.is_corpsetask (task))
    goto task_dead;

  *port = frida_private_api.ipc_port_copyout_send (send_right,
      frida_private_api.get_task_ipcspace (current_task ()));

  proc_rele (proc);

  return 0;

not_found:
  {
    return ESRCH;
  }
task_dead:
  {
    frida_private_api.ipc_port_release_send (send_right);
    proc_rele (proc);
    return ESRCH;
  }
}

static bool
frida_find_private_api (FridaPrivateApi * api)
{
  FridaMachODetails details;
  const struct symtab_command * symtab;
  const struct nlist_64 * symbols;
  const char * strings;
  uint32_t sym_index;
  int remaining;

  bzero (api, sizeof (FridaPrivateApi));

  frida_find_kernel_mach_o_details (&details);

  symtab = details.symtab;
  symbols = details.linkedit + symtab->symoff;
  strings = details.linkedit + symtab->stroff;

  remaining = 13;
  for (sym_index = 0; sym_index != symtab->nsyms && remaining > 0; sym_index++)
  {
    const struct nlist_64 * symbol = &symbols[sym_index];
    const char * name = strings + symbol->n_un.n_strx;

#   define FRIDA_TRY_RESOLVE(n) \
    if (strcmp (name, "_" OS_STRINGIFY (n)) == 0) \
    { \
      api->n = (void *) symbol->n_value; \
      remaining--; \
      continue; \
    }

    FRIDA_TRY_RESOLVE (task_pidsuspend)
    FRIDA_TRY_RESOLVE (task_pidresume)
    FRIDA_TRY_RESOLVE (convert_task_to_port)
    FRIDA_TRY_RESOLVE (is_corpsetask)
    FRIDA_TRY_RESOLVE (get_task_ipcspace)

    FRIDA_TRY_RESOLVE (thread_set_thread_name)
    FRIDA_TRY_RESOLVE (thread_policy_get)

    FRIDA_TRY_RESOLVE (ipc_port_copyout_send)
    FRIDA_TRY_RESOLVE (ipc_port_release_send)

    FRIDA_TRY_RESOLVE (proc_task)
    FRIDA_TRY_RESOLVE (proc_pidpathinfo_internal)

    FRIDA_TRY_RESOLVE (dtrace_proc_waitfor_exec_ptr)

    FRIDA_TRY_RESOLVE (cdevsw_setkqueueok)
  }

  return remaining == 0;
}

static void
frida_find_kernel_mach_o_details (FridaMachODetails * details)
{
  const struct mach_header_64 * header;
  const void * command;
  uint32_t cmd_index;

  header = frida_find_kernel_header ();

  details->header = header;
  details->linkedit = NULL;
  details->symtab = NULL;

  command = header + 1;
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    const struct load_command * lc = command;

    switch (lc->cmd)
    {
      case LC_SEGMENT_64:
      {
        const struct segment_command_64 * sc = command;

        if (strcmp (sc->segname, "__LINKEDIT") == 0)
        {
          details->linkedit = (const void *) (sc->vmaddr - sc->fileoff);
        }

        break;
      }
      case LC_SYMTAB:
      {
        details->symtab = command;

        break;
      }
    }

    command += lc->cmdsize;
  }
}

static const struct mach_header_64 *
frida_find_kernel_header (void)
{
  const void * cur;

  cur = (const void *) ((size_t) OSMalloc_Tagalloc & ~(size_t) (4096 - 1));
  while (true)
  {
    const struct mach_header_64 * header = cur;

    if (header->magic == MH_MAGIC_64)
      return header;

    cur = cur - 4096;
  }

  return NULL;
}

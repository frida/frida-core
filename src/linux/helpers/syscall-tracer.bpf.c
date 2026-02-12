#include "frida-linux-syscalls.h"

#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TARGET_TGIDS 4096
#define MAX_TARGET_UIDS 256
#define MAX_MAP_STATES 8192
#define MAX_STACK_ENTRIES 16384
#define MAX_INFLIGHT_COPIES 4096

#define MAX_STACK_DEPTH 16
#define MAX_PATH_DEPTH 20
#define MAX_PATH 256
#define MAX_SOCK 128
#define MAX_BUF_BUILDER_SIZE 1024

#define SYSCALL_NARGS 6

typedef struct _Event Event;
typedef __u16 EventType;

typedef struct _AttachmentHeader AttachmentHeader;
typedef __u16 AttachmentType;

typedef struct _SyscallEvent SyscallEvent;
typedef struct _SyscallEnterEvent SyscallEnterEvent;
typedef struct _SyscallExitEvent SyscallExitEvent;

typedef struct _SyscallEnterEventNone SyscallEnterEventNone;
typedef struct _SyscallEnterEventPath SyscallEnterEventPath;
typedef struct _SyscallEnterEventSock SyscallEnterEventSock;

typedef struct _SyscallExitEventNone SyscallExitEventNone;
typedef struct _SyscallExitEventOut SyscallExitEventOut;

typedef struct _NeedSnapshotEvent NeedSnapshotEvent;
typedef struct _MapCreateEvent MapCreateEvent;
typedef struct _MapDestroyRangeEvent MapDestroyRangeEvent;

typedef struct _ProcessState ProcessState;
typedef struct _Inflight Inflight;
typedef struct _Stats Stats;
typedef struct _BufBuilder BufBuilder;
typedef struct _ScratchArea ScratchArea;

struct _Event
{
  __u64 time_ns;
  __u32 tgid;
  __u32 tid;

  EventType type;

  __u16 attachment_count;
};

enum _EventType
{
  EVENT_TYPE_SYSCALL_ENTER,
  EVENT_TYPE_SYSCALL_EXIT,

  EVENT_TYPE_NEED_SNAPSHOT,
  EVENT_TYPE_MAP_CREATE,
  EVENT_TYPE_MAP_DESTROY_RANGE
};

struct _AttachmentHeader
{
  AttachmentType type;
  __u16 arg_index;
  __u32 len;
};

enum _AttachmentType
{
  ATTACHMENT_STRING,
  ATTACHMENT_BYTES,
};

struct _SyscallEvent
{
  Event parent;

  __s32 syscall_nr;
  __s32 stack_id;
  __u32 map_gen;
};

struct _SyscallEnterEvent
{
  SyscallEvent parent;

  __u64 args[SYSCALL_NARGS];
};

struct _SyscallExitEvent
{
  SyscallEvent parent;

  __s64 retval;
};

struct _SyscallEnterEventNone
{
  SyscallEnterEvent parent;
};

struct _SyscallEnterEventPath
{
  SyscallEnterEvent parent;

  AttachmentHeader attach;
  __u8 data[MAX_PATH];
};

struct _SyscallEnterEventSock
{
  SyscallEnterEvent parent;

  AttachmentHeader attach;
  __u8 data[MAX_SOCK];
};

struct _SyscallExitEventNone
{
  SyscallExitEvent parent;
};

struct _SyscallExitEventOut
{
  SyscallExitEvent parent;

  AttachmentHeader attach;
  __u8 data[MAX_PATH];
};

struct _NeedSnapshotEvent
{
  Event parent;
};

struct _MapCreateEvent
{
  Event parent;

  __u64 start;
  __u64 end;

  __u64 pgoff;
  __u64 vm_flags;

  __u64 device;
  __u64 inode;

  __u32 gen;

  AttachmentHeader attach;
  __u8 data[MAX_PATH];
};

struct _MapDestroyRangeEvent
{
  Event parent;

  __u64 start;
  __u64 end;

  __u32 gen;
};

struct _ProcessState
{
  __u8 abi;
  __u32 map_gen;
};

struct _Inflight
{
  __s32 syscall_nr;

  __u16 kind;
  __u16 _pad0;

  union
  {
    struct
    {
      __u16 arg_index;
      __u16 _pad1;

      __u64 user_ptr;
      __u32 max_len;
      __u32 _pad2;
    } out_copy;
  } u;
};

enum
{
  INFLIGHT_KIND_OUT_COPY = 1,
};

struct _Stats
{
  __u64 emitted_events;
  __u64 emitted_bytes;

  __u64 dropped_events;
  __u64 dropped_bytes;
};

struct _BufBuilder
{
  __u8 buf[2 * MAX_BUF_BUILDER_SIZE];
  __u32 pos;
};

struct _ScratchArea
{
  BufBuilder bb;
  __u64 chain[MAX_PATH_DEPTH];
};

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, MAX_TARGET_TGIDS);
  __type (key, __u32);
  __type (value, __u8);
}
target_tgids SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, MAX_TARGET_UIDS);
  __type (key, __u32);
  __type (value, __u8);
}
target_uids SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 1 << 22);
}
syscall_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 1 << 20);
}
map_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_STACK_TRACE);
  __uint (max_entries, MAX_STACK_ENTRIES);
  __uint (key_size, sizeof (__u32));
  __uint (value_size, MAX_STACK_DEPTH * sizeof (__u64));
}
stacks SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_LRU_HASH);
  __uint (max_entries, MAX_MAP_STATES);
  __type (key, __u32);
  __type (value, ProcessState);
}
process_states SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, MAX_INFLIGHT_COPIES);
  __type (key, __u32);
  __type (value, Inflight);
}
inflight SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint (max_entries, 1);
  __type (key, __u32);
  __type (value, Stats);
}
stats SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint (max_entries, 1);
  __type (key, __u32);
  __type (value, ScratchArea);
}
scratch_area SEC (".maps");

struct trace_event_raw_sys_enter
{
  __u64 unused;
  long id;
  unsigned long args[6];
};

struct trace_event_raw_sys_exit
{
  __u64 unused;
  long id;
  long ret;
};

typedef __u32 dev_t;

struct super_block
{
  dev_t s_dev;
} __attribute__ ((preserve_access_index));

struct inode
{
  struct super_block * i_sb;
  unsigned long i_ino;
} __attribute__ ((preserve_access_index));

struct vfsmount
{
  struct dentry * mnt_root;
} __attribute__ ((preserve_access_index));

struct mount
{
  struct vfsmount mnt;
  struct mount * mnt_parent;
  struct dentry * mnt_mountpoint;
} __attribute__ ((preserve_access_index));

struct qstr
{
  const unsigned char * name;
  __u32 len;
} __attribute__ ((preserve_access_index));

struct dentry
{
  struct dentry * d_parent;
  struct qstr d_name;
} __attribute__ ((preserve_access_index));

struct path
{
  struct vfsmount * mnt;
  struct dentry * dentry;
} __attribute__ ((preserve_access_index));

struct file
{
  struct inode * f_inode;
  const struct path f_path;
} __attribute__ ((preserve_access_index));

struct mm_struct
{
} __attribute__ ((preserve_access_index));

typedef unsigned long vm_flags_t;

struct vm_area_struct
{
  unsigned long vm_start;
  unsigned long vm_end;
  vm_flags_t vm_flags;
  unsigned long vm_pgoff;
  struct file * vm_file;
} __attribute__ ((preserve_access_index));

static bool should_trace_current (__u32 * out_tgid, __u32 * out_tid);

static SyscallEnterEventNone * reserve_enter_none (void);
static SyscallEnterEventPath * reserve_enter_path (void);
static SyscallEnterEventSock * reserve_enter_sock (void);

static SyscallExitEventNone * reserve_exit_none (void);
static SyscallExitEventOut * reserve_exit_out (void);

static void * reserve_syscall_event (__u64 size);

static void fill_syscall_event (SyscallEvent * e, EventType type, __u32 tgid, __u32 tid, __s32 nr, __u32 map_gen,
    void * ctx);
static void fill_enter_args (__u64 args[SYSCALL_NARGS], struct trace_event_raw_sys_enter * ctx);

static __u16 write_attach_str_arg (AttachmentHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_str);
static __u16 write_attach_bytes_arg (AttachmentHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap,
    const void * user_src, __u32 n);
static __u16 write_attach_dentry_path (AttachmentHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, struct file * file);

static void maybe_schedule_out_copy (__u32 tid, __s32 nr, __u16 arg_index, __u64 user_ptr, __u32 max_len );

static __u32 ensure_map_gen (__u32 tgid, __u32 tid);
static __u32 bump_map_gen (__u32 tgid);
static bool emit_need_snapshot (__u32 tgid, __u32 tid);

static MapCreateEvent * reserve_map_create (void);
static MapDestroyRangeEvent * reserve_map_destroy_range (void);

static void * reserve_map_event (__u64 size);

static Stats * get_ringbuf_stats (void);
static void note_emit (Stats * stats, __u64 bytes);
static void note_drop (Stats * stats, __u64 wanted_bytes);

static void stop_current_thread (void);

static void bb_reset (BufBuilder * b);
static bool bb_putc (BufBuilder * b, __u8 c);
static __u32 bb_append_kstr (BufBuilder * b, const void * kstr);
static void bb_flush_to (const BufBuilder * b, __u8 * dst, __u32 dst_cap);

SEC ("tracepoint/raw_syscalls/sys_enter")
int
on_sys_enter (struct trace_event_raw_sys_enter * ctx)
{
  __u32 tgid, tid;
  if (!should_trace_current (&tgid, &tid))
    return 0;

  __s32 nr = (__s32) ctx->id;
  __u32 map_gen = ensure_map_gen (tgid, tid);

  if (nr == FRIDA_LINUX_SYSCALL_OPENAT ||
      nr == FRIDA_LINUX_SYSCALL_FACCESSAT ||
      nr == FRIDA_LINUX_SYSCALL_STATFS ||
#ifdef FRIDA_LINUX_SYSCALL_NEWFSTATAT
      nr == FRIDA_LINUX_SYSCALL_NEWFSTATAT ||
#endif
      nr == FRIDA_LINUX_SYSCALL_READLINKAT)
  {
    SyscallEnterEventPath * ev = reserve_enter_path ();
    if (ev == NULL)
      return 0;

    fill_syscall_event (&ev->parent.parent, EVENT_TYPE_SYSCALL_ENTER, tgid, tid, nr, map_gen, ctx);
    fill_enter_args (ev->parent.args, ctx);

    if (nr == FRIDA_LINUX_SYSCALL_STATFS)
      write_attach_str_arg (&ev->attach, 0, &ev->data[0], MAX_PATH, (void *) ctx->args[0]);
    else
      write_attach_str_arg (&ev->attach, 1, &ev->data[0], MAX_PATH, (void *) ctx->args[1]);

    ev->parent.parent.parent.attachment_count = 1;

    if (nr == FRIDA_LINUX_SYSCALL_READLINKAT)
    {
      maybe_schedule_out_copy (tid, nr, 2, (__u64) ctx->args[2], (__u32) ctx->args[3]);
    }

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }

  if (nr == FRIDA_LINUX_SYSCALL_CONNECT)
  {
    SyscallEnterEventSock * ev = reserve_enter_sock ();
    if (ev == NULL)
      return 0;

    fill_syscall_event (&ev->parent.parent, EVENT_TYPE_SYSCALL_ENTER, tgid, tid, nr, map_gen, ctx);
    fill_enter_args (ev->parent.args, ctx);

    write_attach_bytes_arg (&ev->attach, 1, &ev->data[0], MAX_SOCK, (void *) ctx->args[1], ctx->args[2]);

    ev->parent.parent.parent.attachment_count = 1;

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }

  {
    SyscallEnterEventNone * ev = reserve_enter_none ();
    if (ev == NULL)
      return 0;

    fill_syscall_event (&ev->parent.parent, EVENT_TYPE_SYSCALL_ENTER, tgid, tid, nr, map_gen, ctx);
    fill_enter_args (ev->parent.args, ctx);

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }
}

SEC ("tracepoint/raw_syscalls/sys_exit")
int
on_sys_exit (struct trace_event_raw_sys_exit * ctx)
{
  __u32 tgid, tid;
  if (!should_trace_current (&tgid, &tid))
    return 0;

  __s32 nr = (__s32) ctx->id;
  __u32 map_gen = ensure_map_gen (tgid, tid);

  Inflight * in = bpf_map_lookup_elem (&inflight, &tid);
  if (in != NULL && in->kind == INFLIGHT_KIND_OUT_COPY && in->syscall_nr == nr)
  {
    SyscallExitEventOut * ev = reserve_exit_out ();
    if (ev == NULL)
      return 0;

    fill_syscall_event (&ev->parent.parent, EVENT_TYPE_SYSCALL_EXIT, tgid, tid, nr, map_gen, ctx);

    ev->parent.retval = (__s64) ctx->ret;

    long n = ctx->ret;
    if (n > 0)
    {
      __u32 maxn = in->u.out_copy.max_len;
      if (maxn > MAX_PATH - 1)
        maxn = MAX_PATH - 1;

      __u32 to_copy = (__u32) n;
      if (to_copy > maxn)
        to_copy = maxn;

      ev->attach.type = ATTACHMENT_BYTES;
      ev->attach.arg_index = in->u.out_copy.arg_index;

      if (to_copy == (MAX_PATH - 1))
      {
        ev->attach.len = (MAX_PATH - 1) + 1;
        bpf_probe_read_user (&ev->data[0], MAX_PATH - 1, (void *) in->u.out_copy.user_ptr);
        ev->data[MAX_PATH - 1] = '\0';
      }
      else
      {
        ev->attach.len = to_copy + 1;
        if (to_copy != 0)
          bpf_probe_read_user (&ev->data[0], to_copy, (void *) in->u.out_copy.user_ptr);
        ev->data[to_copy] = '\0';
      }

      ev->parent.parent.parent.attachment_count = 1;
    }

    bpf_map_delete_elem (&inflight, &tid);

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }

  {
    SyscallExitEventNone * ev = reserve_exit_none ();
    if (ev == NULL)
      return 0;

    fill_syscall_event (&ev->parent.parent, EVENT_TYPE_SYSCALL_EXIT, tgid, tid, nr, map_gen, ctx);

    ev->parent.retval = (__s64) ctx->ret;

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }
}

SEC ("kprobe/uprobe_mmap")
int
BPF_KPROBE (on_uprobe_mmap, struct vm_area_struct * vma)
{
  __u32 tgid, tid;
  if (!should_trace_current (&tgid, &tid))
    return 0;

  __u32 gen = bump_map_gen (tgid);
  if (gen == 0)
    return 0;

  struct file * file = BPF_CORE_READ (vma, vm_file);
  if (file == NULL)
    return 0;

  struct inode * inode = BPF_CORE_READ (file, f_inode);
  if (inode == NULL)
    return 0;

  MapCreateEvent * ev = reserve_map_create ();
  if (ev == NULL)
    return 0;

  ev->parent.time_ns = bpf_ktime_get_ns ();
  ev->parent.tgid = tgid;
  ev->parent.tid = tid;

  ev->parent.type = EVENT_TYPE_MAP_CREATE;
  ev->parent.attachment_count = 0;

  ev->start = BPF_CORE_READ (vma, vm_start);
  ev->end = BPF_CORE_READ (vma, vm_end);

  ev->pgoff = BPF_CORE_READ (vma, vm_pgoff);
  ev->vm_flags = BPF_CORE_READ (vma, vm_flags);

  ev->device = BPF_CORE_READ (inode, i_sb, s_dev);
  ev->inode = BPF_CORE_READ (inode, i_ino);

  ev->gen = gen;

  if (write_attach_dentry_path (&ev->attach, 0, &ev->data[0], MAX_PATH, file) != 0)
    ev->parent.attachment_count = 1;

  bpf_ringbuf_submit (ev, 0);
  return 0;
}

SEC ("kprobe/uprobe_munmap")
int
BPF_KPROBE (on_uprobe_munmap, struct vm_area_struct * vma, unsigned long start, unsigned long end)
{
  __u32 tgid, tid;
  if (!should_trace_current (&tgid, &tid))
    return 0;

  struct file * file = BPF_CORE_READ (vma, vm_file);
  if (file == NULL)
    return 0;

  __u32 gen = bump_map_gen (tgid);
  if (gen == 0)
    return 0;

  MapDestroyRangeEvent * ev = reserve_map_destroy_range ();
  if (ev == NULL)
    return 0;

  ev->parent.time_ns = bpf_ktime_get_ns ();
  ev->parent.tgid = tgid;
  ev->parent.tid = tid;

  ev->parent.type = EVENT_TYPE_MAP_DESTROY_RANGE;
  ev->parent.attachment_count = 0;

  ev->start = start;
  ev->end = end;

  ev->gen = gen;

  bpf_ringbuf_submit (ev, 0);
  return 0;
}

static bool
should_trace_current (__u32 * out_tgid, __u32 * out_tid)
{
  __u64 pid_tgid = bpf_get_current_pid_tgid ();
  __u32 tgid = pid_tgid >> 32;
  __u32 tid  = (__u32) pid_tgid;

  *out_tgid = tgid;
  *out_tid = tid;

  __u8 * tgid_enabled = bpf_map_lookup_elem (&target_tgids, &tgid);
  if (tgid_enabled != NULL)
    return true;

  __u64 uid_gid = bpf_get_current_uid_gid ();
  __u32 uid = (__u32) uid_gid;

  __u8 * uid_enabled = bpf_map_lookup_elem (&target_uids, &uid);
  if (uid_enabled != NULL)
    return true;

  return false;
}

static SyscallEnterEventNone *
reserve_enter_none (void)
{
  return reserve_syscall_event (sizeof (SyscallEnterEventNone));
}

static SyscallEnterEventPath *
reserve_enter_path (void)
{
  return reserve_syscall_event (sizeof (SyscallEnterEventPath));
}

static SyscallEnterEventSock *
reserve_enter_sock (void)
{
  return reserve_syscall_event (sizeof (SyscallEnterEventSock));
}

static SyscallExitEventNone *
reserve_exit_none (void)
{
  return reserve_syscall_event (sizeof (SyscallExitEventNone));
}

static SyscallExitEventOut *
reserve_exit_out (void)
{
  return reserve_syscall_event (sizeof (SyscallExitEventOut));
}

static void *
reserve_syscall_event (__u64 size)
{
  void * event = bpf_ringbuf_reserve (&syscall_events, size, 0);

  Stats * stats = get_ringbuf_stats ();
  if (event != NULL)
    note_emit (stats, size);
  else
    note_drop (stats, size);

  return event;
}

static void
fill_syscall_event (SyscallEvent * e, EventType type, __u32 tgid, __u32 tid, __s32 nr, __u32 map_gen, void * ctx)
{
  e->parent.time_ns = bpf_ktime_get_ns ();
  e->parent.tgid = tgid;
  e->parent.tid = tid;

  e->parent.type = type;
  e->parent.attachment_count = 0;

  e->syscall_nr = nr;
  e->stack_id = bpf_get_stackid (ctx, &stacks, BPF_F_USER_STACK);
  e->map_gen = map_gen;
}

static void
fill_enter_args (__u64 args[SYSCALL_NARGS], struct trace_event_raw_sys_enter * ctx)
{
  args[0] = (__u64) ctx->args[0];
  args[1] = (__u64) ctx->args[1];
  args[2] = (__u64) ctx->args[2];
  args[3] = (__u64) ctx->args[3];
  args[4] = (__u64) ctx->args[4];
  args[5] = (__u64) ctx->args[5];
}

static __u16
write_attach_str_arg (AttachmentHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_str)
{
  h->type = ATTACHMENT_STRING;
  h->arg_index = arg_index;
  h->len = 0;

  long r = bpf_probe_read_user_str (dst, dst_cap, user_str);
  __u32 used = (r > 0) ? (__u32) r : 0;

  h->len = used;
  return (__u16) used;
}

static __u16
write_attach_bytes_arg (AttachmentHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_src, __u32 n)
{
  h->type = ATTACHMENT_BYTES;
  h->arg_index = arg_index;

  if (n == 0)
  {
    h->len = 0;
    return 0;
  }

  if (n > dst_cap)
    n = dst_cap;

  bpf_probe_read_user (dst, n, user_src);

  h->len = n;

  return (__u16) n;
}

static __u16
write_attach_dentry_path (AttachmentHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, struct file * file)
{
  __u32 n;

  h->type = ATTACHMENT_STRING;
  h->arg_index = arg_index;
  h->len = 0;

  __u32 key = 0;
  ScratchArea * sa = bpf_map_lookup_elem (&scratch_area, &key);
  if (sa == NULL)
    return 0;

  BufBuilder * b = &sa->bb;
  bb_reset (b);

  struct dentry * d = BPF_CORE_READ (file, f_path.dentry);
  if (d == NULL)
    return 0;

  struct vfsmount * vmnt = BPF_CORE_READ (file, f_path.mnt);
  if (vmnt == NULL)
    return 0;

  struct mount * mnt = container_of (vmnt, struct mount, mnt);
  if (mnt == NULL)
    return 0;

  __u32 count = 0;
  struct dentry * mnt_root = BPF_CORE_READ (&mnt->mnt, mnt_root);

  for (__u32 i = 0; i != MAX_PATH_DEPTH; i++)
  {
    if (d == NULL || mnt == NULL)
      break;

    if (mnt_root != NULL && d == mnt_root)
    {
      struct mount * parent = BPF_CORE_READ (mnt, mnt_parent);
      if (parent == NULL || parent == mnt)
        break;

      struct dentry * mp = BPF_CORE_READ (mnt, mnt_mountpoint);
      if (mp == NULL)
        break;

      mnt = parent;
      mnt_root = BPF_CORE_READ (&mnt->mnt, mnt_root);
      d = mp;
      continue;
    }

    sa->chain[count] = (__u64) d;
    count++;
    if (count >= MAX_PATH_DEPTH)
      break;

    struct dentry * parent = BPF_CORE_READ (d, d_parent);
    if (parent == NULL || parent == d)
      break;

    d = parent;
  }

  if (!bb_putc (b, '/'))
    return 0;

  if (count == 0)
  {
    bb_putc (b, '\0');
    goto flush;
  }

  for (__u32 j = 0; j != MAX_PATH_DEPTH; j++)
  {
    if (count == 0)
      break;

    count--;
    struct dentry * cur = (struct dentry *) sa->chain[count];
    if (cur == NULL)
      break;

    const unsigned char * name = BPF_CORE_READ (cur, d_name.name);
    if (name == NULL)
      break;

    if (b->pos != 1)
    {
      if (!bb_putc (b, '/'))
        break;
    }

    if (bb_append_kstr (b, (const void *) name) == 0)
      break;
  }

  if (!bb_putc (b, '\0'))
    b->buf[MAX_BUF_BUILDER_SIZE - 1] = '\0';

flush:
  n = b->pos;
  if (n > dst_cap)
    n = dst_cap;

  if (n != 0)
    bpf_probe_read_kernel (dst, n, b->buf);

  h->len = n;
  return (__u16) n;
}

static void
maybe_schedule_out_copy (__u32 tid, __s32 nr, __u16 arg_index, __u64 user_ptr, __u32 max_len)
{
  Inflight v;

  v.syscall_nr = nr;
  v.kind = INFLIGHT_KIND_OUT_COPY;
  v._pad0 = 0;

  v.u.out_copy.arg_index = arg_index;
  v.u.out_copy._pad1 = 0;

  v.u.out_copy.user_ptr = user_ptr;
  v.u.out_copy.max_len = max_len;
  v.u.out_copy._pad2 = 0;

  bpf_map_update_elem (&inflight, &tid, &v, BPF_ANY);
}

static __u32
ensure_map_gen (__u32 tgid, __u32 tid)
{
  ProcessState * st = bpf_map_lookup_elem (&process_states, &tgid);
  if (st == NULL)
  {
    ProcessState init;

    init.abi = 0;
    init.map_gen = 0;

    long r = bpf_map_update_elem (&process_states, &tgid, &init, BPF_NOEXIST);
    if (r == 0)
    {
      if (emit_need_snapshot (tgid, tid))
      {
        bpf_send_signal (SIGSTOP);
      }
      else
      {
        bpf_map_delete_elem (&process_states, &tgid);
        return 0;
      }
    }

    st = bpf_map_lookup_elem (&process_states, &tgid);
    if (st == NULL)
      return 0;
  }

  return st->map_gen;
}

static __u32
bump_map_gen (__u32 tgid)
{
  ProcessState * st = bpf_map_lookup_elem (&process_states, &tgid);
  if (st == NULL || st->map_gen == 0)
    return 0;

  __u32 new_gen = __sync_add_and_fetch (&st->map_gen, 1);
  return new_gen;
}

static bool
emit_need_snapshot (__u32 tgid, __u32 tid)
{
  NeedSnapshotEvent * ev = reserve_map_event (sizeof (NeedSnapshotEvent));
  if (ev == NULL)
    return false;

  ev->parent.time_ns = bpf_ktime_get_ns ();
  ev->parent.tgid = tgid;
  ev->parent.tid = tid;

  ev->parent.type = EVENT_TYPE_NEED_SNAPSHOT;
  ev->parent.attachment_count = 0;

  bpf_ringbuf_submit (ev, 0);
  return true;
}

static MapCreateEvent *
reserve_map_create (void)
{
  return reserve_map_event (sizeof (MapCreateEvent));
}

static MapDestroyRangeEvent *
reserve_map_destroy_range (void)
{
  return reserve_map_event (sizeof (MapDestroyRangeEvent));
}

static void *
reserve_map_event (__u64 size)
{
  void * event = bpf_ringbuf_reserve (&map_events, size, 0);

  Stats * stats = get_ringbuf_stats ();
  if (event != NULL)
    note_emit (stats, size);
  else
    note_drop (stats, size);

  return event;
}

static Stats *
get_ringbuf_stats (void)
{
  __u32 key = 0;
  return bpf_map_lookup_elem (&stats, &key);
}

static void
note_emit (Stats * stats, __u64 bytes)
{
  if (stats == NULL)
    return;

  stats->emitted_events++;
  stats->emitted_bytes += bytes;
}

static void
note_drop (Stats * stats, __u64 wanted_bytes)
{
  if (stats == NULL)
    return;

  stats->dropped_events++;
  stats->dropped_bytes += wanted_bytes;
}

static void
bb_reset (BufBuilder * b)
{
  b->pos = 0;
}

static bool
bb_putc (BufBuilder * b, __u8 c)
{
  __u32 pos = b->pos;

  if (pos >= MAX_BUF_BUILDER_SIZE - 1)
    return false;

  b->buf[pos] = c;
  b->pos++;

  return true;
}

static __u32
bb_append_kstr (BufBuilder * b, const void * kstr)
{
  __u32 pos = b->pos;

  if (pos >= MAX_BUF_BUILDER_SIZE - 1)
    return 0;

  __u32 cap = MAX_BUF_BUILDER_SIZE - pos;
  if (cap < 2)
    return 0;

  cap &= MAX_BUF_BUILDER_SIZE - 1;
  if (cap < 2)
    return 0;

  long r = bpf_probe_read_kernel_str ((char *) &b->buf[pos], cap, kstr);
  if (r <= 1)
    return 0;

  __u32 n = (__u32) r - 1;
  b->pos = pos + n;

  return n;
}

static void
bb_flush_to (const BufBuilder * b, __u8 * dst, __u32 dst_cap)
{
  bpf_probe_read_kernel (dst, dst_cap, b->buf);
}

char LICENSE[] SEC ("license") = "Dual BSD/GPL";

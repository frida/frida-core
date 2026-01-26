#include "frida-linux-syscalls.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DEPTH 16
#define MAX_STACK_ENTRIES 16384
#define MAX_READLINKAT_ARGS_ENTRIES 4096
#define MAX_PATH  256
#define MAX_SOCK  128

typedef __u16 SyscallEventKind;
typedef __u16 SyscallEventPhase;
typedef struct _SyscallEvent SyscallEvent;
typedef struct _SyscallOpenatPayload SyscallOpenatPayload;
typedef struct _SyscallFaccessatPayload SyscallFaccessatPayload;
typedef struct _SyscallStatfsPayload SyscallStatfsPayload;
typedef struct _SyscallNewfstatatPayload SyscallNewfstatatPayload;
typedef struct _SyscallReadlinkatPayload SyscallReadlinkatPayload;
typedef struct _SyscallReadlinkatExitPayload SyscallReadlinkatExitPayload;
typedef struct _SyscallConnectPayload SyscallConnectPayload;

typedef struct _ReadlinkatArgs ReadlinkatArgs;

enum _SyscallEventKind
{
  SYSCALL_EVENT_GENERIC,
  SYSCALL_EVENT_OPENAT,
  SYSCALL_EVENT_FACCESSAT,
  SYSCALL_EVENT_STATFS,
  SYSCALL_EVENT_NEWFSTATAT,
  SYSCALL_EVENT_READLINKAT,
  SYSCALL_EVENT_CONNECT,
};

enum
{
  SYSCALL_PHASE_ENTER,
  SYSCALL_PHASE_EXIT,
};

struct _SyscallEvent
{
  __u64 time_ns;
  __u32 tgid;
  __u32 tid;

  __s32 syscall_nr;
  __s32 stack_id;

  SyscallEventKind kind;
  __u16 payload_len;

  SyscallEventPhase phase;
  __s64 retval;

  /* payload follows */
};

struct _SyscallOpenatPayload
{
  __s32 dfd;
  __s32 flags;
  __u32 mode;
  __u32 path_len;
  char  path[MAX_PATH];
};

struct _SyscallFaccessatPayload
{
  __s32 dfd;
  __s32 mode;
  __s32 flags;
  __u32 path_len;
  char  path[MAX_PATH];
};

struct _SyscallStatfsPayload
{
  __u32 path_len;
  char  path[MAX_PATH];
};

struct _SyscallNewfstatatPayload
{
  __s32 dfd;
  __s32 flags;
  __u32 path_len;
  char  path[MAX_PATH];
};

struct _SyscallReadlinkatPayload
{
  __s32 dfd;
  __u32 bufsize;
  __u32 path_len;
  char  path[MAX_PATH];
};

struct _SyscallReadlinkatExitPayload
{
  __u32 link_len;
  char  link[MAX_PATH];
};

struct _SyscallConnectPayload
{
  __s32 fd;
  __u32 addrlen;
  __u16 family;
  __u16 _pad;
  __u8  addr[MAX_SOCK];
};

struct _ReadlinkatArgs
{
  __u64 buf;
  __u32 bufsize;
  __u32 _pad;
};

struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __uint (max_entries, 1);
  __type (key, __u32);
  __type (value, __u32);
}
target_tgid SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, 1 << 22);
}
events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_STACK_TRACE);
  __uint (max_entries, MAX_STACK_ENTRIES);
  __uint (key_size, sizeof (__u32));
  __uint (value_size, MAX_DEPTH * sizeof (__u64));
}
stacks SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, MAX_READLINKAT_ARGS_ENTRIES);
  __type (key, __u32);
  __type (value, ReadlinkatArgs);
}
readlinkat_args SEC (".maps");

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

static __always_inline SyscallEventKind classify_syscall (__s32 nr);
static __always_inline __u32 clamp_u32 (__u32 v, __u32 max);

static __always_inline SyscallEvent *
reserve_event (SyscallEventKind kind, __u16 payload_len);

SEC ("tracepoint/raw_syscalls/sys_enter")
int
on_sys_enter (struct trace_event_raw_sys_enter * ctx)
{
  __u32 k0 = 0;
  __u32 * target = bpf_map_lookup_elem (&target_tgid, &k0);
  if (target == NULL)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid ();
  __u32 tid  = (__u32) pid_tgid;
  __u32 tgid = pid_tgid >> 32;
  if (tgid != *target)
    return 0;

  __s32 nr = (__s32) ctx->id;
  SyscallEventKind kind = classify_syscall (nr);

  __u16 payload_len = 0;

  switch (kind)
  {
    case SYSCALL_EVENT_OPENAT:
      payload_len = (__u16) sizeof (SyscallOpenatPayload);
      break;
    case SYSCALL_EVENT_FACCESSAT:
      payload_len = (__u16) sizeof (SyscallFaccessatPayload);
      break;
    case SYSCALL_EVENT_STATFS:
      payload_len = (__u16) sizeof (SyscallStatfsPayload);
      break;
    case SYSCALL_EVENT_NEWFSTATAT:
      payload_len = (__u16) sizeof (SyscallNewfstatatPayload);
      break;
    case SYSCALL_EVENT_READLINKAT:
      payload_len = (__u16) sizeof (SyscallReadlinkatPayload);
      break;
    case SYSCALL_EVENT_CONNECT:
      payload_len = (__u16) sizeof (SyscallConnectPayload);
      break;
    default:
      payload_len = 0;
      break;
  }

  SyscallEvent * e = reserve_event (kind, payload_len);
  if (e == NULL)
    return 0;

  e->time_ns = bpf_ktime_get_ns ();
  e->tgid = tgid;
  e->tid = tid;
  e->syscall_nr = nr;
  e->kind = kind;
  e->payload_len = payload_len;

  e->phase = SYSCALL_PHASE_ENTER;
  e->retval = 0;

  e->stack_id = bpf_get_stackid (ctx, &stacks, BPF_F_USER_STACK);

  void * payload = (void *) (e + 1);

  if (kind == SYSCALL_EVENT_OPENAT)
  {
    SyscallOpenatPayload * p = payload;

    p->dfd = (__s32) ctx->args[0];
    p->flags = (__s32) ctx->args[2];
    p->mode = (__u32) ctx->args[3];

    long r = bpf_probe_read_user_str (p->path, MAX_PATH, (void *) ctx->args[1]);
    p->path_len = (r > 0) ? r : 0;
  }
  else if (kind == SYSCALL_EVENT_FACCESSAT)
  {
    SyscallFaccessatPayload * p = payload;

    p->dfd = (__s32) ctx->args[0];
    long r = bpf_probe_read_user_str (p->path, MAX_PATH, (void *) ctx->args[1]);
    p->path_len = (r > 0) ? r : 0;
    p->mode = (__s32) ctx->args[2];
    p->flags = (__s32) ctx->args[3];
  }
  else if (kind == SYSCALL_EVENT_STATFS)
  {
    SyscallStatfsPayload * p = payload;

    long r = bpf_probe_read_user_str (p->path, MAX_PATH, (void *) ctx->args[0]);
    p->path_len = (r > 0) ? r : 0;
  }
  else if (kind == SYSCALL_EVENT_NEWFSTATAT)
  {
    SyscallNewfstatatPayload * p = payload;

    p->dfd = (__s32) ctx->args[0];
    long r = bpf_probe_read_user_str (p->path, MAX_PATH, (void *) ctx->args[1]);
    p->path_len = (r > 0) ? r : 0;

    p->flags = (__s32) ctx->args[3];
  }
  else if (kind == SYSCALL_EVENT_READLINKAT)
  {
    SyscallReadlinkatPayload * p = payload;

    p->dfd = (__s32) ctx->args[0];
    long r = bpf_probe_read_user_str (p->path, MAX_PATH, (void *) ctx->args[1]);
    p->path_len = (r > 0) ? r : 0;

    p->bufsize = (__u32) ctx->args[3];

    ReadlinkatArgs a;
    a.buf = (__u64) ctx->args[2];
    a.bufsize = (__u32) ctx->args[3];
    a._pad = 0;
    bpf_map_update_elem (&readlinkat_args, &tid, &a, BPF_ANY);
  }
  else if (kind == SYSCALL_EVENT_CONNECT)
  {
    SyscallConnectPayload * p = payload;

    p->fd = (__s32) ctx->args[0];

    __u32 n = (__u32) ctx->args[2];

    p->family = 0;
    p->_pad = 0;

    if (n > MAX_SOCK)
    {
      p->addrlen = MAX_SOCK;
      bpf_probe_read_user (p->addr, MAX_SOCK, (void *) ctx->args[1]);

      __u16 fam = 0;
      bpf_probe_read_kernel (&fam, sizeof (fam), p->addr);
      p->family = fam;
    }
    else if (n != 0)
    {
      p->addrlen = n;
      bpf_probe_read_user (p->addr, n, (void *) ctx->args[1]);

      if (n >= sizeof (__u16))
      {
        __u16 fam = 0;
        bpf_probe_read_kernel (&fam, sizeof (fam), p->addr);
        p->family = fam;
      }
    }
    else
    {
      p->addrlen = 0;
    }
  }

  bpf_ringbuf_submit (e, 0);
  return 0;
}

SEC ("tracepoint/raw_syscalls/sys_exit")
int
on_sys_exit (struct trace_event_raw_sys_exit * ctx)
{
  __u32 k0 = 0;
  __u32 * target = bpf_map_lookup_elem (&target_tgid, &k0);
  if (target == NULL)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid ();
  __u32 tid  = (__u32) pid_tgid;
  __u32 tgid = pid_tgid >> 32;
  if (tgid != *target)
    return 0;

  __s32 nr = (__s32) ctx->id;
  SyscallEventKind kind = classify_syscall (nr);

  __u16 payload_len = 0;

  if (kind == SYSCALL_EVENT_READLINKAT)
    payload_len = (__u16) sizeof (SyscallReadlinkatExitPayload);

  SyscallEvent * e = reserve_event (kind, payload_len);
  if (e == NULL)
    return 0;

  e->time_ns = bpf_ktime_get_ns ();
  e->tgid = tgid;
  e->tid = tid;
  e->syscall_nr = nr;
  e->kind = kind;
  e->payload_len = payload_len;

  e->phase = SYSCALL_PHASE_EXIT;
  e->retval = (__s64) ctx->ret;

  e->stack_id = bpf_get_stackid (ctx, &stacks, BPF_F_USER_STACK);

  if (kind == SYSCALL_EVENT_READLINKAT)
  {
    SyscallReadlinkatExitPayload * p = (void *) (e + 1);

    p->link_len = 0;

    ReadlinkatArgs * a = bpf_map_lookup_elem (&readlinkat_args, &tid);
    if (a != NULL)
    {
      long n = ctx->ret;
      if (n > 0)
      {
        __u32 maxn = a->bufsize;
        if (maxn > (MAX_PATH - 1))
          maxn = (MAX_PATH - 1);

        __u32 to_copy = (__u32) n;
        if (to_copy > maxn)
          to_copy = maxn;

        bpf_probe_read_user (p->link, to_copy, (void *) a->buf);
        p->link[to_copy] = '\0';
        p->link_len = to_copy + 1;
      }

      bpf_map_delete_elem (&readlinkat_args, &tid);
    }
  }

  bpf_ringbuf_submit (e, 0);
  return 0;
}

static __always_inline SyscallEvent *
reserve_event (SyscallEventKind kind, __u16 payload_len)
{
  __u32 total_len = sizeof (SyscallEvent) + (__u32) payload_len;
  return bpf_ringbuf_reserve (&events, total_len, 0);
}

static __always_inline SyscallEventKind
classify_syscall (__s32 nr)
{
  switch (nr)
  {
    case FRIDA_LINUX_SYSCALL_OPENAT:
      return SYSCALL_EVENT_OPENAT;
    case FRIDA_LINUX_SYSCALL_FACCESSAT:
      return SYSCALL_EVENT_FACCESSAT;
    case FRIDA_LINUX_SYSCALL_STATFS:
      return SYSCALL_EVENT_STATFS;
#ifdef FRIDA_LINUX_SYSCALL_NEWFSTATAT
    case FRIDA_LINUX_SYSCALL_NEWFSTATAT:
      return SYSCALL_EVENT_NEWFSTATAT;
#endif
    case FRIDA_LINUX_SYSCALL_READLINKAT:
      return SYSCALL_EVENT_READLINKAT;
    case FRIDA_LINUX_SYSCALL_CONNECT:
      return SYSCALL_EVENT_CONNECT;
    default:
      return SYSCALL_EVENT_GENERIC;
  }
}

static __always_inline __u32
clamp_u32 (__u32 v, __u32 max)
{
  return (v > max) ? max : v;
}

char LICENSE[] SEC ("license") = "Dual BSD/GPL";

#include "frida-linux-syscalls.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DEPTH 16
#define MAX_STACK_ENTRIES 16384

#define MAX_INFLIGHT_ENTRIES 4096

#define MAX_PATH 256
#define MAX_SOCK 128

#define SYSCALL_NARGS 6

typedef __u16 SyscallPhase;
typedef struct _SyscallEventCommon SyscallEventCommon;
typedef struct _SyscallEnterPayload SyscallEnterPayload;
typedef struct _SyscallExitPayload SyscallExitPayload;

typedef __u16 AttachType;
typedef struct _AttachHeader AttachHeader;

typedef struct _SyscallEnterEventNone SyscallEnterEventNone;
typedef struct _SyscallEnterEventPath SyscallEnterEventPath;
typedef struct _SyscallEnterEventSock SyscallEnterEventSock;

typedef struct _SyscallExitEventNone SyscallExitEventNone;
typedef struct _SyscallExitEventOut SyscallExitEventOut;

typedef struct _Inflight Inflight;

enum
{
  SYSCALL_PHASE_ENTER,
  SYSCALL_PHASE_EXIT,
};

struct _SyscallEventCommon
{
  __u64 time_ns;
  __u32 tgid;
  __u32 tid;

  __s32 syscall_nr;
  __s32 stack_id;

  SyscallPhase phase;

  __u16 payload_len;
  __u16 attach_count;
};

struct _SyscallEnterPayload
{
  __u64 args[SYSCALL_NARGS];
};

struct _SyscallExitPayload
{
  __s64 retval;
};

enum
{
  ATTACH_STRING_ARG,
  ATTACH_BYTES_ARG,
  ATTACH_OUT_BYTES,
};

struct _AttachHeader
{
  AttachType type;
  __u16 arg_index;
  __u32 len;
};

struct _SyscallEnterEventNone
{
  SyscallEventCommon common;
  SyscallEnterPayload payload;
};

struct _SyscallEnterEventPath
{
  SyscallEventCommon common;
  SyscallEnterPayload payload;

  AttachHeader attach;
  __u8 data[MAX_PATH];
};

struct _SyscallEnterEventSock
{
  SyscallEventCommon common;
  SyscallEnterPayload payload;

  AttachHeader attach;
  __u8 data[MAX_SOCK];
};

struct _SyscallExitEventNone
{
  SyscallEventCommon common;
  SyscallExitPayload payload;
};

struct _SyscallExitEventOut
{
  SyscallEventCommon common;
  SyscallExitPayload payload;

  AttachHeader attach;
  __u8 data[MAX_PATH];
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
  __uint (max_entries, MAX_INFLIGHT_ENTRIES);
  __type (key, __u32);
  __type (value, Inflight);
}
inflight SEC (".maps");

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

static __always_inline SyscallEnterEventNone * reserve_enter_none (void);
static __always_inline SyscallEnterEventPath * reserve_enter_path (void);
static __always_inline SyscallEnterEventSock * reserve_enter_sock (void);

static __always_inline SyscallExitEventNone * reserve_exit_none (void);
static __always_inline SyscallExitEventOut * reserve_exit_out (void);

static __always_inline void fill_common (SyscallEventCommon * e, __u32 tgid, __u32 tid, __s32 nr, SyscallPhase phase, void * ctx);
static __always_inline void fill_enter_args (SyscallEnterPayload * p, struct trace_event_raw_sys_enter * ctx);

static __always_inline __u16 write_attach_str_arg (AttachHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_str);
static __always_inline __u16 write_attach_bytes_arg (AttachHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_src,
    __u32 n);

static __always_inline void maybe_schedule_out_copy ( __u32 tid, __s32 nr, __u16 arg_index, __u64 user_ptr, __u32 max_len );

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

    fill_common (&ev->common, tgid, tid, nr, SYSCALL_PHASE_ENTER, ctx);
    fill_enter_args (&ev->payload, ctx);

    __u16 arg_index = 1;
    if (nr == FRIDA_LINUX_SYSCALL_STATFS)
      arg_index = 0;

    __u16 used;
    if (nr == FRIDA_LINUX_SYSCALL_STATFS)
      used = write_attach_str_arg (&ev->attach, 0, &ev->data[0], MAX_PATH, (void *) ctx->args[0]);
    else
      used = write_attach_str_arg (&ev->attach, 1, &ev->data[0], MAX_PATH, (void *) ctx->args[1]);

    ev->common.payload_len = ( __u16 ) (sizeof (SyscallEnterPayload) + sizeof (AttachHeader) + used);
    ev->common.attach_count = 1;

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

    fill_common (&ev->common, tgid, tid, nr, SYSCALL_PHASE_ENTER, ctx);
    fill_enter_args (&ev->payload, ctx);

    __u32 n = (__u32) ctx->args[2];
    __u16 used = write_attach_bytes_arg (&ev->attach, 1, &ev->data[0], MAX_SOCK, (void *) ctx->args[1], n);

    ev->common.payload_len = ( __u16 ) (sizeof (SyscallEnterPayload) + sizeof (AttachHeader) + used);
    ev->common.attach_count = 1;

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }

  {
    SyscallEnterEventNone * ev = reserve_enter_none ();
    if (ev == NULL)
      return 0;

    fill_common (&ev->common, tgid, tid, nr, SYSCALL_PHASE_ENTER, ctx);
    fill_enter_args (&ev->payload, ctx);

    ev->common.payload_len = ( __u16 ) sizeof (SyscallEnterPayload);

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }
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

  Inflight * in = bpf_map_lookup_elem (&inflight, &tid);
  if (in != NULL && in->kind == INFLIGHT_KIND_OUT_COPY && in->syscall_nr == nr)
  {
    SyscallExitEventOut * ev = reserve_exit_out ();
    if (ev == NULL)
      return 0;

    fill_common (&ev->common, tgid, tid, nr, SYSCALL_PHASE_EXIT, ctx);

    ev->payload.retval = (__s64) ctx->ret;

    long n = ctx->ret;
    if (n > 0)
    {
      __u32 maxn = in->u.out_copy.max_len;
      if (maxn > MAX_PATH - 1)
        maxn = MAX_PATH - 1;

      __u32 to_copy = (__u32) n;
      if (to_copy > maxn)
        to_copy = maxn;

      ev->attach.type = ATTACH_OUT_BYTES;
      ev->attach.arg_index = in->u.out_copy.arg_index;

      __u16 used;
      if (to_copy == (MAX_PATH - 1))
      {
        ev->attach.len = (MAX_PATH - 1) + 1;
        bpf_probe_read_user (&ev->data[0], MAX_PATH - 1, (void *) in->u.out_copy.user_ptr);
        ev->data[MAX_PATH - 1] = '\0';
        used = (__u16) MAX_PATH;
      }
      else
      {
        ev->attach.len = to_copy + 1;
        if (to_copy != 0)
          bpf_probe_read_user (&ev->data[0], to_copy, (void *) in->u.out_copy.user_ptr);
        ev->data[to_copy] = '\0';
        used = (__u16) (to_copy + 1);
      }

      ev->common.payload_len = ( __u16 ) (sizeof (SyscallExitPayload) + sizeof (AttachHeader) + used);
      ev->common.attach_count = 1;
    }
    else
    {
      ev->common.payload_len = ( __u16 ) sizeof (SyscallExitPayload);
    }

    bpf_map_delete_elem (&inflight, &tid);

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }

  {
    SyscallExitEventNone * ev = reserve_exit_none ();
    if (ev == NULL)
      return 0;

    fill_common (&ev->common, tgid, tid, nr, SYSCALL_PHASE_EXIT, ctx);

    ev->payload.retval = (__s64) ctx->ret;

    ev->common.payload_len = ( __u16 ) sizeof (SyscallExitPayload);

    bpf_ringbuf_submit (ev, 0);
    return 0;
  }
}

static __always_inline SyscallEnterEventNone *
reserve_enter_none (void)
{
  return bpf_ringbuf_reserve (&events, sizeof (SyscallEnterEventNone), 0);
}

static __always_inline SyscallEnterEventPath *
reserve_enter_path (void)
{
  return bpf_ringbuf_reserve (&events, sizeof (SyscallEnterEventPath), 0);
}

static __always_inline SyscallEnterEventSock *
reserve_enter_sock (void)
{
  return bpf_ringbuf_reserve (&events, sizeof (SyscallEnterEventSock), 0);
}

static __always_inline SyscallExitEventNone *
reserve_exit_none (void)
{
  return bpf_ringbuf_reserve (&events, sizeof (SyscallExitEventNone), 0);
}

static __always_inline SyscallExitEventOut *
reserve_exit_out (void)
{
  return bpf_ringbuf_reserve (&events, sizeof (SyscallExitEventOut), 0);
}

static __always_inline void
fill_common (SyscallEventCommon * e, __u32 tgid, __u32 tid, __s32 nr, SyscallPhase phase, void * ctx)
{
  e->time_ns = bpf_ktime_get_ns ();
  e->tgid = tgid;
  e->tid = tid;

  e->syscall_nr = nr;
  e->phase = phase;

  e->payload_len = 0;
  e->attach_count = 0;

  e->stack_id = bpf_get_stackid (ctx, &stacks, BPF_F_USER_STACK);
}

static __always_inline void
fill_enter_args (SyscallEnterPayload * p, struct trace_event_raw_sys_enter * ctx)
{
  p->args[0] = (__u64) ctx->args[0];
  p->args[1] = (__u64) ctx->args[1];
  p->args[2] = (__u64) ctx->args[2];
  p->args[3] = (__u64) ctx->args[3];
  p->args[4] = (__u64) ctx->args[4];
  p->args[5] = (__u64) ctx->args[5];
}

static __always_inline __u16
write_attach_str_arg (AttachHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_str)
{
  h->type = ATTACH_STRING_ARG;
  h->arg_index = arg_index;
  h->len = 0;

  long r = bpf_probe_read_user_str (dst, dst_cap, user_str);
  __u32 used = (r > 0) ? (__u32) r : 0;

  h->len = used;
  return (__u16) used;
}

static __always_inline __u16
write_attach_bytes_arg (AttachHeader * h, __u16 arg_index, __u8 * dst, __u32 dst_cap, const void * user_src, __u32 n)
{
  h->type = ATTACH_BYTES_ARG;
  h->arg_index = arg_index;

  if (n > dst_cap)
  {
    h->len = dst_cap;
    if (dst_cap != 0)
      bpf_probe_read_user (dst, dst_cap, user_src);
    return (__u16) dst_cap;
  }

  h->len = n;
  if (n != 0)
    bpf_probe_read_user (dst, n, user_src);
  return (__u16) n;
}

static __always_inline void
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

char LICENSE[] SEC ("license") = "Dual BSD/GPL";

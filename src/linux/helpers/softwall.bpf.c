#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TARGET_TGIDS 4096
#define MAX_TARGET_UIDS 256

#define MAX_RULES 4096
#define MAX_INODE_INDEX 8192

#define MAX_AUDIT_EVENTS (1 << 20)

typedef struct _Event Event;
typedef __u16 EventType;

typedef struct _AuditEvent AuditEvent;

typedef struct _InodeKey InodeKey;
typedef struct _FileOpenRule FileOpenRule;

typedef struct _Stats Stats;

struct _Event
{
  __u64 time_ns;
  __u32 tgid;
  __u32 tid;

  EventType type;

  __u16 _pad0;
};

enum _EventType
{
  EVENT_TYPE_AUDIT
};

struct _AuditEvent
{
  Event parent;

  __u32 rule_id;

  __u32 _pad0;
};

struct _InodeKey
{
  __u64 dev;
  __u64 ino;
};

struct _FileOpenRule
{
  __u64 dev;
  __u64 ino;

  __s32 errno_neg;
  __u32 _pad0;
};

struct _Stats
{
  __u64 emitted_events;
  __u64 emitted_bytes;

  __u64 dropped_events;
  __u64 dropped_bytes;
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
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, MAX_RULES);
  __type (key, __u32);
  __type (value, FileOpenRule);
}
rules_by_id SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_HASH);
  __uint (max_entries, MAX_INODE_INDEX);
  __type (key, InodeKey);
  __type (value, __u32);
}
inode_index SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_RINGBUF);
  __uint (max_entries, MAX_AUDIT_EVENTS);
}
audit_events SEC (".maps");

struct
{
  __uint (type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint (max_entries, 1);
  __type (key, __u32);
  __type (value, Stats);
}
stats SEC (".maps");

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

struct file
{
  struct inode * f_inode;
} __attribute__ ((preserve_access_index));

static bool should_enforce_current (__u32 * out_tgid, __u32 * out_tid);

static Stats * get_ringbuf_stats (void);
static void note_emit (Stats * stats, __u64 bytes);
static void note_drop (Stats * stats, __u64 wanted_bytes);

static AuditEvent * reserve_audit_event (void);

static bool get_file_inode_key (struct file * file, InodeKey * out_key);

SEC ("lsm/file_open")
int
BPF_PROG (on_file_open, struct file * file)
{
  __u32 tgid, tid;
  if (!should_enforce_current (&tgid, &tid))
    return 0;

  InodeKey key;
  if (!get_file_inode_key (file, &key))
    return 0;

  __u32 * rule_id = bpf_map_lookup_elem (&inode_index, &key);
  if (rule_id == NULL)
    return 0;

  FileOpenRule * rule = bpf_map_lookup_elem (&rules_by_id, rule_id);
  if (rule == NULL)
    return 0;

  AuditEvent * ev = reserve_audit_event ();
  if (ev != NULL)
  {
    ev->parent.time_ns = bpf_ktime_get_ns ();
    ev->parent.tgid = tgid;
    ev->parent.tid = tid;

    ev->parent.type = EVENT_TYPE_AUDIT;

    ev->rule_id = *rule_id;
    ev->_pad0 = 0;

    bpf_ringbuf_submit (ev, 0);
  }

  return rule->errno_neg;
}

static bool
should_enforce_current (__u32 * out_tgid, __u32 * out_tid)
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

static bool
get_file_inode_key (struct file * file, InodeKey * out_key)
{
  if (file == NULL)
    return false;

  struct inode * inode = BPF_CORE_READ (file, f_inode);
  if (inode == NULL)
    return false;

  out_key->dev = BPF_CORE_READ (inode, i_sb, s_dev);
  out_key->ino = BPF_CORE_READ (inode, i_ino);

  return true;
}

static AuditEvent *
reserve_audit_event (void)
{
  void * event = bpf_ringbuf_reserve (&audit_events, sizeof (AuditEvent), 0);

  Stats * stats = get_ringbuf_stats ();
  if (event != NULL)
    note_emit (stats, sizeof (AuditEvent));
  else
    note_drop (stats, sizeof (AuditEvent));

  return (AuditEvent *) event;
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

char LICENSE[] SEC ("license") = "Dual BSD/GPL";

#ifndef __FRIDA_LINUX_BPF_H__
#define __FRIDA_LINUX_BPF_H__

#include <glib.h>

G_BEGIN_DECLS

#define FRIDA_BPF_ANY                 0

#define FRIDA_BPF_RINGBUF_HEADER_SIZE 8

typedef int FridaBpfCommand;
typedef guint32 FridaBpfMapType;
typedef int FridaBpfProgramType;
typedef struct _FridaBpfAttrProgLoad FridaBpfAttrProgLoad;
typedef struct _FridaBpfInsn FridaBpfInsn;
typedef struct _FridaBpfAttrMapCreate FridaBpfAttrMapCreate;
typedef struct _FridaBpfAttrMapElem FridaBpfAttrMapElem;
typedef guint32 FridaBpfStackTraceMapFlags;
typedef guint32 FridaBpfRingbufFlags;

enum _FridaBpfCommand
{
  FRIDA_BPF_COMMAND_MAP_CREATE,
  FRIDA_BPF_COMMAND_MAP_LOOKUP_ELEM,
  FRIDA_BPF_COMMAND_MAP_UPDATE_ELEM,
  FRIDA_BPF_COMMAND_PROG_LOAD = 5,
};

enum _FridaBpfMapType
{
  FRIDA_BPF_MAP_TYPE_ARRAY       = 2,
  FRIDA_BPF_MAP_TYPE_STACK_TRACE = 7,
  FRIDA_BPF_MAP_TYPE_RINGBUF     = 27,
};

enum _FridaBpfProgramType
{
  FRIDA_BPF_PROGRAM_TYPE_TRACEPOINT = 5,
  FRIDA_BPF_PROGRAM_TYPE_PERF_EVENT = 7,
};

struct _FridaBpfAttrProgLoad
{
  guint32 prog_type;
  guint32 insn_cnt;
  guint64 insns;
  guint64 license;
  guint32 log_level;
  guint32 log_size;
  guint64 log_buf;
  guint32 kern_version;
  guint32 prog_flags;
  gchar   prog_name[16];
  guint32 prog_ifindex;
  guint32 expected_attach_type;
};

struct _FridaBpfInsn
{
  guint8 code;
  guint8 dst_src;
  gint16 off;
  gint32 imm;
};

struct _FridaBpfAttrMapCreate
{
  guint32 map_type;
  guint32 key_size;
  guint32 value_size;
  guint32 max_entries;
  guint32 map_flags;
  guint32 inner_map_fd;
  guint32 numa_node;
  gchar   map_name[16];
  guint32 map_ifindex;
  guint32 btf_fd;
  guint32 btf_key_type_id;
  guint32 btf_value_type_id;
};

struct _FridaBpfAttrMapElem
{
  guint32 map_fd;
  guint64 key;
  guint64 value;
  guint64 flags;
};

enum _FridaBpfStackTraceMapFlags
{
  FRIDA_BPF_STACK_TRACE_MAP_BUILD_ID = (1U << 5),
};

enum _FridaBpfRingbufFlags
{
  FRIDA_BPF_RINGBUF_BUSY    = (1U << 31),
  FRIDA_BPF_RINGBUF_DISCARD = (1U << 30),
};

G_END_DECLS

#endif

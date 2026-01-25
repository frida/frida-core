#ifndef __FRIDA_LINUX_PERF_EVENT_H__
#define __FRIDA_LINUX_PERF_EVENT_H__

#include <glib.h>
#include <sys/ioctl.h>

G_BEGIN_DECLS

#define FRIDA_PERF_EVENT_COUNT_SW_CPU_CLOCK  0

typedef struct _FridaPerfEventAttr FridaPerfEventAttr;
typedef guint32 FridaPerfEventType;
typedef gulong FridaPerfEventIoctl;

struct _FridaPerfEventAttr
{
  FridaPerfEventType event_type;
  guint32 size;
  guint64 config;

  union
  {
    guint64 sample_period;
    guint64 sample_freq;
  };

  guint64 sample_type;
  guint64 read_format;

  guint64 flags;

  guint32 wakeup_events;
  guint32 bp_type;

  union
  {
    guint64 bp_addr;
    guint64 config1;
  };

  union
  {
    guint64 bp_len;
    guint64 config2;
  };
};

enum _FridaPerfEventType
{
  FRIDA_PERF_EVENT_TYPE_SOFTWARE = 1,
  FRIDA_PERF_EVENT_TYPE_TRACEPOINT,
};

enum _FridaPerfEventIoctl
{
  FRIDA_PERF_EVENT_IOCTL_ENABLE  = _IO ('$', 0),
  FRIDA_PERF_EVENT_IOCTL_DISABLE = _IO ('$', 1),
  FRIDA_PERF_EVENT_IOCTL_SET_BPF = _IOW ('$', 8, guint32),
};

G_END_DECLS

#endif

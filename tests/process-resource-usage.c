#include "frida-tests.h"

typedef struct _FridaMetricCollectorEntry FridaMetricCollectorEntry;
typedef guint (* FridaMetricCollector) (void * handle);

struct _FridaMetricCollectorEntry
{
  const gchar * name;
  FridaMetricCollector collect;
};

#ifdef HAVE_WINDOWS

#include <windows.h>
#include <psapi.h>

static guint
frida_collect_memory_footprint (void * handle)
{
  PROCESS_MEMORY_COUNTERS_EX counters;
  BOOL success;

  success = GetProcessMemoryInfo (handle, (PPROCESS_MEMORY_COUNTERS) &counters, sizeof (counters));
  g_assert (success);

  return counters.PrivateUsage;
}

static guint
frida_collect_handles (void * handle)
{
  DWORD count;
  BOOL success;

  success = GetProcessHandleCount (handle, &count);
  g_assert (success);

  return count;
}

#endif

#ifdef HAVE_DARWIN

#include <libproc.h>
#include <mach/mach.h>

static guint
frida_collect_memory_footprint (void * handle)
{
  int pid = GPOINTER_TO_SIZE (handle);
  struct rusage_info_v2 info;
  int res;

  res = proc_pid_rusage (pid, RUSAGE_INFO_V2, (rusage_info_t *) &info);
  g_assert_cmpint (res, ==, 0);

  return info.ri_phys_footprint;
}

static guint
frida_collect_mach_ports (void * handle)
{
  int pid = GPOINTER_TO_SIZE (handle);
  mach_port_t task;
  kern_return_t kr;
  ipc_info_space_basic_t info;

  kr = task_for_pid (mach_task_self (), pid, &task);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_space_basic_info (task, &info);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_deallocate (mach_task_self (), task);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  return info.iisb_table_inuse;
}

#endif

static const FridaMetricCollectorEntry frida_metric_collectors[] =
{
#ifdef HAVE_WINDOWS
  { "memory", frida_collect_memory_footprint },
  { "handles", frida_collect_handles },
#endif
#ifdef HAVE_DARWIN
  { "memory", frida_collect_memory_footprint },
  { "ports", frida_collect_mach_ports },
#endif
  { NULL, NULL }
};

FridaTestResourceUsageSnapshot *
frida_test_process_backend_snapshot_resource_usage (void * handle)
{
  FridaTestResourceUsageSnapshot * snapshot;
  const FridaMetricCollectorEntry * entry;

  snapshot = frida_test_resource_usage_snapshot_new ();

  for (entry = frida_metric_collectors; entry->name != NULL; entry++)
  {
    g_hash_table_insert (snapshot->metrics,
        g_strdup (entry->name),
        GSIZE_TO_POINTER (entry->collect (handle)));
  }

  return snapshot;
}

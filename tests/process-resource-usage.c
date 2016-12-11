#include "frida-tests.h"

typedef struct _FridaMetricCollectorEntry FridaMetricCollectorEntry;
typedef guint (* FridaMetricCollector) (void * handle);

struct _FridaMetricCollectorEntry
{
  const gchar * name;
  FridaMetricCollector collect;
};

#ifdef HAVE_DARWIN

#include <mach/mach.h>

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
#ifdef HAVE_DARWIN
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

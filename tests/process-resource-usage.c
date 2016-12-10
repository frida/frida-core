#include "frida-tests.h"

typedef struct _FridaMetricCollectorEntry FridaMetricCollectorEntry;
typedef guint (* FridaMetricCollector) (void * handle);

struct _FridaMetricCollectorEntry
{
  const gchar * name;
  FridaMetricCollector collect;
};

static const FridaMetricCollectorEntry frida_metric_collectors[] =
{
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

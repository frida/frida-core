#include "frida-tests.h"

typedef struct _FridaMetricCollector FridaMetricCollector;
typedef guint (* FridaMetricCollectorFunc) (void * handle);

struct _FridaMetricCollector
{
  const gchar * name;
  FridaMetricCollectorFunc collect;
};

static const FridaMetricCollector frida_metric_collectors[] =
{
  { NULL, NULL }
};

FridaTestResourceUsageSnapshot *
frida_test_process_backend_snapshot_resource_usage (void * handle)
{
  FridaTestResourceUsageSnapshot * snapshot;
  GHashTable * metrics;
  const FridaMetricCollector * collector;

  snapshot = frida_test_resource_usage_snapshot_new ();
  metrics = snapshot->metrics;

  for (collector = frida_metric_collectors; collector->name != NULL; collector++)
  {
    g_hash_table_insert (metrics,
        g_strdup (collector->name),
        GSIZE_TO_POINTER (collector->collect (handle)));
  }

  return snapshot;
}

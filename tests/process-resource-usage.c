#include "frida-tests.h"

typedef struct _FridaMetricCollectorEntry FridaMetricCollectorEntry;
typedef guint (* FridaMetricCollector) (FridaTestProcess * process);

struct _FridaMetricCollectorEntry
{
  const gchar * name;
  FridaMetricCollector collect;
};

#ifdef HAVE_WINDOWS

#include <windows.h>
#include <psapi.h>

static guint
frida_collect_memory_footprint (FridaTestProcess * process)
{
  PROCESS_MEMORY_COUNTERS_EX counters;
  BOOL success;

  success = GetProcessMemoryInfo (frida_test_process_get_handle (process), (PPROCESS_MEMORY_COUNTERS) &counters,
      sizeof (counters));
  g_assert_true (success);

  return counters.PrivateUsage;
}

static guint
frida_collect_handles (FridaTestProcess * process)
{
  DWORD count;
  BOOL success;

  success = GetProcessHandleCount (frida_test_process_get_handle (process), &count);
  g_assert_true (success);

  return count;
}

#endif

#ifdef HAVE_DARWIN

#ifdef HAVE_IOS
int proc_pid_rusage (int pid, int flavor, rusage_info_t * buffer);
#else
# include <libproc.h>
#endif
#include <mach/mach.h>

static guint
frida_collect_memory_footprint (FridaTestProcess * process)
{
  struct rusage_info_v2 info;
  int res;

  res = proc_pid_rusage (frida_test_process_get_id (process), RUSAGE_INFO_V2, (rusage_info_t *) &info);
  g_assert_cmpint (res, ==, 0);

  return info.ri_phys_footprint;
}

static guint
frida_collect_mach_ports (FridaTestProcess * process)
{
  mach_port_t task;
  kern_return_t kr;
  ipc_info_space_basic_t info;

  kr = task_for_pid (mach_task_self (), frida_test_process_get_id (process), &task);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_space_basic_info (task, &info);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_deallocate (mach_task_self (), task);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  return info.iisb_table_inuse;
}

#endif

#ifdef HAVE_LINUX

#include <gum/gum.h>

static guint
frida_collect_memory_footprint (FridaTestProcess * process)
{
  gchar * path, * stats;
  gboolean success;
  gint num_pages;

  path = g_strdup_printf ("/proc/%u/statm", frida_test_process_get_id (process));

  success = g_file_get_contents (path, &stats, NULL, NULL);
  g_assert_true (success);

  num_pages = atoi (strchr (stats,  ' ') + 1); /* RSS */

  g_free (stats);
  g_free (path);

  return num_pages * gum_query_page_size ();
}

static guint
frida_collect_file_descriptors (FridaTestProcess * process)
{
  gchar * path;
  GDir * dir;
  guint count;

  path = g_strdup_printf ("/proc/%u/fd", frida_test_process_get_id (process));

  dir = g_dir_open (path, 0, NULL);
  g_assert_nonnull (dir);

  count = 0;
  while (g_dir_read_name (dir) != NULL)
    count++;

  g_dir_close (dir);

  g_free (path);

  return count;
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
#ifdef HAVE_LINUX
  { "memory", frida_collect_memory_footprint },
  { "files", frida_collect_file_descriptors },
#endif
  { NULL, NULL }
};

FridaTestResourceUsageSnapshot *
frida_test_process_snapshot_resource_usage (FridaTestProcess * self)
{
  FridaTestResourceUsageSnapshot * snapshot;
  const FridaMetricCollectorEntry * entry;

  snapshot = frida_test_resource_usage_snapshot_new ();

  for (entry = frida_metric_collectors; entry->name != NULL; entry++)
  {
    guint value;

    value = entry->collect (self);

    g_hash_table_insert (snapshot->metrics, g_strdup (entry->name), GSIZE_TO_POINTER (value));
  }

  return snapshot;
}

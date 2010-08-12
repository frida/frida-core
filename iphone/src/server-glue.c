#include "zid-server.h"

#include <sys/sysctl.h>

ZedHostProcessInfo *
zid_system_enumerate_processes (int * result_length1)
{
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  struct kinfo_proc * entries;
  size_t length;
  gint err;
  guint count, i;
  ZedHostProcessInfo * result;

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length,
      NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  result = g_new (ZedHostProcessInfo, count);
  *result_length1 = count;

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];

    zed_host_process_info_init (&result[i], e->kp_proc.p_pid, e->kp_proc.p_comm,
        "", "");
  }

  g_free (entries);

  return result;
}


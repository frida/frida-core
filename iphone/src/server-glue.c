#include "zid-server.h"

#include <signal.h>
#include <unistd.h>
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
  ZedHostProcessIcon no_icon;

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length,
      NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  result = g_new (ZedHostProcessInfo, count);
  *result_length1 = count;

  zed_host_process_icon_init (&no_icon, 0, 0, 0, "");

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];

    zed_host_process_info_init (&result[i], e->kp_proc.p_pid, e->kp_proc.p_comm,
        &no_icon, &no_icon);
  }

  zed_host_process_icon_destroy (&no_icon);

  g_free (entries);

  return result;
}

void
zid_system_kill (guint pid)
{
  killpg (getpgid (pid), SIGTERM);
}


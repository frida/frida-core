#include <glib.h>

#ifdef HAVE_MACOS

#include <libproc.h>

guint
frida_host_session_test_darwin_parent_pid_of (guint pid)
{
  struct proc_bsdinfo info;

  if (proc_pidinfo (pid, PROC_PIDTBSDINFO, 0, &info, sizeof (info)) != sizeof (info))
    return 0;

  return info.pbi_ppid;
}

gboolean
frida_host_session_test_darwin_holds_both_ends_of_a_socketpair (guint pid)
{
  gboolean result = FALSE;
  int size, n, i, j;
  struct proc_fdinfo * fds;
  uint64_t * sockets, * peers;
  int num_sockets = 0;

  size = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, NULL, 0);
  g_assert_cmpint (size, >, 0);
  fds = g_malloc (size);
  n = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, fds, size) / PROC_PIDLISTFD_SIZE;

  sockets = g_new (uint64_t, n);
  peers = g_new (uint64_t, n);
  for (i = 0; i != n; i++)
  {
    struct socket_fdinfo si;

    if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET)
      continue;
    if (proc_pidfdinfo (pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof (si)) != sizeof (si))
      continue;
    if (si.psi.soi_kind != SOCKINFO_UN)
      continue;

    sockets[num_sockets] = si.psi.soi_so;
    peers[num_sockets] = si.psi.soi_proto.pri_un.unsi_conn_so;
    num_sockets++;
  }

  for (i = 0; i != num_sockets && !result; i++)
  {
    for (j = 0; j != num_sockets; j++)
    {
      if (peers[i] == sockets[j])
      {
        result = TRUE;
        break;
      }
    }
  }

  g_free (peers);
  g_free (sockets);
  g_free (fds);

  return result;
}

#endif

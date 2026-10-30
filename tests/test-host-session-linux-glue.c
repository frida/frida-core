#include <glib.h>

#ifdef HAVE_LINUX

#include <signal.h>

static void frida_host_session_test_linux_on_sigchld (int sig);

static struct sigaction frida_host_session_test_linux_saved_sigchld_action;

void
frida_host_session_test_linux_install_sigchld_handler (void)
{
  struct sigaction action = { 0, };

  action.sa_handler = frida_host_session_test_linux_on_sigchld;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_RESTART;
  sigaction (SIGCHLD, &action, &frida_host_session_test_linux_saved_sigchld_action);
}

gboolean
frida_host_session_test_linux_sigchld_handler_is_installed (void)
{
  struct sigaction action;

  sigaction (SIGCHLD, NULL, &action);

  return action.sa_handler == frida_host_session_test_linux_on_sigchld;
}

void
frida_host_session_test_linux_reset_sigchld_handler (void)
{
  struct sigaction action = { 0, };

  action.sa_handler = SIG_DFL;
  sigemptyset (&action.sa_mask);
  sigaction (SIGCHLD, &action, &frida_host_session_test_linux_saved_sigchld_action);
}

void
frida_host_session_test_linux_restore_sigchld_handler (void)
{
  sigaction (SIGCHLD, &frida_host_session_test_linux_saved_sigchld_action, NULL);
}

static void
frida_host_session_test_linux_on_sigchld (int sig)
{
}

#endif

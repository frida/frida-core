#include "zed-core.h"

#include <errno.h>
#include <mach/mach.h>
#include <spawn.h>
#include <string.h>
#include <gum/gumdarwin.h>

static gboolean print_thread (GumThreadDetails * details, gpointer user_data);

guint
_zed_darwin_host_session_spawn (const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  pid_t pid;
  posix_spawnattr_t attr;
  sigset_t signal_mask_set;
  int result;
  kern_return_t ret;
  mach_port_name_t self_task, task;
  GumAddress entrypoint;

  g_print ("_zed_darwin_host_session_spawn path='%s' argv_length=%d envp_length=%d\n", path, argv_length, envp_length);

  posix_spawnattr_init (&attr);
  sigemptyset (&signal_mask_set);
  posix_spawnattr_setsigmask (&attr, &signal_mask_set);
  posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED);

  result = posix_spawn (&pid, path, 0, &attr, argv, envp);

  posix_spawnattr_destroy (&attr);

  if (result != 0)
    goto handle_spawn_error;

  g_print ("result=%d, pid=%d\n", result, (int) pid);

  self_task = mach_task_self ();
  ret = task_for_pid (self_task, pid, &task);

  g_print ("task_for_pid ret=%d\n", (int) ret);

  g_print ("starting to enumerate threads\n");
  gum_darwin_enumerate_threads (task, print_thread, NULL);
  g_print ("finished enumerating threads\n");

  entrypoint = gum_darwin_find_entrypoint (task);
  g_print ("entrypoint is at %p\n", (gpointer) entrypoint);

  //g_usleep (20 * 60 * G_USEC_PER_SEC);

  mach_port_deallocate (self_task, task);

  kill (pid, SIGCONT);

  //g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not there yet");
  return pid;

handle_spawn_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "posix_spawn failed: %s (%d)", strerror (result), result);
    return 0;;
  }
}

void
_zed_darwin_host_session_resume (guint pid, GError ** error)
{
}

static gboolean
print_thread (GumThreadDetails * details, gpointer user_data)
{
  kern_return_t ret;

  g_print ("  print_thread! id=%p state=%d rip=%p\n", (gpointer) details->id, (int) details->state, (gpointer) details->cpu_context.rip);

  //ret = thread_suspend (details->id);
  //g_print ("thread_suspend returned %d\n", ret);

  return TRUE;
}

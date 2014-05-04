#include "frida-core.h"

#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

typedef struct _FridaSpawnInstance FridaSpawnInstance;

struct _FridaSpawnInstance
{
  FridaLinuxHostSession * host_session;
  pid_t pid;
};

static FridaSpawnInstance * frida_spawn_instance_new (FridaLinuxHostSession * host_session);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static gboolean is_libc_loaded (pid_t pid);
static gboolean wait_for_syscall (pid_t pid, GError ** error);

guint
_frida_linux_host_session_do_spawn (FridaLinuxHostSession * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  FridaSpawnInstance * instance;
  int status;

  instance = frida_spawn_instance_new (self);

  instance->pid = fork ();
  if (instance->pid == 0)
  {
    ptrace (PTRACE_TRACEME, 0, NULL, NULL);
    kill (getpid (), SIGSTOP);
    if (execve (path, argv, envp) == -1)
    {
      g_printerr ("execve failed: %s (%d)\n", strerror (errno), errno);
      abort ();
    }
  }

  waitpid (instance->pid, &status, 0);
  ptrace (PTRACE_SETOPTIONS, instance->pid, NULL, GSIZE_TO_POINTER (PTRACE_O_TRACESYSGOOD));

  /* execve enter */
  if (!wait_for_syscall (instance->pid, error))
    goto error_epilogue;

  /* execve leave */
  if (!wait_for_syscall (instance->pid, error))
    goto error_epilogue;

  while (!is_libc_loaded (instance->pid))
  {
    if (!wait_for_syscall (instance->pid, error))
      goto error_epilogue;
  }

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_pid), GUINT_TO_POINTER (instance->pid), instance);

  return instance->pid;

error_epilogue:
  {
    frida_spawn_instance_free (instance);
    return 0;
  }
}

void
_frida_linux_host_session_resume_instance (FridaLinuxHostSession * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_linux_host_session_free_instance (FridaLinuxHostSession * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaLinuxHostSession * host_session)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
  instance->host_session = g_object_ref (host_session);

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  g_object_unref (instance->host_session);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  ptrace (PTRACE_DETACH, self->pid, NULL, NULL);
}

static gboolean
is_libc_loaded (pid_t pid)
{
  gboolean result = FALSE;
  gchar * maps_path, * maps_data;

  maps_path = g_strdup_printf ("/proc/%d/maps", pid);
  if (g_file_get_contents (maps_path, &maps_data, NULL, NULL))
  {
    result = strstr (maps_data, "/libc") != NULL;
    g_free (maps_data);
  }
  g_free (maps_path);

  return result;
}

static gboolean
wait_for_syscall (pid_t pid, GError ** error)
{
  gboolean stopped_at_syscall;

  do
  {
    int status;

    ptrace (PTRACE_SYSCALL, pid, NULL, NULL);

    waitpid (pid, &status, 0);
    if (WIFEXITED (status))
      goto handle_exited_error;

    stopped_at_syscall = WIFSTOPPED (status) && (WSTOPSIG (status) & 0x80) != 0;
  }
  while (!stopped_at_syscall);

  return TRUE;

handle_exited_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "process exited prematurely");
    return FALSE;
  }
}


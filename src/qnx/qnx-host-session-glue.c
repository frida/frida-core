#include "frida-core.h"

#include <gum/gumlinux.h>
#include <elf.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif

#define FRIDA_OFFSET_E_ENTRY 0x18
#if defined (HAVE_I386)
# define FRIDA_SIGBKPT SIGTRAP
#elif defined (HAVE_ARM)
# define FRIDA_SIGBKPT SIGBUS
#endif

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_os_error; \
  }

#if defined (HAVE_I386)
# define regs_t struct user_regs_struct
#elif defined (HAVE_ARM)
# define regs_t struct pt_regs
#else
# error Unsupported architecture
#endif

typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaProbeElfContext FridaProbeElfContext;

struct _FridaSpawnInstance
{
  FridaQNXHostSession * host_session;
  pid_t pid;
};

struct _FridaProbeElfContext
{
  pid_t pid;
  GumAddress entry_point;
  gsize word_size;
};

static FridaSpawnInstance * frida_spawn_instance_new (FridaQNXHostSession * host_session);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static gboolean frida_wait_for_child_signal (pid_t pid, int signal);
static gboolean frida_run_to_entry_point (pid_t pid, GError ** error);

static gboolean frida_examine_range_for_elf_header (const GumRangeDetails * details, gpointer user_data);

guint
_frida_linux_host_session_do_spawn (FridaQNXHostSession * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  FridaSpawnInstance * instance;
  int status;
  long ret;
  gboolean success;
  const gchar * failed_operation;

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

  ret = ptrace (PTRACE_CONT, instance->pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (instance->pid, SIGTRAP);
  CHECK_OS_RESULT (success, !=, FALSE, "wait(SIGTRAP)");

  if (!frida_run_to_entry_point (instance->pid, error))
    goto error_epilogue;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_pid), GUINT_TO_POINTER (instance->pid), instance);

  return instance->pid;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    goto error_epilogue;
  }
error_epilogue:
  {
    frida_spawn_instance_free (instance);
    return 0;
  }
}

void
_frida_linux_host_session_resume_instance (FridaQNXHostSession * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_linux_host_session_free_instance (FridaQNXHostSession * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaQNXHostSession * host_session)
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
frida_wait_for_child_signal (pid_t pid, int signal)
{
  int status = 0;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || !WIFSTOPPED (status))
    return FALSE;

  return WSTOPSIG (status) == signal;
}

static gboolean
frida_run_to_entry_point (pid_t pid, GError ** error)
{
  FridaProbeElfContext ctx;
  gpointer entry_point_address;
  long original_entry_code, patched_entry_code;
  long ret;
  regs_t regs;
  const gchar * failed_operation;
  gboolean success;

  ctx.pid = pid;
  ctx.entry_point = 0;
  gum_linux_enumerate_ranges (pid, GUM_PAGE_RX, frida_examine_range_for_elf_header, &ctx);
  if (ctx.entry_point == 0)
    goto handle_probe_error;

#ifdef HAVE_ARM
  entry_point_address = GSIZE_TO_POINTER (ctx.entry_point & ~1);
#else
  entry_point_address = GSIZE_TO_POINTER (ctx.entry_point);
#endif

  original_entry_code = ptrace (PTRACE_PEEKDATA, pid, entry_point_address, NULL);

#ifdef HAVE_ARM
  if (ctx.word_size == 4)
  {
    if ((ctx.entry_point & 1) == 0)
    {
      /* ARM */
      patched_entry_code = 0xe1200070;
    }
    else
    {
      /* Thumb */
      patched_entry_code = 0xbe00;
    }
  }
  else
  {
    /* ARM64 */
    patched_entry_code = 0xd4200000;
  }
#else
  /* x86 */
  patched_entry_code = 0xcc;
#endif

  ptrace (PTRACE_POKEDATA, pid, entry_point_address, GSIZE_TO_POINTER (patched_entry_code));

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, FRIDA_SIGBKPT);
  CHECK_OS_RESULT (success, !=, FALSE, "WAIT(FRIDA_SIGBKPT)");

  ptrace (PTRACE_POKEDATA, pid, entry_point_address, GSIZE_TO_POINTER (original_entry_code));

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.eip = GPOINTER_TO_SIZE (entry_point_address);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.rip = GPOINTER_TO_SIZE (entry_point_address);
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (entry_point_address);
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  return TRUE;

handle_probe_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to probe process");
    return FALSE;
  }
handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_examine_range_for_elf_header (const GumRangeDetails * details, gpointer user_data)
{
  FridaProbeElfContext * ctx = user_data;
  union
  {
    long word;
    guint8 u8;
    guint16 u16;
    guint32 u32;
    guint64 u64;
    gchar magic[SELFMAG];
  } value;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address), NULL);
  if (memcmp (value.magic, ELFMAG, SELFMAG) != 0)
    return TRUE;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address + EI_NIDENT), NULL);
  if (value.u16 != ET_EXEC)
    return TRUE;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address + EI_CLASS), NULL);
  ctx->word_size = value.u8 == ELFCLASS32 ? 4 : 8;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address + FRIDA_OFFSET_E_ENTRY), NULL);
  ctx->entry_point = ctx->word_size == 4 ? value.u32 : value.u64;

  return FALSE;
}


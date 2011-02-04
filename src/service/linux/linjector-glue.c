#include "zed-core.h"

#include <dlfcn.h>
#include <errno.h>
#ifdef HAVE_I386
#include <gum/arch-x86/gumx86writer.h>
#endif
#ifdef HAVE_ARM
#include <gum/arch-arm/gumarmwriter.h>
#include <gum/arch-arm/gumthumbwriter.h>
#endif
#include <gum/gum.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#ifdef HAVE_SYS_USER_H
#include <sys/user.h>
#endif
#include <sys/wait.h>

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_os_error; \
  }

#if defined (HAVE_I386)
#define regs_t struct user_regs_struct
#elif defined (HAVE_ARM)
#define regs_t struct pt_regs
#else
#error Unspoorted arch
#endif

typedef struct _ZedCodeChunk ZedCodeChunk;
typedef struct _ZedLinContext ZedLinContext;
typedef struct _ZedInjectionInstance ZedInjectionInstance;

struct _ZedCodeChunk
{
  guint8 bytes[256];
  gsize size;
};

struct _ZedLinContext
{
  gpointer foo;
};

struct _ZedInjectionInstance
{
  ZedLinjector * linjector;
  guint id;
};

static void zed_emit_trampoline_code (int pid, GumAddress remote_address, ZedCodeChunk * code);

static gboolean zed_attach_to_process (int pid, regs_t * saved_regs, GError ** error);
static gboolean zed_detach_from_process (int pid, const regs_t * saved_regs, GError ** error);

static gpointer zed_remote_alloc (int pid, size_t size, int prot, GError ** error);
static gboolean zed_remote_write (int pid, gpointer remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean zed_remote_exec (int pid, gpointer remote_address, GError ** error);

static gboolean zed_wait_for_child_signal (gulong pid, int signal);

static gpointer zed_resolve_remote_libc_function (int remote_pid, const gchar * function_name);
static gpointer zed_find_libc_base (int pid);

void
_zed_linjector_create_context (ZedLinjector * self)
{
  ZedLinContext * ctx;

  ctx = g_new0 (ZedLinContext, 1);

  self->context = ctx;
}

void
_zed_linjector_destroy_context (ZedLinjector * self)
{
  ZedLinContext * ctx = self->context;

  g_free (ctx);
}

static ZedInjectionInstance *
zed_injection_instance_new (ZedLinjector * linjector, guint id)
{
  ZedInjectionInstance * instance;

  instance = g_new (ZedInjectionInstance, 1);
  instance->linjector = g_object_ref (linjector);
  instance->id = id;

  return instance;
}

static void
zed_injection_instance_free (ZedInjectionInstance * instance)
{
  g_object_unref (instance->linjector);
  g_free (instance);
}

void
_zed_linjector_free_instance (ZedLinjector * self, void * instance)
{
  zed_injection_instance_free (instance);
}

guint
_zed_linjector_do_inject (ZedLinjector * self, gulong pid, const char * so_path, const char * data_string,
    GError ** error)
{
  ZedInjectionInstance * instance;
  regs_t saved_regs;
  gpointer remote_code;
  ZedCodeChunk code;

  instance = zed_injection_instance_new (self, self->last_id++);

  if (!zed_attach_to_process (pid, &saved_regs, error))
    goto beach;

  remote_code = zed_remote_alloc (pid, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, error);
  if (remote_code == NULL)
    goto beach;

  zed_emit_trampoline_code (pid, GUM_ADDRESS (remote_code), &code);

  if (!zed_remote_write (pid, remote_code, code.bytes, code.size, error))
    goto beach;

  if (!zed_remote_exec (pid, remote_code, error))
    goto beach;

  if (!zed_detach_from_process (pid, &saved_regs, error))
    goto beach;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  return instance->id;

beach:
  {
    zed_injection_instance_free (instance);
    return 0;
  }
}

#if defined (HAVE_I386)
static void
zed_emit_trampoline_code (int pid, GumAddress remote_address, ZedCodeChunk * code)
{
  GumX86Writer cw;

  gum_x86_writer_init (&cw, code->bytes);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, GUM_ADDRESS (zed_resolve_remote_libc_function (pid, "printf")));
  gum_x86_writer_put_xor_reg_reg (&cw, GUM_REG_XAX, GUM_REG_XAX);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XBX,
      1, GUM_ARG_POINTER, (remote_address + 128));
  gum_x86_writer_put_int3 (&cw);

  gum_x86_writer_free (&cw);

  memcpy (code->bytes + 128, "Hey baby\n", 9 + 1);

  code->size = 128 + 9 + 1;
}
#elif defined (HAVE_ARM)
static void
zed_emit_trampoline_code (int pid, GumAddress remote_address, ZedCodeChunk * code)
{
  GumThumbWriter cw;

  gum_thumb_writer_init (&cw, code->bytes);

  gum_thumb_writer_put_breakpoint (&cw);

  gum_thumb_writer_free (&cw);

  memcpy (code->bytes + 128, "Hey baby\n", 9 + 1);

  code->size = 128 + 9 + 1;
}
#endif

static gboolean
zed_attach_to_process (int pid, regs_t * saved_regs, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  gboolean success;
  regs_t regs;

  ret = ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_ATTACH");

  success = zed_wait_for_child_signal (pid, SIGSTOP);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_ATTACH wait");

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");
  memcpy (saved_regs, &regs, sizeof (regs));

#if defined (HAVE_I386)
  regs.rip = 0;
#elif defined (HAVE_ARM)
  regs.ARM_pc = 0;
#endif
  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = zed_wait_for_child_signal (pid, SIGSEGV);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
zed_detach_from_process (int pid, const regs_t * saved_regs, GError ** error)
{
  long ret;
  const gchar * failed_operation;

  ret = ptrace (PTRACE_SETREGS, pid, NULL, saved_regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_DETACH, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_DETACH");

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gpointer
zed_remote_alloc (int pid, size_t size, int prot, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

  /* setup argument list for mmap and call it */
#if defined (HAVE_I386)
  regs.rip = GPOINTER_TO_SIZE (zed_resolve_remote_libc_function (pid, "mmap"));

  /* all six arguments in registers (SysV ABI) */
  regs.rdi = 0;
  regs.rsi = size;
  regs.rdx = prot;
  regs.rcx = MAP_PRIVATE | MAP_ANONYMOUS;
  regs.r8 = -1;
  regs.r9 = 0;

  regs.rax = 0x1337;

  regs.rsp -= 8;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.rsp, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (zed_resolve_remote_libc_function (pid, "mmap"));

  /* first four arguments in r0 - r3 */
  regs.ARM_r0 = 0;
  regs.ARM_r1 = size;
  regs.ARM_r2 = prot;
  regs.ARM_r3 = MAP_PRIVATE | MAP_ANONYMOUS;

  /* 6th argument on stack */
  regs.ARM_sp -= 4;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.ARM_sp, GSIZE_TO_POINTER (0));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");

  /* 5th argument on stack */
  regs.ARM_sp -= 4;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.ARM_sp, GSIZE_TO_POINTER (-1));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");

  /* return address on stack */
  regs.ARM_sp -= 4;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.ARM_sp, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = zed_wait_for_child_signal (pid, SIGSEGV);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386)
  return GSIZE_TO_POINTER (regs.rax);
#elif defined (HAVE_ARM)
  return GSIZE_TO_POINTER (regs.ARM_ORIG_r0);
#endif

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    return NULL;
  }
}

static gboolean
zed_remote_write (int pid, gpointer remote_address, gconstpointer data, gsize size, GError ** error)
{
  gsize * dst;
  const gsize * src;
  long ret;
  const gchar * failed_operation;
  gsize remainder;

  dst = remote_address;
  src = data;

  while (dst != remote_address + ((size / sizeof (gsize)) * sizeof (gsize)))
  {
    ret = ptrace (PTRACE_POKETEXT, pid, dst, *src);
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKETEXT head");

    dst++;
    src++;
  }

  remainder = size % sizeof (gsize);
  if (remainder != 0)
  {
    gsize word;

    memcpy (&word, src, remainder);

    ret = ptrace (PTRACE_POKETEXT, pid, dst, word);
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKETEXT tail");
  }

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
zed_remote_exec (int pid, gpointer remote_address, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386)
  regs.rip = GPOINTER_TO_SIZE (remote_address);
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (remote_address);
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = zed_wait_for_child_signal (pid, SIGTRAP);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
zed_wait_for_child_signal (gulong pid, int signal)
{
  int status;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || !WIFSTOPPED (status))
    return FALSE;

  return WSTOPSIG (status) == signal;
}

static gpointer
zed_resolve_remote_libc_function (int remote_pid, const gchar * function_name)
{
  gpointer local_base, remote_base, module;
  gpointer local_address, remote_address;

  local_base = zed_find_libc_base (getpid ());
  remote_base = zed_find_libc_base (remote_pid);

  module = dlopen ("/lib/libc.so.6", RTLD_GLOBAL | RTLD_NOW);
  g_assert (module != NULL);

  local_address = dlsym (module, function_name);
  g_assert (local_address != NULL);

  remote_address = remote_base + (local_address - local_base);

  dlclose (module);

  return remote_address;
}

static gpointer
zed_find_libc_base (int pid)
{
  gpointer result = NULL;
  gchar * maps_path;
  FILE * fp;
  const guint line_size = 1024 + PATH_MAX;
  gchar * line, * path;

  maps_path = g_strdup_printf ("/proc/%d/maps", pid);

  fp = fopen (maps_path, "r");
  g_assert (fp != NULL);

  g_free (maps_path);

  line = g_malloc (line_size);
  path = g_malloc (PATH_MAX);

  while (result == NULL && fgets (line, line_size, fp) != NULL)
  {
    gpointer start;
    gint n;
    gchar * name;

    n = sscanf (line, "%p-%*p %*s %*x %*s %*s %s", &start, path);
    if (n == 1)
      continue;
    g_assert_cmpint (n, ==, 2);

    if (path[0] == '[')
      continue;

    name = g_path_get_basename (path);
    if (g_str_has_prefix (name, "libc"))
      result = start;
    g_free (name);
  }

  g_free (path);
  g_free (line);

  fclose (fp);

  return result;
}

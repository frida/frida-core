#include "frida-core.h"

#include <gio/gunixinputstream.h>
#ifdef HAVE_I386
#include <udis86.h>
#include <gum/arch-x86/gumx86writer.h>
#endif
#ifdef HAVE_ARM
#include <gum/arch-arm/gumarmwriter.h>
#include <gum/arch-arm/gumthumbwriter.h>
#endif
#include <gum/gum.h>
#include <gum/gumlinux.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_SYS_USER_H
#include <sys/user.h>
#endif
#include <sys/wait.h>

#define FRIDA_RTLD_DLOPEN (0x80000000)

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
#error Unsupported architecture
#endif

#define FRIDA_REMOTE_PAYLOAD_SIZE (8192)
#define FRIDA_REMOTE_DATA_OFFSET (512)
#define FRIDA_REMOTE_STACK_OFFSET (FRIDA_REMOTE_PAYLOAD_SIZE - 512)
#define FRIDA_REMOTE_DATA_FIELD(n) \
  GSIZE_TO_POINTER (remote_address + FRIDA_REMOTE_DATA_OFFSET + G_STRUCT_OFFSET (FridaTrampolineData, n))

typedef struct _FridaInjectionInstance FridaInjectionInstance;
typedef struct _FridaInjectionParams FridaInjectionParams;
typedef struct _FridaCodeChunk FridaCodeChunk;
typedef struct _FridaTrampolineData FridaTrampolineData;
typedef struct _FridaFindLandingStripContext FridaFindLandingStripContext;

typedef void (* FridaEmitFunc) (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

struct _FridaInjectionInstance
{
  FridaLinjector * linjector;
  guint id;
  pid_t pid;
  gchar * fifo_path;
  gint fifo;
  gpointer remote_payload;
};

struct _FridaInjectionParams
{
  pid_t pid;
  const char * so_path;
  const char * data_string;

  const char * fifo_path;
  gpointer remote_address;
};

struct _FridaCodeChunk
{
  guint8 * cur;
  gsize size;
  guint8 bytes[2048];
};

struct _FridaTrampolineData
{
  gchar pthread_so[32];
  gchar pthread_create[32];
  gchar fifo_path[256];
  gchar so_path[256];
  gchar entrypoint_name[32];
  gchar data_string[256];

  pthread_t worker_thread;
};

struct _FridaFindLandingStripContext
{
  pid_t pid;
  gpointer result;
};

static gboolean frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, gpointer * result,
    GError ** error);

static void frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

static gboolean frida_attach_to_process (pid_t pid, regs_t * saved_regs, GError ** error);
static gboolean frida_detach_from_process (pid_t pid, const regs_t * saved_regs, GError ** error);

static gpointer frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error);
static int frida_remote_dealloc (pid_t pid, gpointer address, size_t size, GError ** error);
static gboolean frida_remote_write (pid_t pid, gpointer remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_exec (pid_t pid, gpointer remote_address, gpointer remote_stack, gpointer * result, GError ** error);

static gboolean frida_wait_for_child_signal (pid_t pid, int signal);

static gpointer frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name);

static gpointer frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name);
static gpointer frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path);

static gpointer frida_find_landing_strip (pid_t pid);

static gboolean frida_examine_range_for_landing_strip (const GumRangeDetails * details, gpointer user_data);

static FridaInjectionInstance *
frida_injection_instance_new (FridaLinjector * linjector, guint id, pid_t pid)
{
  FridaInjectionInstance * instance;
  int ret;

  instance = g_slice_new0 (FridaInjectionInstance);
  instance->linjector = g_object_ref (linjector);
  instance->id = id;
  instance->pid = pid;
  instance->fifo_path = g_strdup_printf ("/tmp/linjector-%d-%p-%d", getpid (), linjector, pid);
  ret = mkfifo (instance->fifo_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  g_assert_cmpint (ret, ==, 0);
  instance->fifo = open (instance->fifo_path, O_RDONLY | O_NONBLOCK);
  g_assert_cmpint (instance->fifo, !=, -1);

  return instance;
}

static void
frida_injection_instance_free (FridaInjectionInstance * instance)
{
  if (instance->remote_payload != NULL)
  {
    regs_t saved_regs;
    GError * error = NULL;

    if (frida_attach_to_process (instance->pid, &saved_regs, &error))
    {
      frida_remote_dealloc (instance->pid, instance->remote_payload, FRIDA_REMOTE_PAYLOAD_SIZE, &error);
      g_clear_error (&error);

      frida_detach_from_process (instance->pid, &saved_regs, &error);
    }

    g_clear_error (&error);
  }

  close (instance->fifo);
  unlink (instance->fifo_path);
  g_free (instance->fifo_path);
  g_object_unref (instance->linjector);
  g_slice_free (FridaInjectionInstance, instance);
}

GInputStream *
_frida_linjector_get_fifo_for_instance (FridaLinjector * self, void * instance)
{
  return g_unix_input_stream_new (((FridaInjectionInstance *) instance)->fifo, FALSE);
}

void
_frida_linjector_free_instance (FridaLinjector * self, void * instance)
{
  frida_injection_instance_free (instance);
}

guint
_frida_linjector_do_inject (FridaLinjector * self, guint pid, const char * so_path, const char * data_string,
    GError ** error)
{
  FridaInjectionInstance * instance;
  FridaInjectionParams params = { pid, so_path, data_string };
  regs_t saved_regs;

  instance = frida_injection_instance_new (self, self->last_id++, pid);

  if (!frida_attach_to_process (pid, &saved_regs, error))
    goto beach;

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, FRIDA_REMOTE_PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, error);
  if (params.remote_address == NULL)
    goto beach;
  instance->remote_payload = params.remote_address;

  if (!frida_emit_and_remote_execute (frida_emit_payload_code, &params, NULL, error))
    goto beach;

  if (!frida_detach_from_process (pid, &saved_regs, error))
    goto beach;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  return instance->id;

beach:
  {
    frida_injection_instance_free (instance);
    return 0;
  }
}

static gboolean
frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, gpointer * result,
    GError ** error)
{
  FridaCodeChunk code;
  guint padding = 0;
  FridaTrampolineData * data;

  code.cur = code.bytes;
  code.size = 0;

#if defined (HAVE_I386)
  {
    GumX86Writer cw;
    guint i;

    padding = 2;

    gum_x86_writer_init (&cw, code.cur);
    for (i = 0; i != padding; i++)
      gum_x86_writer_put_nop (&cw);
    gum_x86_writer_flush (&cw);
    code.cur = gum_x86_writer_cur (&cw);
    code.size += gum_x86_writer_offset (&cw);

    gum_x86_writer_free (&cw);
  }
#endif

  func (params, GUM_ADDRESS (params->remote_address), &code);

  data = (FridaTrampolineData *) (code.bytes + FRIDA_REMOTE_DATA_OFFSET);
  strcpy (data->pthread_so, "libpthread.so.0");
  strcpy (data->pthread_create, "pthread_create");
  strcpy (data->fifo_path, params->fifo_path);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, "frida_agent_main");
  strcpy (data->data_string, params->data_string);

  if (!frida_remote_write (params->pid, params->remote_address, code.bytes, FRIDA_REMOTE_DATA_OFFSET + sizeof (FridaTrampolineData), error))
    return FALSE;

  if (!frida_remote_exec (params->pid, params->remote_address + padding, params->remote_address + FRIDA_REMOTE_STACK_OFFSET, result, error))
    return FALSE;

  return TRUE;
}

#if defined (HAVE_I386)

static void
frida_x86_commit_code (GumX86Writer * cw, FridaCodeChunk * code)
{
  gum_x86_writer_flush (cw);
  code->cur = gum_x86_writer_cur (cw);
  code->size += gum_x86_writer_offset (cw);
}

static void
frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumX86Writer cw;
  const guint worker_offset = 128;

  gum_x86_writer_init (&cw, code->cur);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "__libc_dlopen_mode")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (pthread_so),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XBP, GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "__libc_dlsym")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_REGISTER, GUM_REG_XBP,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (pthread_create));

  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      4,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (worker_thread),
      GUM_ARG_POINTER, NULL,
      GUM_ARG_POINTER, remote_address + worker_offset,
      GUM_ARG_POINTER, NULL);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "__libc_dlclose")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_REGISTER, GUM_REG_XBP);

  gum_x86_writer_put_int3 (&cw);
  gum_x86_writer_flush (&cw);
  g_assert_cmpuint (gum_x86_writer_offset (&cw), <=, worker_offset);
  while (gum_x86_writer_offset (&cw) != worker_offset - code->size)
    gum_x86_writer_put_nop (&cw);
  frida_x86_commit_code (&cw, code);
  gum_x86_writer_free (&cw);

  gum_x86_writer_init (&cw, code->cur);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBP);
  /* NOTE: stack must be aligned on a 16 byte boundary */
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, 2 * sizeof (gpointer));

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "open")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (fifo_path),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (O_WRONLY));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_XSP, 0, GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "write")));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_XCX, GUM_REG_XSP, 0);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      3,
      GUM_ARG_REGISTER, GUM_REG_XCX,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (entrypoint_name),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (1));

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "__libc_dlopen_mode")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (so_path),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XBP, GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "__libc_dlsym")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_REGISTER, GUM_REG_XBP,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (entrypoint_name));

  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (data_string));

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "__libc_dlclose")));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_REGISTER, GUM_REG_XBP);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (frida_resolve_remote_libc_function (params->pid, "close")));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_XCX, GUM_REG_XSP, 0);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, 2 * sizeof (gpointer));
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  frida_x86_commit_code (&cw, code);
  gum_x86_writer_free (&cw);
}

#elif defined (HAVE_ARM)

static void
frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumThumbWriter cw;

  gum_thumb_writer_init (&cw, code->cur);

  gum_thumb_writer_put_breakpoint (&cw);

  gum_thumb_writer_free (&cw);
}

#endif

static gboolean
frida_attach_to_process (pid_t pid, regs_t * saved_regs, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  gboolean success;

  ret = ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_ATTACH");

  success = frida_wait_for_child_signal (pid, SIGSTOP);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_ATTACH wait");

  ret = ptrace (PTRACE_GETREGS, pid, NULL, saved_regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "attach_to_process %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_detach_from_process (pid_t pid, const regs_t * saved_regs, GError ** error)
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
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "detach_from_process %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gpointer
frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

  /* setup argument list for mmap and call it */
#if defined (HAVE_I386)
  regs.rip = GPOINTER_TO_SIZE (frida_resolve_remote_libc_function (pid, "mmap"));

  /* all six arguments in registers (SysV ABI) */
  regs.rdi = 0;
  regs.rsi = size;
  regs.rdx = prot;
  regs.rcx = MAP_PRIVATE | MAP_ANONYMOUS;
  regs.r8 = -1;
  regs.r9 = 0;

  regs.rax = 1337;

  regs.rsp -= 8;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.rsp, frida_find_landing_strip (pid));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (frida_resolve_remote_libc_function (pid, "mmap"));

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
  ret = ptrace (PTRACE_POKEDATA, pid, regs.ARM_sp, frida_find_landing_strip (pid));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, SIGTRAP);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386)
  g_assert (regs.rax != 1337);

  return GSIZE_TO_POINTER (regs.rax);
#elif defined (HAVE_ARM)
  return GSIZE_TO_POINTER (regs.ARM_ORIG_r0);
#endif

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_alloc %s failed: %d", failed_operation, errno);
    return NULL;
  }
}

static int
frida_remote_dealloc (pid_t pid, gpointer address, size_t size, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

  /* setup argument list for munmap and call it */
#if defined (HAVE_I386)
  regs.rip = GPOINTER_TO_SIZE (frida_resolve_remote_libc_function (pid, "munmap"));

  regs.rdi = GPOINTER_TO_SIZE (address);
  regs.rsi = size;

  regs.rax = 1337;

  regs.rsp -= 8;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.rsp, frida_find_landing_strip (pid));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (frida_resolve_remote_libc_function (pid, "munmap"));

  regs.ARM_r0 = GPOINTER_TO_SIZE (address);
  regs.ARM_r1 = size;

  regs.ARM_sp -= 4;
  ret = ptrace (PTRACE_POKEDATA, pid, regs.ARM_sp, frida_find_landing_strip (pid));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, SIGTRAP);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386)
  return regs.rax;
#elif defined (HAVE_ARM)
  return regs.ARM_ORIG_r0;
#endif

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_dealloc %s failed: %d", failed_operation, errno);
    return -1;
  }
}

static gboolean
frida_remote_write (pid_t pid, gpointer remote_address, gconstpointer data, gsize size, GError ** error)
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
    ret = ptrace (PTRACE_POKEDATA, pid, dst, *src);
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA head");

    dst++;
    src++;
  }

  remainder = size % sizeof (gsize);
  if (remainder != 0)
  {
    gsize word;

    memcpy (&word, src, remainder);

    ret = ptrace (PTRACE_POKEDATA, pid, dst, word);
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA tail");
  }

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_write %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_remote_exec (pid_t pid, gpointer remote_address, gpointer remote_stack, gpointer * result, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386)
  regs.rip = GPOINTER_TO_SIZE (remote_address);
  regs.rsp = GPOINTER_TO_SIZE (remote_stack);
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (remote_address);
  regs.ARM_sp = GPOINTER_TO_SIZE (remote_stack);
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, SIGTRAP);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  if (result != NULL)
  {
#if defined (HAVE_I386)
    *result = GSIZE_TO_POINTER (regs.rax);
#elif defined (HAVE_ARM)
    *result = GSIZE_TO_POINTER (regs.ARM_r0);
#endif
  }

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_exec %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_wait_for_child_signal (pid_t pid, int signal)
{
  int status;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || !WIFSTOPPED (status))
    return FALSE;

  return WSTOPSIG (status) == signal;
}

static gpointer
frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name)
{
  return frida_resolve_remote_library_function (remote_pid, "libc", function_name);
}

static gpointer
frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name)
{
  gchar * local_library_path, * remote_library_path;
  gpointer local_base, remote_base, module;
  gpointer local_address, remote_address;

  local_base = frida_find_library_base (getpid (), library_name, &local_library_path);
  g_assert (local_base != NULL);

  remote_base = frida_find_library_base (remote_pid, library_name, &remote_library_path);
  g_assert (remote_base != NULL);

  g_assert_cmpstr (local_library_path, ==, remote_library_path);

  module = dlopen (local_library_path, RTLD_GLOBAL | RTLD_NOW);
  g_assert (module != NULL);

  local_address = dlsym (module, function_name);
  g_assert (local_address != NULL);

  remote_address = remote_base + (local_address - local_base);

  dlclose (module);

  g_free (local_library_path);
  g_free (remote_library_path);

  return remote_address;
}

static gpointer
frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path)
{
  gpointer result = NULL;
  gchar * maps_path;
  FILE * fp;
  const guint line_size = 1024 + PATH_MAX;
  gchar * line, * path;

  *library_path = NULL;

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
    gchar * p;

    n = sscanf (line, "%p-%*p %*s %*x %*s %*s %s", &start, path);
    if (n == 1)
      continue;
    g_assert_cmpint (n, ==, 2);

    if (path[0] == '[')
      continue;

    p = strrchr (path, '/');
    if (p != NULL)
    {
      p++;
      if (g_str_has_prefix (p, library_name) && g_str_has_suffix (p, ".so"))
      {
        gchar next_char = p[strlen (library_name)];
        if (next_char == '-' || next_char == '.')
        {
          result = start;
          *library_path = g_strdup (path);
        }
      }
    }
  }

  g_free (path);
  g_free (line);

  fclose (fp);

  return result;
}

static gpointer
frida_find_landing_strip (pid_t pid)
{
  FridaFindLandingStripContext ctx;

  ctx.pid = pid;
  ctx.result = NULL;

  gum_linux_enumerate_ranges (pid, GUM_PAGE_RX, frida_examine_range_for_landing_strip, &ctx);

  return ctx.result;
}

static gboolean
frida_examine_range_for_landing_strip (const GumRangeDetails * details, gpointer user_data)
{
  FridaFindLandingStripContext * ctx = (FridaFindLandingStripContext *) user_data;
  const GumMemoryRange * range = details->range;
  const gsize * cur, * end;

  cur = GSIZE_TO_POINTER (range->base_address);
  end = GSIZE_TO_POINTER (range->base_address + ((range->size / sizeof (gsize)) * sizeof (gsize)));

  while (ctx->result == NULL && cur != end)
  {
    long ret;
    gsize val;

    ret = ptrace (PTRACE_PEEKDATA, ctx->pid, cur, NULL);
    if (ret == -1 && errno != 0)
      break;

    val = (gsize) ret;

#if defined (HAVE_I386)
# define GUM_X86_INSN_INT3 0xcc
    {
      guint i;

      for (i = 0; i != 8; i++)
      {
        if ((val & 0xff) == GUM_X86_INSN_INT3)
        {
          ctx->result = ((guint8 *) cur) + i;
          break;
        }

        val >>= 8;
      }
    }
#endif

    cur++;
  }

  return ctx->result == NULL;
}

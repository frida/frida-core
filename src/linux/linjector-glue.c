#include "frida-core.h"

#include <gio/gunixinputstream.h>
#ifdef HAVE_I386
# include <udis86.h>
# include <gum/arch-x86/gumx86writer.h>
#endif
#ifdef HAVE_ARM
# include <gum/arch-arm/gumarmwriter.h>
# include <gum/arch-arm/gumthumbwriter.h>
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
# include <sys/user.h>
#endif
#include <sys/wait.h>

#if defined (HAVE_I386)
# define FRIDA_SIGBKPT SIGTRAP
#elif defined (HAVE_ARM)
# define FRIDA_SIGBKPT SIGBUS
#endif
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
  GumAddress remote_payload;
};

struct _FridaInjectionParams
{
  pid_t pid;
  const char * so_path;
  const char * data_string;

  const char * fifo_path;
  GumAddress remote_address;
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
  GumAddress result;
};

static gboolean frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, GumAddress * result, GError ** error);

static void frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

static gboolean frida_attach_to_process (pid_t pid, regs_t * saved_regs, GError ** error);
static gboolean frida_detach_from_process (pid_t pid, const regs_t * saved_regs, GError ** error);

static GumAddress frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error);
static int frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error);
static gboolean frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, GError ** error);
static gboolean frida_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, GError ** error);

static gboolean frida_wait_for_attach_signal (pid_t pid);
static gboolean frida_wait_for_child_signal (pid_t pid, int signal);

static GumAddress frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name);
#ifdef HAVE_ANDROID
static GumAddress frida_resolve_remote_linker_function (int remote_pid, gpointer func);
#endif

static GumAddress frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name);
static GumAddress frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path);

static GumAddress frida_find_landing_strip (pid_t pid);

static gboolean frida_examine_range_for_landing_strip (const GumRangeDetails * details, gpointer user_data);

static FridaInjectionInstance *
frida_injection_instance_new (FridaLinjector * linjector, guint id, pid_t pid, const char * temp_path)
{
  FridaInjectionInstance * instance;
  int ret;

  instance = g_slice_new0 (FridaInjectionInstance);
  instance->linjector = g_object_ref (linjector);
  instance->id = id;
  instance->pid = pid;
  instance->fifo_path = g_strdup_printf ("%s/linjector-%d", temp_path, pid);
  ret = mkfifo (instance->fifo_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  g_assert_cmpint (ret, ==, 0);
  instance->fifo = open (instance->fifo_path, O_RDONLY | O_NONBLOCK);
  g_assert_cmpint (instance->fifo, !=, -1);

  return instance;
}

static void
frida_injection_instance_free (FridaInjectionInstance * instance)
{
  if (instance->remote_payload != 0)
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
    const char * temp_path, GError ** error)
{
  FridaInjectionInstance * instance;
  FridaInjectionParams params = { pid, so_path, data_string };
  regs_t saved_regs;

  instance = frida_injection_instance_new (self, self->last_id++, pid, temp_path);

  if (!frida_attach_to_process (pid, &saved_regs, error))
    goto beach;

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, FRIDA_REMOTE_PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, error);
  if (params.remote_address == 0)
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
frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, GumAddress * result,
    GError ** error)
{
  FridaCodeChunk code;
  guint padding = 0;
  GumAddress address_mask = 0;
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
#elif defined (HAVE_ARM)
  {
    GumThumbWriter cw;

    padding = 2;
    address_mask = 1;

    gum_thumb_writer_init (&cw, code.cur);
    gum_thumb_writer_put_nop (&cw);
    gum_thumb_writer_flush (&cw);
    code.cur = gum_thumb_writer_cur (&cw);
    code.size += gum_thumb_writer_offset (&cw);
    gum_thumb_writer_free (&cw);
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

  if (!frida_remote_exec (params->pid, (params->remote_address + padding) | address_mask, params->remote_address + FRIDA_REMOTE_STACK_OFFSET, result, error))
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
#ifdef HAVE_ANDROID
# error Not yet ported to Android/x86
#else
  GumX86Writer cw;
  const guint worker_offset = 128;

  gum_x86_writer_init (&cw, code->cur);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "__libc_dlopen_mode"));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (pthread_so),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XBP, GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "__libc_dlsym"));
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
      frida_resolve_remote_libc_function (params->pid, "__libc_dlclose"));
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
      frida_resolve_remote_libc_function (params->pid, "open"));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (fifo_path),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (O_WRONLY));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_XSP, 0, GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "write"));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_XCX, GUM_REG_XSP, 0);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      3,
      GUM_ARG_REGISTER, GUM_REG_XCX,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (entrypoint_name),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (1));

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "__libc_dlopen_mode"));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (so_path),
      GUM_ARG_POINTER, GSIZE_TO_POINTER (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XBP, GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "__libc_dlsym"));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      2,
      GUM_ARG_REGISTER, GUM_REG_XBP,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (entrypoint_name));

  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_POINTER, FRIDA_REMOTE_DATA_FIELD (data_string));

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "__libc_dlclose"));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_REGISTER, GUM_REG_XBP);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      frida_resolve_remote_libc_function (params->pid, "close"));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_XCX, GUM_REG_XSP, 0);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, 2 * sizeof (gpointer));
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  frida_x86_commit_code (&cw, code);
  gum_x86_writer_free (&cw);
#endif
}

#elif defined (HAVE_ARM)

static void
frida_arm_commit_code (GumThumbWriter * cw, FridaCodeChunk * code)
{
  gum_thumb_writer_flush (cw);
  code->cur = gum_thumb_writer_cur (cw);
  code->size += gum_thumb_writer_offset (cw);
}

static void
frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
#ifdef HAVE_ANDROID
  GumThumbWriter cw;
  const guint worker_offset = 64;

  gum_thumb_writer_init (&cw, code->cur);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "pthread_create"),
      4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      GUM_ARG_ADDRESS, remote_address + worker_offset + 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_thumb_writer_put_breakpoint (&cw);
  gum_thumb_writer_flush (&cw);
  g_assert_cmpuint (gum_thumb_writer_offset (&cw), <=, worker_offset);
  while (gum_thumb_writer_offset (&cw) != worker_offset - code->size)
    gum_thumb_writer_put_nop (&cw);
  frida_arm_commit_code (&cw, code);
  gum_thumb_writer_free (&cw);

  gum_thumb_writer_init (&cw, code->cur);

  gum_thumb_writer_put_push_regs (&cw, 4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_LR);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "open"),
      2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (O_WRONLY));
  gum_thumb_writer_put_mov_reg_reg (&cw, GUM_AREG_R7, GUM_AREG_R0);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "write"),
      3,
      GUM_ARG_REGISTER, GUM_AREG_R7,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (1));

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_linker_function (params->pid, dlopen),
      2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (so_path)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (RTLD_LAZY));
  gum_thumb_writer_put_mov_reg_reg (&cw, GUM_AREG_R6, GUM_AREG_R0);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_linker_function (params->pid, dlsym),
      2,
      GUM_ARG_REGISTER, GUM_AREG_R6,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  gum_thumb_writer_put_mov_reg_reg (&cw, GUM_AREG_R5, GUM_AREG_R0);

  gum_thumb_writer_put_call_reg_with_arguments (&cw,
      GUM_AREG_R5,
      1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (data_string)));

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_linker_function (params->pid, dlclose),
      1,
      GUM_ARG_REGISTER, GUM_AREG_R6);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "close"),
      1,
      GUM_ARG_REGISTER, GUM_AREG_R7);

  gum_thumb_writer_put_pop_regs (&cw, 4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_PC);

  frida_arm_commit_code (&cw, code);
  gum_thumb_writer_free (&cw);
#else
# error Not yet ported to Linux/ARM
#endif
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

  success = frida_wait_for_attach_signal (pid);
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

  ret = ptrace (PTRACE_SETREGS, pid, NULL, (void *) saved_regs);
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

static GumAddress
frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error)
{
  GumAddress args[] = {
    0,
    size,
    prot,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  };
  GumAddress retval = 0;

  frida_remote_call (pid, frida_resolve_remote_libc_function (pid, "mmap"), args, G_N_ELEMENTS (args), &retval, error);

  if (retval == GUM_ADDRESS (-1))
    return 0;

  return retval;
}

static int
frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error)
{
  GumAddress args[] = {
    address,
    size
  };
  GumAddress retval;

  if (!frida_remote_call (pid, frida_resolve_remote_libc_function (pid, "munmap"), args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static gboolean
frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  GumAddress dst;
  const gsize * src;
  long ret;
  const gchar * failed_operation;
  gsize remainder;

  dst = remote_address;
  src = data;

  while (dst < remote_address + size)
  {
    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (dst), GSIZE_TO_POINTER (*src));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA head");

    dst += sizeof (gsize);
    src++;
  }

  dst = remote_address + (size / sizeof (gsize));
  remainder = size % sizeof (gsize);
  if (remainder != 0)
  {
    gsize word;

    memcpy (&word, src, remainder);

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (dst), GSIZE_TO_POINTER (word));
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
frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  GumAddress return_address;
  gint i;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

  return_address = frida_find_landing_strip (pid);

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.eip = func;

  for (i = 0; i < args_length; i++)
  {
    regs.esp -= 4;

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.esp), GSIZE_TO_POINTER (args[i]));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
  }

  regs.rsp -= 4;
  ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.esp), GSIZE_TO_POINTER (return_address));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.rip = func;

  for (i = 0; i != args_length && i < 6; i++)
  {
    switch (i)
    {
      case 0:
        regs.rdi = args[i];
        break;
      case 1:
        regs.rsi = args[i];
        break;
      case 2:
        regs.rdx = args[i];
        break;
      case 3:
        regs.rcx = args[i];
        break;
      case 4:
        regs.r8 = args[i];
        break;
      case 5:
        regs.r9 = args[i];
        break;
      default:
        g_assert_not_reached ();
    }
  }

  for (i = args_length - 1; i >= 6; i--)
  {
    regs.rsp -= 8;

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.rsp), GSIZE_TO_POINTER (args[i]));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
  }

  regs.rsp -= 8;
  ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.rsp), GSIZE_TO_POINTER (return_address));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_ARM)
  if ((func & 1) != 0)
  {
    regs.ARM_pc = (func & ~1);
    regs.ARM_cpsr |= PSR_T_BIT;
  }
  else
  {
    regs.ARM_pc = func;
    regs.ARM_cpsr &= ~PSR_T_BIT;
  }

  for (i = 0; i < args_length && i < 4; i++)
  {
    regs.uregs[i] = args[i];
  }

  for (i = args_length - 1; i >= 4; i--)
  {
    regs.ARM_sp -= 4;

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.ARM_sp), GSIZE_TO_POINTER (args[i]));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
  }

  regs.ARM_lr = return_address;
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, FRIDA_SIGBKPT);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  *retval = regs.eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  *retval = regs.rax;
#elif defined (HAVE_ARM)
  *retval = regs.ARM_r0;
#endif

  return TRUE;

handle_os_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  regs_t regs;
  gboolean success;

  ret = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_GETREGS");

#if defined (HAVE_I386)
  regs.rip = remote_address;
  regs.rsp = remote_stack;
#elif defined (HAVE_ARM)
  if ((remote_address & 1) != 0)
  {
    regs.ARM_pc = (remote_address & ~1);
    regs.ARM_cpsr |= PSR_T_BIT;
  }
  else
  {
    regs.ARM_pc = remote_address;
    regs.ARM_cpsr &= ~PSR_T_BIT;
  }
  regs.ARM_sp = remote_stack;
#endif

  ret = ptrace (PTRACE_SETREGS, pid, NULL, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_SETREGS");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, FRIDA_SIGBKPT);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  if (result != NULL)
  {
#if defined (HAVE_I386)
    *result = regs.rax;
#elif defined (HAVE_ARM)
    *result = regs.ARM_r0;
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
frida_wait_for_attach_signal (pid_t pid)
{
  int status = 0;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || !WIFSTOPPED (status))
    return FALSE;

  switch (WSTOPSIG (status))
  {
    case SIGTRAP:
      if (ptrace (PTRACE_CONT, pid, NULL, NULL) != 0)
        return FALSE;
      if (!frida_wait_for_child_signal (pid, SIGSTOP))
        return FALSE;
      /* fall through */
    case SIGSTOP:
      if (frida_find_library_base (pid, "libc", NULL) == 0)
      {
        if (ptrace (PTRACE_CONT, pid, NULL, NULL) != 0)
          return FALSE;
        sleep (1);
        kill (pid, SIGSTOP);
        if (!frida_wait_for_child_signal (pid, SIGSTOP))
          return FALSE;
        return frida_find_library_base (pid, "libc", NULL) != 0;
      }
      return TRUE;
    default:
      break;
  }

  return FALSE;
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

static GumAddress
frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name)
{
  return frida_resolve_remote_library_function (remote_pid, "libc", function_name);
}

#ifdef HAVE_ANDROID

static GumAddress
frida_resolve_remote_linker_function (int remote_pid, gpointer func)
{
  const gchar * linker_path = "/system/bin/linker";
  GumAddress local_base, remote_base, remote_address;

  local_base = frida_find_library_base (getpid (), linker_path, NULL);
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (remote_pid, linker_path, NULL);
  g_assert (remote_base != 0);

  remote_address = remote_base + (GUM_ADDRESS (func) - local_base);

  return remote_address;
}

#endif

static GumAddress
frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name)
{
  gchar * local_library_path, * remote_library_path;
  GumAddress local_base, remote_base, remote_address;
  gpointer module, local_address;

  local_base = frida_find_library_base (getpid (), library_name, &local_library_path);
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (remote_pid, library_name, &remote_library_path);
  g_assert (remote_base != 0);

  g_assert_cmpstr (local_library_path, ==, remote_library_path);

  module = dlopen (local_library_path, RTLD_GLOBAL | RTLD_NOW);
  g_assert (module != NULL);

  local_address = dlsym (module, function_name);
  g_assert (local_address != NULL);

  remote_address = remote_base + (GUM_ADDRESS (local_address) - local_base);

  dlclose (module);

  g_free (local_library_path);
  g_free (remote_library_path);

  return remote_address;
}

static GumAddress
frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path)
{
  GumAddress result = 0;
  gchar * maps_path;
  FILE * fp;
  const guint line_size = 1024 + PATH_MAX;
  gchar * line, * path;

  if (library_path != NULL)
    *library_path = NULL;

  maps_path = g_strdup_printf ("/proc/%d/maps", pid);

  fp = fopen (maps_path, "r");
  g_assert (fp != NULL);

  g_free (maps_path);

  line = g_malloc (line_size);
  path = g_malloc (PATH_MAX);

  while (result == 0 && fgets (line, line_size, fp) != NULL)
  {
    guint64 start;
    gint n;

    n = sscanf (line, "%" G_GINT64_MODIFIER "x-%*x %*s %*x %*s %*s %s", &start, path);
    if (n == 1)
      continue;
    g_assert_cmpint (n, ==, 2);

    if (path[0] == '[')
      continue;

    if (strcmp (path, library_name) == 0)
    {
      result = start;
      if (library_path != NULL)
        *library_path = g_strdup (path);
    }
    else
    {
      gchar * p = strrchr (path, '/');
      if (p != NULL)
      {
        p++;

        if (g_str_has_prefix (p, library_name) && g_str_has_suffix (p, ".so"))
        {
          gchar next_char = p[strlen (library_name)];
          if (next_char == '-' || next_char == '.')
          {
            result = start;
            if (library_path != NULL)
              *library_path = g_strdup (path);
          }
        }
      }
    }
  }

  g_free (path);
  g_free (line);

  fclose (fp);

  return result;
}

static GumAddress
frida_find_landing_strip (pid_t pid)
{
  FridaFindLandingStripContext ctx;

  ctx.pid = pid;
  ctx.result = 0;

  gum_linux_enumerate_ranges (pid, GUM_PAGE_RX, frida_examine_range_for_landing_strip, &ctx);

  return ctx.result;
}

static gboolean
frida_examine_range_for_landing_strip (const GumRangeDetails * details, gpointer user_data)
{
  FridaFindLandingStripContext * ctx = (FridaFindLandingStripContext *) user_data;
  const GumMemoryRange * range = details->range;
  GumAddress cur, end;

  cur = range->base_address;
  end = range->base_address + range->size;

  while (ctx->result == 0 && cur < end)
  {
    long ret;
    gsize val;

    errno = 0;
    ret = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (cur), NULL);
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
          ctx->result = cur + i;
          break;
        }

        val >>= 8;
      }
    }
#elif defined (HAVE_ARM)
# define GUM_ARM_INSN_BKPT_T1 0xbe00
# define GUM_ARM_INSN_BKPT_A1 0x1200070
    {
      guint i;

      if ((val & 0xfff000f0) == GUM_ARM_INSN_BKPT_A1)
      {
        ctx->result = cur;
      }
      else
      {
        for (i = 0; i != 2; i++)
        {
          if ((val & 0xff00) == GUM_ARM_INSN_BKPT_T1)
          {
            ctx->result = cur + (i * 2) + 1;
            break;
          }

          val >>= 16;
        }
      }
    }
#endif

    cur += 4;
  }

  return ctx->result == 0;
}

#include "frida-core.h"

#include <gio/gunixinputstream.h>
#include <gum/arch-arm/gumarmwriter.h>
#include <gum/arch-arm/gumthumbwriter.h>
#include <gum/gum.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/states.h>
#include <sys/types.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#include <sys/wait.h>

enum {
  GUM_QNX_ARM_REG_PC = ARM_REG_PC,
  GUM_QNX_ARM_REG_LR = ARM_REG_LR,
  GUM_QNX_ARM_REG_SP = ARM_REG_SP,
  GUM_QNX_ARM_REG_R0 = ARM_REG_R0
};
#undef ARM_REG_R0
#undef ARM_REG_R1
#undef ARM_REG_R2
#undef ARM_REG_R3
#undef ARM_REG_R4
#undef ARM_REG_R5
#undef ARM_REG_R6
#undef ARM_REG_R7
#undef ARM_REG_R8
#undef ARM_REG_R9
#undef ARM_REG_R10
#undef ARM_REG_R11
#undef ARM_REG_R12
#undef ARM_REG_R13
#undef ARM_REG_R14
#undef ARM_REG_R15
#undef ARM_REG_SPSR
#undef ARM_REG_FP
#undef ARM_REG_IP
#undef ARM_REG_SP
#undef ARM_REG_LR
#undef ARM_REG_PC

#define PSR_T_BIT (1 << 5)

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

#define FRIDA_REMOTE_PAYLOAD_SIZE (8192)
#define FRIDA_REMOTE_DATA_OFFSET (512)
#define FRIDA_REMOTE_STACK_OFFSET (FRIDA_REMOTE_PAYLOAD_SIZE - 512)
#define FRIDA_REMOTE_DATA_FIELD(n) \
    GSIZE_TO_POINTER ((remote_address & 0xfffffffe) + FRIDA_REMOTE_DATA_OFFSET + G_STRUCT_OFFSET (FridaTrampolineData, n))

typedef struct _FridaInjectionInstance FridaInjectionInstance;
typedef struct _FridaInjectionParams FridaInjectionParams;
typedef struct _FridaCodeChunk FridaCodeChunk;
typedef struct _FridaTrampolineData FridaTrampolineData;
typedef struct _FridaFindLandingStripContext FridaFindLandingStripContext;

typedef void (* FridaEmitFunc) (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

struct _FridaInjectionInstance
{
  FridaQinjector * qinjector;
  guint id;
  pid_t pid;
  gboolean already_attached;
  gchar * fifo_path;
  gint fifo;
  GumAddress remote_payload;
};

struct _FridaInjectionParams
{
  pid_t pid;
  const gchar * so_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;

  const gchar * fifo_path;
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
  gchar entrypoint_name[256];
  gchar entrypoint_data[256];

  pthread_attr_t create_thread_attr;
  pthread_t worker_thread;
};

struct _FridaFindLandingStripContext
{
  pid_t pid;
  GumAddress result;
};

static gboolean frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, GumAddress * result, GError ** error);

static void frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

static GumAddress frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error);
static int frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error);
static int frida_remote_pthread_create (pid_t pid, GumAddress address, GError ** error);
static int frida_remote_msync (pid_t pid, GumAddress remote_address, gint size, gint flags, GError ** error);
static gboolean frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_write_fd (gint fd, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, GError ** error);

static GumAddress frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name);

static GumAddress frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name);
static GumAddress frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path);

static FridaInjectionInstance *
frida_injection_instance_new (FridaQinjector * qinjector, guint id, pid_t pid, const char * temp_path)
{
  FridaInjectionInstance * instance;
  const int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  int ret;

  instance = g_slice_new0 (FridaInjectionInstance);
  instance->qinjector = g_object_ref (qinjector);
  instance->id = id;
  instance->pid = pid;
  instance->already_attached = FALSE;
  instance->fifo_path = g_strdup_printf ("%s/qinjector-%d", temp_path, pid);
  ret = mkfifo (instance->fifo_path, mode);
  g_assert (ret == 0);
  ret = chmod (instance->fifo_path, mode);
  g_assert (ret == 0);
  instance->fifo = open (instance->fifo_path, O_RDONLY | O_NONBLOCK);
  g_assert (instance->fifo != -1);

  return instance;
}

static void
frida_injection_instance_free (FridaInjectionInstance * instance)
{
  if (instance->remote_payload != 0)
  {
    GError * error = NULL;

    frida_remote_dealloc (instance->pid, instance->remote_payload, FRIDA_REMOTE_PAYLOAD_SIZE, &error);

    g_clear_error (&error);
  }

  close (instance->fifo);
  unlink (instance->fifo_path);
  g_free (instance->fifo_path);
  g_object_unref (instance->qinjector);
  g_slice_free (FridaInjectionInstance, instance);
}

GInputStream *
_frida_qinjector_get_fifo_for_instance (FridaQinjector * self, void * instance)
{
  return g_unix_input_stream_new (((FridaInjectionInstance *) instance)->fifo, FALSE);
}

void
_frida_qinjector_free_instance (FridaQinjector * self, void * instance)
{
  frida_injection_instance_free (instance);
}

guint
_frida_qinjector_do_inject (FridaQinjector * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data,
    const gchar * temp_path, GError ** error)
{
  FridaInjectionInstance * instance;
  FridaInjectionParams params = { pid, path, entrypoint, data };

  instance = frida_injection_instance_new (self, self->next_instance_id++, pid, temp_path);

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, FRIDA_REMOTE_PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, error);
  if (params.remote_address == 0)
    goto beach;
  instance->remote_payload = params.remote_address;

  if (!frida_emit_and_remote_execute (frida_emit_payload_code, &params, NULL, error))
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
  FridaTrampolineData * data;

  code.cur = code.bytes;
  code.size = 0;

  func (params, GUM_ADDRESS (params->remote_address), &code);

  data = (FridaTrampolineData *) (code.bytes + FRIDA_REMOTE_DATA_OFFSET);
  strcpy (data->pthread_so, "libpthread.so.0");
  strcpy (data->pthread_create, "pthread_create");
  strcpy (data->fifo_path, params->fifo_path);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, params->entrypoint_name);
  strcpy (data->entrypoint_data, params->entrypoint_data);

  pthread_attr_init (&data->create_thread_attr);
  pthread_attr_setstacksize (&data->create_thread_attr, 2 * 1024 * 1024);

  if (!frida_remote_write (params->pid, params->remote_address, code.bytes, FRIDA_REMOTE_DATA_OFFSET + sizeof (FridaTrampolineData), error))
    return FALSE;

  /*
   * We need to flush the data cache and invalidate the instruction cache before
   * trying to run the generated code.
   */
  if (frida_remote_msync (params->pid, params->remote_address, FRIDA_REMOTE_PAYLOAD_SIZE, MS_SYNC | MS_INVALIDATE_ICACHE, error) != 0)
    return FALSE;

  if (frida_remote_pthread_create (params->pid, params->remote_address, error) != 0)
    return FALSE;

  return TRUE;
}

static void
frida_thumb_commit_code (GumThumbWriter * cw, FridaCodeChunk * code)
{
  gum_thumb_writer_flush (cw);
  code->cur = gum_thumb_writer_cur (cw);
  code->size += gum_thumb_writer_offset (cw);
}

static void
frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumThumbWriter cw;
  GumArmWriter caw;
  const guint worker_offset = 64;

  /*
   * We need a 'thunk' to transfer from arm mode to thumb mode as pthread_create
   * is being unpleasant about starting a thumb address.
   */
  gum_arm_writer_init (&caw, code->cur);

  gum_arm_writer_put_ldr_reg_u32 (&caw, ARM_REG_PC, (params->remote_address + worker_offset) | 1);
  while (gum_arm_writer_offset (&caw) != worker_offset - code->size - 4)
    gum_arm_writer_put_nop (&caw);

  gum_arm_writer_flush (&caw);
  code->cur = gum_arm_writer_cur (&caw);
  code->size += gum_arm_writer_offset (&caw);
  gum_arm_writer_clear (&caw);

  /*
   * The actual (thumb) payload starts here:
   */
  gum_thumb_writer_init (&cw, code->cur);

  gum_thumb_writer_put_push_regs (&cw, 4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "open"),
      2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (O_WRONLY));
  gum_thumb_writer_put_mov_reg_reg (&cw, ARM_REG_R7, ARM_REG_R0);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "write"),
      3,
      GUM_ARG_REGISTER, ARM_REG_R7,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (1));

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "dlopen"),
      2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (so_path)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (RTLD_LAZY));
  gum_thumb_writer_put_mov_reg_reg (&cw, ARM_REG_R6, ARM_REG_R0);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "dlsym"),
      2,
      GUM_ARG_REGISTER, ARM_REG_R6,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  gum_thumb_writer_put_mov_reg_reg (&cw, ARM_REG_R5, ARM_REG_R0);

  gum_thumb_writer_put_call_reg_with_arguments (&cw,
      ARM_REG_R5,
      3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "dlclose"),
      1,
      GUM_ARG_REGISTER, ARM_REG_R6);

  gum_thumb_writer_put_call_address_with_arguments (&cw,
      frida_resolve_remote_libc_function (params->pid, "close"),
      1,
      GUM_ARG_REGISTER, ARM_REG_R7);

  gum_thumb_writer_put_pop_regs (&cw, 4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);

  frida_thumb_commit_code (&cw, code);
  gum_thumb_writer_clear (&cw);
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
  GumAddress function = frida_resolve_remote_libc_function (pid, "mmap");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_alloc failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }


  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return 0;

  if (retval == G_GUINT64_CONSTANT (0xffffffffffffffff))
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
  GumAddress function = frida_resolve_remote_libc_function (pid, "munmap");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_dealloc failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static int
frida_remote_pthread_create (pid_t pid, GumAddress remote_address, GError ** error)
{
  GumAddress args[] = {
    GPOINTER_TO_SIZE (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
    GPOINTER_TO_SIZE (FRIDA_REMOTE_DATA_FIELD (create_thread_attr)),
    remote_address,
    0
  };
  GumAddress retval;
  GumAddress function = frida_resolve_remote_libc_function (pid, "pthread_create");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_pthread_create failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static int
frida_remote_msync (pid_t pid, GumAddress remote_address, gint size, gint flags, GError ** error)
{
  GumAddress args[] = {
    remote_address,
    size,
    flags
  };
  GumAddress retval;
  GumAddress function = frida_resolve_remote_libc_function (pid, "msync");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_msync failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static gboolean
frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  gint fd;
  gchar as_path[PATH_MAX];
  gboolean result;

  sprintf (as_path, "/proc/%d/as", pid);
  fd = open (as_path, O_RDWR);
  if (fd == -1)
    return FALSE;

  result = frida_remote_write_fd (fd, remote_address, data, size, error);

  close (fd);

  return result;
}

static gboolean
frida_remote_write_fd (gint fd, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  long ret;
  const gchar * failed_operation;

  ret = lseek (fd, GPOINTER_TO_SIZE (remote_address), SEEK_SET);
  CHECK_OS_RESULT (ret, ==, remote_address, "seek to address");

  ret = write (fd, data, size);
  CHECK_OS_RESULT (ret, ==, size, "write data");

  return TRUE;

os_failure:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_write %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, GError ** error)
{
  gboolean success = FALSE;
  gint ret;
  const gchar * failed_operation;
  gint fd;
  gint i;
  gchar as_path[PATH_MAX];
  pthread_t tid;
  debug_thread_t thread;
  procfs_greg saved_registers, modified_registers;
  procfs_status status;
  procfs_run run;
  sigset_t * run_fault = (sigset_t *) &run.fault;

  sprintf (as_path, "/proc/%d/as", pid);
  fd = open (as_path, O_RDWR);
  if (fd == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call failed to open process %d, errno: %d", pid, errno);
    return FALSE;
  }

  /*
   * Find the first active thread:
   */
  for (tid = 1;; tid++)
  {
    thread.tid = tid;
    if (devctl (fd, DCMD_PROC_TIDSTATUS, &thread, sizeof (thread), 0) == EOK)
      break;
  }

  /*
   * Set current thread and freeze our target thread:
   */
  ret = devctl (fd, DCMD_PROC_CURTHREAD, &tid, sizeof (tid), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_CURTHREAD");

  ret = devctl (fd, DCMD_PROC_STOP, &status, sizeof (status), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_STOP");

  if (status.state == STATE_DEAD)
    goto beach;

  if (status.state != STATE_STOPPED)
  {
    /*
     * If the thread was not in the STOPPED state, it's probably
     * blocked in a NANOSLEEP or some syscall. We'll SIGHUP
     * it to kick it out of the blocker and WAITSTOP until the
     * signal is delivered.
     */
    memset (&run, 0, sizeof (run));
    run.flags |= _DEBUG_RUN_TRACE;
    sigemptyset (&run.trace);
    sigaddset (&run.trace, SIGHUP);
    ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_RUN");

    kill (pid, SIGHUP);

    ret = devctl (fd, DCMD_PROC_WAITSTOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_WAITSTOP");
    if (status.why == _DEBUG_WHY_TERMINATED)
      goto beach;

    /*
     * We need the extra PROC_STOP because status.state is not
     * properly reported by WAITSTOP.
     */
    ret = devctl (fd, DCMD_PROC_STOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_STOP");
  }

  /*
   * Get the thread's registers:
   */
  ret = devctl (fd, DCMD_PROC_GETGREG, &saved_registers, sizeof (saved_registers), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_GETGREG");

  memcpy (&modified_registers, &saved_registers, sizeof (saved_registers));

  /*
   * Set the PC to be the function address and SP to the stack address.
   */
  if ((func & 1) != 0)
  {
    modified_registers.arm.gpr[GUM_QNX_ARM_REG_PC] = (func & ~1);
    modified_registers.arm.spsr |= PSR_T_BIT;
  }
  else
  {
    modified_registers.arm.gpr[GUM_QNX_ARM_REG_PC] = func;
    modified_registers.arm.spsr &= ~PSR_T_BIT;
  }

  for (i = 0; i < args_length && i < 4; i++)
  {
    modified_registers.arm.gpr[i] = args[i];
  }

  for (i = args_length - 1; i >= 4; i--)
  {
    modified_registers.arm.gpr[GUM_QNX_ARM_REG_SP] -= 4;

    if (!frida_remote_write_fd (fd, modified_registers.arm.gpr[GUM_QNX_ARM_REG_SP], &args[i],
        4, error))
      goto beach;
  }

  /*
   * Set the LR to be a dummy address which will trigger a pagefault.
   */
  modified_registers.arm.gpr[GUM_QNX_ARM_REG_LR] = 0xfffffff0;

  ret = devctl (fd, DCMD_PROC_SETGREG, &modified_registers, sizeof (modified_registers), 0);
  CHECK_OS_RESULT (ret, ==, 0, "DCMD_PROC_SETGREG");

  while (modified_registers.arm.gpr[GUM_QNX_ARM_REG_PC] != 0xfffffff0)
  {
    /*
     * Continue the process, watching for FLTPAGE which should trigger when
     * the dummy LR value (0xfffffff0) is reached.
     */
    memset (&run, 0, sizeof (run));
    sigemptyset (run_fault);
    sigaddset (run_fault, FLTPAGE);
    run.flags |= _DEBUG_RUN_FAULT | _DEBUG_RUN_CLRFLT | _DEBUG_RUN_CLRSIG;
    ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
    CHECK_OS_RESULT (ret, ==, 0, "DCMD_PROC_RUN");

    /*
     * Wait for the process to stop at the fault.
     */
    ret = devctl (fd, DCMD_PROC_WAITSTOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_WAITSTOP");

    /*
     * Get the thread's registers:
     */
    ret = devctl (fd, DCMD_PROC_GETGREG, &modified_registers,
        sizeof (modified_registers), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_GETGREG");
  }

  if (retval != NULL)
    *retval = modified_registers.arm.gpr[GUM_QNX_ARM_REG_R0];

  /*
   * Restore the registers and continue the process:
   */
  ret = devctl (fd, DCMD_PROC_SETGREG, &saved_registers, sizeof (saved_registers), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_SETGREG");

  memset (&run, 0, sizeof (run));
  run.flags |= _DEBUG_RUN_CLRFLT | _DEBUG_RUN_CLRSIG;
  ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_RUN");

  success = TRUE;

beach:
  close (fd);

  return success;

os_failure:
  {
    if (fd != -1)
      close (fd);
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static GumAddress
frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name)
{
  return frida_resolve_remote_library_function (remote_pid, "libc", function_name);
}

static GumAddress
frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name)
{
  gchar * local_library_path, * remote_library_path, * canonical_library_name;
  GumAddress local_base, remote_base, remote_address;
  gpointer module, local_address;

  local_base = frida_find_library_base (getpid (), library_name, &local_library_path);
  if (local_base == -1)
    return -1;
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (remote_pid, library_name, &remote_library_path);
  if (remote_base == -1)
    return -1;
  g_assert (remote_base != 0);

  g_assert (g_strcmp0 (local_library_path, remote_library_path) == 0);

  canonical_library_name = g_path_get_basename (local_library_path);

  module = dlopen (canonical_library_name, RTLD_GLOBAL | RTLD_LAZY);
  g_assert (module != NULL);

  local_address = dlsym (module, function_name);
  g_assert (local_address != NULL);

  remote_address = remote_base + (GUM_ADDRESS (local_address) - local_base);

  dlclose (module);

  g_free (local_library_path);
  g_free (remote_library_path);
  g_free (canonical_library_name);

  return remote_address;
}

static GumAddress
frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path)
{
  GumAddress result = 0;
  gchar * as_path;
  int fd, res;
  procfs_mapinfo * mapinfos;
  gint num_mapinfos;
  procfs_debuginfo * debuginfo;
  gint i;
  gchar * path;

  if (library_path != NULL)
    *library_path = NULL;

  as_path = g_strdup_printf ("/proc/%d/as", pid);

  fd = open (as_path, O_RDONLY);

  g_free (as_path);

  if (fd == -1)
    return -1;

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  g_assert (res == 0);

  mapinfos = g_malloc (num_mapinfos * sizeof (procfs_mapinfo));
  debuginfo = g_malloc (sizeof (procfs_debuginfo) + 0x100);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      num_mapinfos * sizeof (procfs_mapinfo), &num_mapinfos);
  g_assert (res == 0);

  for (i = 0; i != num_mapinfos; i++)
  {
    debuginfo->vaddr = mapinfos[i].vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo,
        sizeof (procfs_debuginfo) + 0x100, NULL);
    g_assert (res == 0);
    path = debuginfo->path;

    if (strcmp (path, library_name) == 0)
    {
      result = mapinfos[i].vaddr;
      if (library_path != NULL)
        *library_path = g_strdup (path);
    }
    else
    {
      gchar * p = strrchr (path, '/');
      if (p != NULL)
      {
        p++;

        gchar * s = strrchr (p, '.');
        gboolean has_numeric_suffix = FALSE;
        if (s != NULL && g_ascii_isdigit (*(s + 1)))
        {
          has_numeric_suffix = TRUE;
          *s = '\0';
        }
        if (g_str_has_prefix (p, library_name) && g_str_has_suffix (p, ".so"))
        {
          gchar next_char = p[strlen (library_name)];
          if (next_char == '-' || next_char == '.')
          {
            result = mapinfos[i].vaddr;
            if (library_path != NULL)
            {
              if (has_numeric_suffix)
                *s = '.';
              *library_path = g_strdup (path);
              break;
            }
          }
        }
      }
    }
  }

  close (fd);
  g_free (mapinfos);
  g_free (debuginfo);

  return result;
}

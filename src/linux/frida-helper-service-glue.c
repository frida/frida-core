#include "frida-helper-service.h"

#include <gio/gunixinputstream.h>
#include <glib-unix.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#endif
#ifdef HAVE_ARM
# include <gum/arch-arm/gumarmwriter.h>
# include <gum/arch-arm/gumthumbwriter.h>
#endif
#ifdef HAVE_ARM64
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#ifdef HAVE_MIPS
# include <gum/arch-mips/gummipswriter.h>
#endif
#include <gum/gum.h>
#include <gum/gumlinux.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#ifdef HAVE_ANDROID
# include <selinux/selinux.h>
# include <sys/system_properties.h>
#endif
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#ifdef HAVE_ARM
# include <asm/ptrace.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#include <sys/wait.h>

#define FRIDA_STACK_ALIGNMENT 16
#define FRIDA_RED_ZONE_SIZE 128
#define FRIDA_OFFSET_E_ENTRY 0x18
#define FRIDA_RTLD_DLOPEN (0x80000000)
#if GLIB_SIZEOF_VOID_P == 8
# define FRIDA_MAP_FAILED G_MAXUINT64
#else
# define FRIDA_MAP_FAILED G_MAXUINT32
#endif

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_os_error; \
  }

#ifndef PTRACE_GETREGS
# define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_SETREGS
# define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
# define PTRACE_SETREGSET 0x4205
#endif
#ifndef NT_PRSTATUS
# define NT_PRSTATUS 1
#endif

#if defined (HAVE_I386)
# define FridaRegs struct user_regs_struct
#elif defined (HAVE_ARM)
# define FridaRegs struct pt_regs
#elif defined (HAVE_ARM64)
# define FridaRegs struct user_pt_regs
#elif defined (HAVE_MIPS)
typedef struct _FridaRegs FridaRegs;

struct _FridaRegs
{
  guint64 zero;
  guint64 at;
  guint64 v0;
  guint64 v1;
  guint64 a0;
  guint64 a1;
  guint64 a2;
  guint64 a3;
  guint64 t0;
  guint64 t1;
  guint64 t2;
  guint64 t3;
  guint64 t4;
  guint64 t5;
  guint64 t6;
  guint64 t7;
  guint64 s0;
  guint64 s1;
  guint64 s2;
  guint64 s3;
  guint64 s4;
  guint64 s5;
  guint64 s6;
  guint64 s7;
  guint64 t8;
  guint64 t9;
  guint64 k0;
  guint64 k1;
  guint64 gp;
  guint64 sp;
  guint64 fp;
  guint64 ra;

  guint64 lo;
  guint64 hi;

  guint64 pc;
  guint64 badvaddr;
  guint64 status;
  guint64 cause;

  guint64 __padding[8];
};
#else
# error Unsupported architecture
#endif

#define FRIDA_REMOTE_DATA_FIELD(n) \
    (remote_address + params->data.offset + G_STRUCT_OFFSET (FridaTrampolineData, n))

#define FRIDA_DUMMY_RETURN_ADDRESS 0x320

typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaInjectInstance FridaInjectInstance;
typedef struct _FridaInjectParams FridaInjectParams;
typedef struct _FridaInjectRegion FridaInjectRegion;
typedef struct _FridaCodeChunk FridaCodeChunk;
typedef struct _FridaTrampolineData FridaTrampolineData;
typedef struct _FridaProbeElfContext FridaProbeElfContext;

typedef void (* FridaInjectEmitFunc) (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code);

struct _FridaSpawnInstance
{
  pid_t pid;

  FridaHelperService * service;
};

struct _FridaInjectInstance
{
  guint id;

  pid_t pid;
  gboolean already_attached;

  gchar * temp_path;

  gchar * fifo_path;
  gint fifo;

  GumAddress remote_payload;
  guint remote_size;
  GumAddress entrypoint;
  GumAddress stack_top;
  GumAddress trampoline_data;

  FridaHelperService * service;
};

struct _FridaInjectRegion
{
  guint offset;
  guint size;
};

struct _FridaInjectParams
{
  pid_t pid;
  const gchar * so_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;

  const gchar * fifo_path;

  FridaInjectRegion code;
  FridaInjectRegion data;
  FridaInjectRegion guard;
  FridaInjectRegion stack;

  GumAddress remote_address;
  guint remote_size;

  GumAddress open_impl;
  GumAddress close_impl;
  GumAddress write_impl;
  GumAddress syscall_impl;

  GumAddress dlopen_impl;
  GumAddress dlopen_pic_value;
  GumAddress dlclose_impl;
  GumAddress dlsym_impl;
};

struct _FridaCodeChunk
{
  guint8 * cur;
  gsize size;
};

struct _FridaTrampolineData
{
  gchar pthread_so_string[32];
  gchar pthread_create_string[32];
  gchar pthread_detach_string[32];
  gchar fifo_path[256];
  gchar so_path[256];
  gchar entrypoint_name[256];
  gchar entrypoint_data[256];
  guint8 hello_byte;

  gpointer pthread_so;
  pthread_t worker_thread;
  gpointer module_handle;
};

struct _FridaProbeElfContext
{
  pid_t pid;
  gchar path[PATH_MAX + 1];
  GumAddress entry_point;
  gsize word_size;
};

static guint frida_helper_service_generate_id (FridaHelperService * self);

static FridaSpawnInstance * frida_spawn_instance_new (FridaHelperService * service);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static void frida_make_pipe (int fds[2]);

static FridaInjectInstance * frida_inject_instance_new (FridaHelperService * service, guint id, pid_t pid, const gchar * temp_path);
static FridaInjectInstance * frida_inject_instance_clone (const FridaInjectInstance * instance, guint id);
static void frida_inject_instance_init_fifo (FridaInjectInstance * self);
static void frida_inject_instance_free (FridaInjectInstance * instance, FridaUnloadPolicy unload_policy);
static gboolean frida_inject_instance_attach (FridaInjectInstance * self, FridaRegs * saved_regs, GError ** error);
static gboolean frida_inject_instance_detach (FridaInjectInstance * self, const FridaRegs * saved_regs, GError ** error);
static gboolean frida_inject_instance_start_remote_thread (FridaInjectInstance * self, gboolean * exited, GError ** error);
static gboolean frida_inject_instance_emit_and_transfer_payload (FridaInjectEmitFunc func, const FridaInjectParams * params, GumAddress * entrypoint, GError ** error);
static void frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code);

static gboolean frida_wait_for_attach_signal (pid_t pid);
static gboolean frida_wait_for_child_signal (pid_t pid, int signal, gboolean * exited);
static gint frida_get_regs (pid_t pid, FridaRegs * regs);
static gint frida_set_regs (pid_t pid, const FridaRegs * regs);

static gboolean frida_run_to_entry_point (pid_t pid, GError ** error);
static gboolean frida_examine_range_for_elf_header (const GumRangeDetails * details, gpointer user_data);

static GumAddress frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error);
static gboolean frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error);
static gboolean frida_remote_mprotect (pid_t pid, GumAddress address, size_t size, int prot, GError ** error);
static gboolean frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, gboolean * exited, GError ** error);
static gboolean frida_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, gboolean * exited, GError ** error);

static GumAddress frida_resolve_libc_function (pid_t pid, const gchar * function_name);
static GumAddress frida_find_libc_base (pid_t pid);
#if defined (HAVE_ANDROID) || defined (HAVE_UCLIBC)
static GumAddress frida_resolve_linker_address (pid_t pid, gpointer func);
#endif
#if defined (HAVE_ANDROID)
static GumAddress frida_resolve_inner_dlopen (pid_t pid, GumAddress * pic_value);
static guint frida_get_android_api_level (void);
#endif
static GumAddress frida_resolve_library_function (pid_t pid, const gchar * library_name, const gchar * function_name);
static GumAddress frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path);

static gboolean frida_is_regset_supported = TRUE;

guint
_frida_helper_service_do_spawn (FridaHelperService * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, FridaStdioPipes ** pipes, GError ** error)
{
  FridaSpawnInstance * instance;
  int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
  int status;
  long ret;
  gboolean success;
  const gchar * failed_operation;

  instance = frida_spawn_instance_new (self);

  frida_make_pipe (stdin_pipe);
  frida_make_pipe (stdout_pipe);
  frida_make_pipe (stderr_pipe);

  *pipes = frida_stdio_pipes_new (stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);

  instance->pid = fork ();
  if (instance->pid == 0)
  {
    setsid ();

    dup2 (stdin_pipe[0], 0);
    dup2 (stdout_pipe[1], 1);
    dup2 (stderr_pipe[1], 2);

    ptrace (PTRACE_TRACEME, 0, NULL, NULL);
    kill (getpid (), SIGSTOP);
    if (execve (path, argv, envp) == -1)
    {
      g_printerr ("Unexpected error while spawning process (execve failed: %s)\n",
          g_strerror (errno));
      abort ();
    }
  }

  close (stdin_pipe[0]);
  close (stdout_pipe[1]);
  close (stderr_pipe[1]);

  waitpid (instance->pid, &status, 0);

  ret = ptrace (PTRACE_CONT, instance->pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (instance->pid, SIGTRAP, NULL);
  CHECK_OS_RESULT (success, !=, FALSE, "wait(SIGTRAP)");

  if (!frida_run_to_entry_point (instance->pid, error))
    goto error_epilogue;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instance_by_pid), GUINT_TO_POINTER (instance->pid), instance);

  return instance->pid;

handle_os_error:
  {
    (void) failed_operation;
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to spawn executable at '%s'",
        path);
    goto error_epilogue;
  }
error_epilogue:
  {
    frida_spawn_instance_free (instance);
    return 0;
  }
}

void
_frida_helper_service_resume_spawn_instance (FridaHelperService * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_helper_service_free_spawn_instance (FridaHelperService * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

guint
_frida_helper_service_do_inject (FridaHelperService * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, const gchar * temp_path, GError ** error)
{
  FridaInjectInstance * instance;
  FridaInjectParams params;
  guint offset, page_size;
  FridaRegs saved_regs;
  gboolean exited;

  params.pid = pid;
  params.so_path = path;
  params.entrypoint_name = entrypoint;
  params.entrypoint_data = data;

  params.fifo_path = NULL;

  offset = 0;
  page_size = gum_query_page_size ();

  params.code.offset = offset;
  params.code.size = page_size;
  offset += params.code.size;

  params.data.offset = offset;
  params.data.size = page_size;
  offset += params.data.size;

  params.guard.offset = offset;
  params.guard.size = page_size;
  offset += params.guard.size;

  params.stack.offset = offset;
  params.stack.size = page_size;
  offset += params.stack.size;

  params.remote_address = 0;
  params.remote_size = offset;

  params.open_impl = frida_resolve_libc_function (pid, "open");
  params.close_impl = frida_resolve_libc_function (pid, "close");
  params.write_impl = frida_resolve_libc_function (pid, "write");
  params.syscall_impl = frida_resolve_libc_function (pid, "syscall");

#if defined (HAVE_GLIBC)
  params.dlopen_impl = frida_resolve_libc_function (pid, "__libc_dlopen_mode");
  params.dlopen_pic_value = 0;
  params.dlclose_impl = frida_resolve_libc_function (pid, "__libc_dlclose");
  params.dlsym_impl = frida_resolve_libc_function (pid, "__libc_dlsym");
#elif defined (HAVE_UCLIBC)
  params.dlopen_impl = frida_resolve_linker_address (params->pid, dlopen);
  params.dlopen_pic_value = 0;
  params.dlclose_impl = frida_resolve_linker_address (params->pid, dlclose);
  params.dlsym_impl = frida_resolve_linker_address (params->pid, dlsym);
#elif defined (HAVE_ANDROID)
  params.dlopen_impl = frida_resolve_inner_dlopen (pid, &params.dlopen_pic_value);
  params.dlclose_impl = frida_resolve_linker_address (pid, dlclose);
  params.dlsym_impl = frida_resolve_linker_address (pid, dlsym);
#endif

  instance = frida_inject_instance_new (self, frida_helper_service_generate_id (self), pid, temp_path);

  if (!frida_inject_instance_attach (instance, &saved_regs, error))
    goto beach;

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, params.remote_size, PROT_READ | PROT_WRITE, error);
  if (params.remote_address == 0)
    goto beach;
  instance->remote_payload = params.remote_address;
  instance->remote_size = params.remote_size;

  if (!frida_inject_instance_emit_and_transfer_payload (frida_inject_instance_emit_payload_code, &params, &instance->entrypoint, error))
    goto beach;
  instance->stack_top = params.remote_address + params.stack.offset + params.stack.size;
  instance->trampoline_data = params.remote_address + params.data.offset;

  if (!frida_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto beach;

  if (!exited)
    frida_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  return instance->id;

beach:
  {
    frida_inject_instance_free (instance, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return 0;
  }
}

guint
_frida_helper_service_demonitor_and_clone_injectee_state (FridaHelperService * self, void * raw_instance)
{
  FridaInjectInstance * instance = raw_instance;
  FridaInjectInstance * clone;

  clone = frida_inject_instance_clone (instance, frida_helper_service_generate_id (self));

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (clone->id), clone);

  return clone->id;
}

void
_frida_helper_service_recreate_injectee_thread (FridaHelperService * self, void * raw_instance, guint pid, GError ** error)
{
  FridaInjectInstance * instance = raw_instance;
  gboolean is_uninitialized_clone;
  FridaRegs saved_regs;
  gboolean exited;

  is_uninitialized_clone = instance->pid == 0;

  instance->pid = pid;

  if (!frida_inject_instance_attach (instance, &saved_regs, error))
    goto handle_error;

  if (is_uninitialized_clone)
  {
    if (!frida_remote_write (instance->pid, instance->trampoline_data + G_STRUCT_OFFSET (FridaTrampolineData, fifo_path),
        instance->fifo_path, strlen (instance->fifo_path) + 1, error))
      goto handle_error;
  }

  if (!frida_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto handle_error;

  if (!exited)
    frida_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  return;

handle_error:
  {
    _frida_helper_service_destroy_inject_instance (self, instance->id, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}

static guint
frida_helper_service_generate_id (FridaHelperService * self)
{
  guint id;

  if (self->next_id == 0 || self->next_id >= G_MAXINT)
  {
    /* Avoid ID collisions when running one helper for 32-bit and one for 64-bit targets */
    self->next_id = (GLIB_SIZEOF_VOID_P == 4) ? 1 : 2;
  }
  id = self->next_id;
  self->next_id += 2;

  return id;
}

GInputStream *
_frida_helper_service_get_fifo_for_inject_instance (FridaHelperService * self, void * instance)
{
  return g_unix_input_stream_new (((FridaInjectInstance *) instance)->fifo, FALSE);
}

void
_frida_helper_service_free_inject_instance (FridaHelperService * self, void * instance, FridaUnloadPolicy unload_policy)
{
  frida_inject_instance_free (instance, unload_policy);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaHelperService * service)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
  instance->service = g_object_ref (service);

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  g_object_unref (instance->service);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  ptrace (PTRACE_DETACH, self->pid, NULL, NULL);
}

static void
frida_make_pipe (int fds[2])
{
  gboolean pipe_opened;

  pipe_opened = g_unix_open_pipe (fds, FD_CLOEXEC, NULL);
  g_assert (pipe_opened);
}

static FridaInjectInstance *
frida_inject_instance_new (FridaHelperService * service, guint id, pid_t pid, const gchar * temp_path)
{
  FridaInjectInstance * instance;

  instance = g_slice_new0 (FridaInjectInstance);
  instance->id = id;

  instance->pid = pid;
  instance->already_attached = FALSE;

  instance->temp_path = g_strdup (temp_path);

  frida_inject_instance_init_fifo (instance);

  instance->service = g_object_ref (service);

  return instance;
}

static FridaInjectInstance *
frida_inject_instance_clone (const FridaInjectInstance * instance, guint id)
{
  FridaInjectInstance * clone;

  clone = g_slice_dup (FridaInjectInstance, instance);
  clone->id = id;

  clone->pid = 0;
  clone->already_attached = FALSE;

  clone->temp_path = g_strdup (instance->temp_path);

  frida_inject_instance_init_fifo (clone);

  g_object_ref (clone->service);

  return clone;
}

static void
frida_inject_instance_init_fifo (FridaInjectInstance * self)
{
  const int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  int ret;

  self->fifo_path = g_strdup_printf ("%s/linjector-%u", self->temp_path, self->id);

  ret = mkfifo (self->fifo_path, mode);
  g_assert_cmpint (ret, ==, 0);

  ret = chmod (self->fifo_path, mode);
  g_assert_cmpint (ret, ==, 0);

#ifdef HAVE_ANDROID
  setfilecon (self->fifo_path, "u:object_r:frida_file:s0");
#endif

  self->fifo = open (self->fifo_path, O_RDONLY | O_NONBLOCK);
  g_assert (self->fifo != -1);
}

static void
frida_inject_instance_free (FridaInjectInstance * instance, FridaUnloadPolicy unload_policy)
{
  if (instance->pid != 0 && instance->remote_payload != 0 && unload_policy == FRIDA_UNLOAD_POLICY_IMMEDIATE)
  {
    FridaRegs saved_regs;

    if (frida_inject_instance_attach (instance, &saved_regs, NULL))
    {
      frida_remote_dealloc (instance->pid, instance->remote_payload, instance->remote_size, NULL);
      frida_inject_instance_detach (instance, &saved_regs, NULL);
    }
  }

  close (instance->fifo);
  unlink (instance->fifo_path);
  g_free (instance->fifo_path);

  g_free (instance->temp_path);

  g_object_unref (instance->service);

  g_slice_free (FridaInjectInstance, instance);
}

static gboolean
frida_inject_instance_attach (FridaInjectInstance * self, FridaRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  long ret;
  int attach_errno;
  const gchar * failed_operation;
  gboolean maybe_already_attached, success;

  ret = ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  attach_errno = errno;
  maybe_already_attached = (ret != 0 && errno == EPERM);
  if (maybe_already_attached)
  {
    ret = frida_get_regs (pid, saved_regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

    self->already_attached = TRUE;
  }
  else
  {
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_ATTACH");

    self->already_attached = FALSE;

    success = frida_wait_for_attach_signal (pid);
    CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_ATTACH wait");

    ret = frida_get_regs (pid, saved_regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");
  }

  return TRUE;

handle_os_error:
  {
    if (attach_errno == EPERM)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to access process with pid %u due to system restrictions;"
          " try `sudo sysctl kernel.yama.ptrace_scope=0`, or run Frida as root",
          pid);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned '%s')",
          pid, failed_operation, g_strerror (errno));
    }

    return FALSE;
  }
}

static gboolean
frida_inject_instance_detach (FridaInjectInstance * self, const FridaRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  long ret;
  const gchar * failed_operation;

  ret = frida_set_regs (pid, saved_regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  if (!self->already_attached)
  {
    ret = ptrace (PTRACE_DETACH, pid, NULL, NULL);
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_DETACH");
  }

  return TRUE;

handle_os_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_OPERATION,
        "detach_from_process %s failed: %d",
        failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_inject_instance_start_remote_thread (FridaInjectInstance * self, gboolean * exited, GError ** error)
{
  return frida_remote_exec (self->pid, self->entrypoint, self->stack_top, NULL, exited, error);
}

static gboolean
frida_inject_instance_emit_and_transfer_payload (FridaInjectEmitFunc func, const FridaInjectParams * params, GumAddress * entrypoint, GError ** error)
{
  gboolean success = FALSE;
  gpointer scratch_buffer;
  FridaCodeChunk code;
  guint padding = 0;
  GumAddress address_mask = 0;
  FridaTrampolineData * data;

  scratch_buffer = g_malloc0 (params->remote_size);

  code.cur = scratch_buffer + params->code.offset;
  code.size = 0;

#if defined (HAVE_ARM)
  {
    GumThumbWriter cw;

    padding = 2;
    address_mask = 1;

    gum_thumb_writer_init (&cw, code.cur);
    gum_thumb_writer_put_nop (&cw);
    gum_thumb_writer_flush (&cw);
    code.cur = gum_thumb_writer_cur (&cw);
    code.size += gum_thumb_writer_offset (&cw);
    gum_thumb_writer_clear (&cw);
  }
#endif

  func (params, params->remote_address, &code);

  data = (FridaTrampolineData *) (scratch_buffer + params->data.offset);
  strcpy (data->pthread_so_string, "libpthread.so.0");
  strcpy (data->pthread_create_string, "pthread_create");
  strcpy (data->pthread_detach_string, "pthread_detach");
  strcpy (data->fifo_path, params->fifo_path);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, params->entrypoint_name);
  strcpy (data->entrypoint_data, params->entrypoint_data);
  data->hello_byte = FRIDA_PROGRESS_MESSAGE_TYPE_HELLO;

  if (!frida_remote_write (params->pid, params->remote_address + params->code.offset, scratch_buffer + params->code.offset, code.size, error))
    goto beach;
  if (!frida_remote_write (params->pid, params->remote_address + params->data.offset, data, sizeof (FridaTrampolineData), error))
    goto beach;

  if (!frida_remote_mprotect (params->pid, params->remote_address + params->code.offset, params->code.size, PROT_READ | PROT_EXEC, error))
    goto beach;
  if (!frida_remote_mprotect (params->pid, params->remote_address + params->guard.offset, params->guard.size, PROT_NONE, error))
    goto beach;

  *entrypoint = (params->remote_address + params->code.offset + padding) | address_mask;

  success = TRUE;

beach:
  g_free (scratch_buffer);

  return success;
}

#define ARG_IMM(value) \
    GUM_ARG_ADDRESS, GUM_ADDRESS (value)

#if defined (HAVE_I386)

#define EMIT_MOVE(dst, src) \
    gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_##dst, GUM_REG_##src)
#define EMIT_LEA(dst, src, offset) \
    gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_##dst, GUM_REG_##src, offset)
#define EMIT_SUB(reg, value) \
    gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_##reg, value)
#define EMIT_PUSH(reg) \
    gum_x86_writer_put_push_reg (&cw, GUM_REG_##reg)
#define EMIT_POP(reg) \
    gum_x86_writer_put_pop_reg (&cw, GUM_REG_##reg)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_x86_writer_put_mov_reg_near_ptr (&cw, GUM_REG_##reg, FRIDA_REMOTE_DATA_FIELD (field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_x86_writer_put_mov_near_ptr_reg (&cw, FRIDA_REMOTE_DATA_FIELD (field), GUM_REG_##reg)
#define EMIT_LOAD_IMM(reg, value) \
    gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_##reg, value)
#define EMIT_LOAD_REG(dst, src, offset) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_##dst, GUM_REG_##src, offset)
#define EMIT_LOAD_REGV(dst, src, offset) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, dst, GUM_REG_##src, offset)
#define EMIT_STORE_IMM(dst, offset, value) \
    gum_x86_writer_put_mov_reg_offset_ptr_u32 (&cw, GUM_REG_##dst, offset, value)
#define EMIT_STORE_REG(dst, offset, src) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_##dst, offset, GUM_REG_##src)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw, GUM_CALL_CAPI, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_x86_writer_put_call_reg_with_aligned_arguments (&cw, GUM_CALL_CAPI, GUM_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_x86_writer_put_ret (&cw)
#define EMIT_LABEL(name) \
    gum_x86_writer_put_label (&cw, name)
#define EMIT_CMP(reg, value) \
    gum_x86_writer_put_cmp_reg_i32 (&cw, GUM_REG_##reg, value)
#define EMIT_JE(label) \
    gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JE, label, GUM_NO_HINT)
#define EMIT_JNE(label) \
    gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JNE, label, GUM_NO_HINT)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, GUM_REG_##reg
#define ARG_REGV(reg) \
    GUM_ARG_REGISTER, reg

static void
frida_inject_instance_commit_x86_code (GumX86Writer * cw, FridaCodeChunk * code)
{
  gum_x86_writer_flush (cw);
  code->cur = gum_x86_writer_cur (cw);
  code->size += gum_x86_writer_offset (cw);
}

static void
frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumX86Writer cw;
  const guint worker_offset = 172;
  gssize fd_offset, unload_policy_offset, tid_offset;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";
  GumCpuReg fd_reg;

  gum_x86_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

#ifdef HAVE_ANDROID
  EMIT_LOAD_IMM (XAX, frida_resolve_libc_function (params->pid, "pthread_create"));
#else
  EMIT_CALL_IMM (params->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, XAX);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_create_string)));
#endif
  EMIT_CALL_REG (XAX,
      4,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (0));

  gum_x86_writer_put_breakpoint (&cw);
  gum_x86_writer_flush (&cw);
  g_assert_cmpuint (gum_x86_writer_offset (&cw), <=, worker_offset);
  while (gum_x86_writer_offset (&cw) != worker_offset - code->size)
    gum_x86_writer_put_nop (&cw);
  frida_inject_instance_commit_x86_code (&cw, code);
  gum_x86_writer_clear (&cw);

  gum_x86_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (XBP);
  EMIT_MOVE (XBP, XSP);
  EMIT_SUB (XSP, 32 + ((cw.target_cpu == GUM_CPU_IA32) ? 4 : 8));
  EMIT_PUSH (XBX);

  fd_offset = -4;
  unload_policy_offset = -8;
  tid_offset = -12;

  EMIT_CALL_IMM (params->open_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY));
  EMIT_STORE_REG (XBP, fd_offset, EAX);

  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (EAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (XAX, module_handle);
  EMIT_CMP (XAX, 0);
  EMIT_JNE (skip_dlopen);
  {
    if (params->dlopen_pic_value != 0)
      EMIT_LOAD_IMM (XBX, params->dlopen_pic_value);
#ifdef HAVE_ANDROID
    EMIT_CALL_IMM (params->dlopen_impl,
        3,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY),
        ARG_IMM (params->open_impl));
#else
    EMIT_CALL_IMM (params->dlopen_impl,
        2,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
#endif
    EMIT_STORE_FIELD (module_handle, XAX);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));

  EMIT_STORE_IMM (XBP, unload_policy_offset, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_LEA (XCX, XBP, unload_policy_offset);
  EMIT_LEA (XDX, XBP, fd_offset);
  EMIT_CALL_REG (XAX,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (XCX),
      ARG_REG (XDX));

  EMIT_LOAD_REG (EAX, XBP, unload_policy_offset);
  EMIT_CMP (EAX, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_JNE (skip_dlclose);
  {
    EMIT_LOAD_FIELD (XAX, module_handle);
    EMIT_CALL_IMM (params->dlclose_impl,
        1,
        ARG_REG (XAX));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LOAD_REG (EAX, XBP, unload_policy_offset);
  EMIT_CMP (EAX, FRIDA_UNLOAD_POLICY_DEFERRED);
  EMIT_JE (skip_detach);
  {
#ifdef HAVE_ANDROID
    EMIT_LOAD_IMM (XAX, frida_resolve_libc_function (params->pid, "pthread_detach"));
#else
    EMIT_LOAD_FIELD (XAX, pthread_so);
    EMIT_CALL_IMM (params->dlsym_impl,
        2,
        ARG_REG (XAX),
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_detach_string)));
#endif
    EMIT_LOAD_FIELD (XCX, worker_thread);
    EMIT_CALL_REG (XAX,
        1,
        ARG_REG (XCX));
  }
  EMIT_LABEL (skip_detach);

#ifndef HAVE_ANDROID
  EMIT_LOAD_FIELD (XAX, pthread_so);
  EMIT_CALL_IMM (params->dlclose_impl,
      1,
      ARG_REG (XAX));
#endif

  fd_reg = (cw.target_cpu == GUM_CPU_IA32) ? GUM_REG_EDX : GUM_REG_EDI;

  EMIT_LOAD_REGV (fd_reg, XBP, fd_offset);
  EMIT_LEA (XCX, XBP, unload_policy_offset);
  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REGV (fd_reg),
      ARG_REG (XCX),
      ARG_IMM (1));

  EMIT_CALL_IMM (params->syscall_impl,
      1,
      ARG_IMM (__NR_gettid));
  EMIT_STORE_REG (XBP, tid_offset, EAX);
  EMIT_LOAD_REGV (fd_reg, XBP, fd_offset);
  EMIT_LEA (XCX, XBP, tid_offset);
  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REGV (fd_reg),
      ARG_REG (XCX),
      ARG_IMM (4));

  EMIT_LOAD_REG (ECX, XBP, fd_offset);
  EMIT_CALL_IMM (params->close_impl,
      1,
      ARG_REG (ECX));

  EMIT_POP (XBX);
  EMIT_MOVE (XSP, XBP);
  EMIT_POP (XBP);
  EMIT_RET ();

  frida_inject_instance_commit_x86_code (&cw, code);
  gum_x86_writer_clear (&cw);
}

#elif defined (HAVE_ARM)

#define EMIT_MOVE(dst, src) \
    gum_thumb_writer_put_mov_reg_reg (&cw, ARM_REG_##dst, ARM_REG_##src)
#define EMIT_ADD(dst, src, offset) \
    gum_thumb_writer_put_add_reg_reg_imm (&cw, ARM_REG_##dst, ARM_REG_##src, offset)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_thumb_writer_put_ldr_reg_reg_offset (&cw, ARM_REG_##reg, ARM_REG_R6, G_STRUCT_OFFSET (FridaTrampolineData, field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_thumb_writer_put_str_reg_reg_offset (&cw, ARM_REG_##reg, ARM_REG_R6, G_STRUCT_OFFSET (FridaTrampolineData, field))
#define EMIT_LDR(dst, src) \
    gum_thumb_writer_put_ldr_reg_reg (&cw, ARM_REG_##dst, ARM_REG_##src)
#define EMIT_LDR_ADDRESS(reg, value) \
    gum_thumb_writer_put_ldr_reg_address (&cw, ARM_REG_##reg, value)
#define EMIT_LDR_U32(reg, value) \
    gum_thumb_writer_put_ldr_reg_u32 (&cw, ARM_REG_##reg, value)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_thumb_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_thumb_writer_put_call_reg_with_arguments (&cw, ARM_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_LABEL(name) \
    gum_thumb_writer_put_label (&cw, name)
#define EMIT_CBNZ(reg, label) \
    gum_thumb_writer_put_cbnz_reg_label (&cw, ARM_REG_##reg, label)
#define EMIT_CMP(reg, imm) \
    gum_thumb_writer_put_cmp_reg_imm (&cw, ARM_REG_##reg, imm)
#define EMIT_BEQ(label) \
    gum_thumb_writer_put_beq_label (&cw, label)
#define EMIT_BNE(label) \
    gum_thumb_writer_put_bne_label (&cw, label)
#define EMIT_STACK_ADJUSTMENT(delta) \
    gum_thumb_writer_put_sub_reg_imm (&cw, ARM_REG_SP, delta * 4)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, ARM_REG_##reg

static void
frida_inject_instance_commit_arm_code (GumThumbWriter * cw, FridaCodeChunk * code)
{
  gum_thumb_writer_flush (cw);
  code->cur = gum_thumb_writer_cur (cw);
  code->size += gum_thumb_writer_offset (cw);
}

static void
frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumThumbWriter cw;
  const guint worker_offset = 128;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";

  gum_thumb_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

#ifdef HAVE_ANDROID
  EMIT_LDR_ADDRESS (R5, frida_resolve_libc_function (params->pid, "pthread_create"));
#else
  EMIT_LDR_ADDRESS (R6, remote_address + params->data.offset);

  EMIT_CALL_IMM (params->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, R0);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (R0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_create_string)));
  EMIT_MOVE (R5, R0);
#endif
  EMIT_CALL_REG (R5,
      4,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset + 1),
      ARG_IMM (remote_address + params->data.offset));

  gum_thumb_writer_put_breakpoint (&cw);
  gum_thumb_writer_flush (&cw);
  g_assert_cmpuint (gum_thumb_writer_offset (&cw), <=, worker_offset);
  while (gum_thumb_writer_offset (&cw) != worker_offset - code->size)
    gum_thumb_writer_put_nop (&cw);
  frida_inject_instance_commit_arm_code (&cw, code);
  gum_thumb_writer_clear (&cw);

  gum_thumb_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  gum_thumb_writer_put_push_regs (&cw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);

  EMIT_MOVE (R6, R0);

  EMIT_CALL_IMM (params->open_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY));
  EMIT_MOVE (R7, R0);

  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (R7),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (R5, module_handle);
  EMIT_CBNZ (R5, skip_dlopen);
  {
#ifdef HAVE_ANDROID
    EMIT_CALL_IMM (params->dlopen_impl,
        3,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY),
        ARG_IMM (params->open_impl));
#else
    EMIT_CALL_IMM (params->dlopen_impl,
        2,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
#endif
    EMIT_MOVE (R5, R0);
    EMIT_STORE_FIELD (module_handle, R5);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (
      params->dlsym_impl,
      2,
      ARG_REG (R5),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  EMIT_MOVE (R4, R0);

  EMIT_STACK_ADJUSTMENT (2);
  EMIT_LDR_U32 (R0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  gum_thumb_writer_put_push_regs (&cw, 2, ARM_REG_R0, ARM_REG_R7);
  EMIT_MOVE (R1, SP);
  EMIT_ADD (R2, SP, 4);
  EMIT_CALL_REG (R4,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (R1),
      ARG_REG (R2));

  EMIT_LDR (R0, SP);
  EMIT_CMP (R0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_BNE (skip_dlclose);
  {
    EMIT_CALL_IMM (
        params->dlclose_impl,
        1,
        ARG_REG (R5));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LDR (R0, SP);
  EMIT_CMP (R0, FRIDA_UNLOAD_POLICY_DEFERRED);
  EMIT_BEQ (skip_detach);
  {
#ifdef HAVE_ANDROID
    EMIT_LDR_ADDRESS (R3, frida_resolve_libc_function (params->pid, "pthread_detach"));
#else
    EMIT_LOAD_FIELD (R0, pthread_so);
    EMIT_CALL_IMM (params->dlsym_impl,
        2,
        ARG_REG (R0),
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_detach_string)));
    EMIT_MOV (R3, R0);
#endif
    EMIT_LOAD_FIELD (R0, worker_thread);
    EMIT_CALL_REG (R3,
        1,
        ARG_REG (R0));
  }
  EMIT_LABEL (skip_detach);

#ifndef HAVE_ANDROID
  EMIT_LOAD_FIELD (R0, pthread_so);
  EMIT_CALL_IMM (params->dlclose_impl,
      1,
      ARG_REG (R0));
#endif

  EMIT_MOVE (R1, SP);
  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (R7),
      ARG_REG (R1),
      ARG_IMM (1));

  EMIT_STACK_ADJUSTMENT (-4);

  EMIT_CALL_IMM (params->syscall_impl,
      1,
      ARG_IMM (__NR_gettid));
  EMIT_STACK_ADJUSTMENT (3);
  gum_thumb_writer_put_push_regs (&cw, 1, ARM_REG_R0);
  EMIT_MOVE (R1, SP);
  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (R7),
      ARG_REG (R1),
      ARG_IMM (4));
  EMIT_STACK_ADJUSTMENT (-4);

  EMIT_CALL_IMM (params->close_impl,
      1,
      ARG_REG (R7));

  gum_thumb_writer_put_pop_regs (&cw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);

  frida_inject_instance_commit_arm_code (&cw, code);
  gum_thumb_writer_clear (&cw);
}

#elif defined (HAVE_ARM64)

#define EMIT_MOVE(dst, src) \
    gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_##dst, ARM64_REG_##src)
#define EMIT_ADD(dst, src, offset) \
    gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_##dst, ARM64_REG_##src, offset)
#define EMIT_PUSH(a, b) \
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_POP(a, b) \
    gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaTrampolineData, field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_arm64_writer_put_str_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaTrampolineData, field))
#define EMIT_LDR(dst, src, offset) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##dst, ARM64_REG_##src, offset)
#define EMIT_LDR_ADDRESS(reg, value) \
    gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_##reg, value)
#define EMIT_LDR_U64(reg, value) \
    gum_arm64_writer_put_ldr_reg_u64 (&cw, ARM64_REG_##reg, value)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_arm64_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_arm64_writer_put_call_reg_with_arguments (&cw, ARM64_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_arm64_writer_put_ret (&cw)
#define EMIT_LABEL(name) \
    gum_arm64_writer_put_label (&cw, name)
#define EMIT_CBNZ(reg, label) \
    gum_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_##reg, label)
#define EMIT_CMP(a, b) \
    gum_arm64_writer_put_cmp_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_B_COND(cond, label) \
    gum_arm64_writer_put_b_cond_label (&cw, ARM64_CC_##cond, label)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, ARM64_REG_##reg

static void
frida_inject_instance_commit_arm64_code (GumArm64Writer * cw, FridaCodeChunk * code)
{
  gum_arm64_writer_flush (cw);
  code->cur = gum_arm64_writer_cur (cw);
  code->size += gum_arm64_writer_offset (cw);
}

static void
frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumArm64Writer cw;
  const guint worker_offset = 96;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";

  gum_arm64_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

#ifdef HAVE_ANDROID
  EMIT_LDR_ADDRESS (X5, frida_resolve_libc_function (params->pid, "pthread_create"));
#else
  EMIT_LDR_ADDRESS (X20, remote_address + params->data.offset);

  EMIT_CALL_IMM (params->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, X0);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (X0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_create_string)));
  EMIT_MOVE (X5, X0);
#endif
  EMIT_CALL_REG (X5,
      4,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (remote_address + params->data.offset));

  gum_arm64_writer_put_brk_imm (&cw, 0);
  gum_arm64_writer_flush (&cw);
  g_assert_cmpuint (gum_arm64_writer_offset (&cw), <=, worker_offset);
  while (gum_arm64_writer_offset (&cw) != worker_offset - code->size)
    gum_arm64_writer_put_nop (&cw);
  frida_inject_instance_commit_arm64_code (&cw, code);
  gum_arm64_writer_clear (&cw);

  gum_arm64_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (FP, LR);
  EMIT_MOVE (FP, SP);
  EMIT_PUSH (X21, X22);
  EMIT_PUSH (X19, X20);

  EMIT_MOVE (X20, X0);

  EMIT_CALL_IMM (params->open_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY));
  EMIT_MOVE (W21, W0);

  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (W21),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (X19, module_handle);
  EMIT_CBNZ (X19, skip_dlopen);
  {
#ifdef HAVE_ANDROID
    EMIT_CALL_IMM (params->dlopen_impl,
        3,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY),
        ARG_IMM (params->open_impl));
#else
    EMIT_CALL_IMM (params->dlopen_impl,
        2,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (FRIDA_RTLD_DLOPEN | RTLD_LAZY));
#endif
    EMIT_MOVE (X19, X0);
    EMIT_STORE_FIELD (module_handle, X19);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (X19),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  EMIT_MOVE (X5, X0);

  EMIT_LDR_U64 (X0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_PUSH (X0, X21);
  EMIT_MOVE (X1, SP);
  EMIT_ADD (X2, SP, 8);
  EMIT_CALL_REG (X5,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (X1),
      ARG_REG (X2));

  EMIT_LDR (W22, SP, 0);

  EMIT_LDR_U64 (X1, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_CMP (W22, W1);
  EMIT_B_COND (NE, skip_dlclose);
  {
    EMIT_CALL_IMM (params->dlclose_impl,
        1,
        ARG_REG (X19));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LDR_U64 (X1, FRIDA_UNLOAD_POLICY_DEFERRED);
  EMIT_CMP (W22, W1);
  EMIT_B_COND (EQ, skip_detach);
  {
#ifdef HAVE_ANDROID
    EMIT_LDR_ADDRESS (X5, frida_resolve_libc_function (params->pid, "pthread_detach"));
#else
    EMIT_LOAD_FIELD (X0, pthread_so);
    EMIT_CALL_IMM (params->dlsym_impl,
        2,
        ARG_REG (X0),
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_detach_string)));
    EMIT_MOV (X5, X0);
#endif
    EMIT_LOAD_FIELD (X0, worker_thread);
    EMIT_CALL_REG (X5,
        1,
        ARG_REG (X0));
  }
  EMIT_LABEL (skip_detach);

#ifndef HAVE_ANDROID
  EMIT_LOAD_FIELD (X0, pthread_so);
  EMIT_CALL_IMM (params->dlclose_impl,
      1,
      ARG_REG (X0));
#endif

  EMIT_MOVE (X1, SP);
  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (W21),
      ARG_REG (X1),
      ARG_IMM (1));

  EMIT_POP (X0, X1);

  EMIT_CALL_IMM (params->syscall_impl,
      1,
      ARG_IMM (__NR_gettid));
  EMIT_PUSH (X0, X1);
  EMIT_MOVE (X1, SP);
  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (W21),
      ARG_REG (X1),
      ARG_IMM (4));
  EMIT_POP (X0, X1);

  EMIT_CALL_IMM (params->close_impl,
      1,
      ARG_REG (W21));

  EMIT_POP (X19, X20);
  EMIT_POP (X21, X22);
  EMIT_POP (FP, LR);
  EMIT_RET ();

  frida_inject_instance_commit_arm64_code (&cw, code);
  gum_arm64_writer_clear (&cw);
}

#elif defined (HAVE_MIPS)

#define EMIT_MOVE(dst, src) \
    gum_mips_writer_put_move_reg_reg (&cw, MIPS_REG_##dst, MIPS_REG_##src)
#define EMIT_PUSH(reg) \
    gum_mips_writer_put_push_reg (&cw, MIPS_REG_##reg)
#define EMIT_POP(reg) \
    gum_mips_writer_put_pop_reg (&cw, MIPS_REG_##reg)
#define EMIT_LA(reg, value) \
    gum_mips_writer_put_la_reg_address (&cw, MIPS_REG_##reg, value)
#define EMIT_LW(dst, src, offset) \
    gum_mips_writer_put_lw_reg_reg_offset (&cw, MIPS_REG_##dst, MIPS_REG_##src, offset)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_mips_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_mips_writer_put_call_reg_with_arguments (&cw, MIPS_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_mips_writer_put_ret (&cw)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, MIPS_REG_##reg

static void
frida_inject_instance_commit_mips_code (GumMipsWriter * cw, FridaCodeChunk * code)
{
  gum_mips_writer_flush (cw);
  code->cur = gum_mips_writer_cur (cw);
  code->size += gum_mips_writer_offset (cw);
}

static void
frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumMipsWriter cw;
  const guint worker_offset = 192;

  gum_mips_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

  EMIT_CALL_IMM (params->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (RTLD_LAZY));
  EMIT_MOVE (S0, V0);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (S0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_create_string)));
  EMIT_MOVE (T9, V0);

  EMIT_LA (S1, FRIDA_REMOTE_DATA_FIELD (worker_thread));

  EMIT_CALL_REG (T9,
      4,
      ARG_REG (S1),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (0));

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (S0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_detach_string)));
  EMIT_MOVE (T9, V0);

  EMIT_LW (A0, S1, 0);
  EMIT_CALL_REG (T9,
      1,
      ARG_REG (A0));

  EMIT_CALL_IMM (params->dlclose_impl,
      1,
      ARG_REG (S0));

  gum_mips_writer_put_break (&cw);
  gum_mips_writer_flush (&cw);
  g_assert_cmpuint (gum_mips_writer_offset (&cw), <=, worker_offset);
  while (gum_mips_writer_offset (&cw) != worker_offset - code->size)
    gum_mips_writer_put_nop (&cw);
  frida_inject_instance_commit_mips_code (&cw, code);
  gum_mips_writer_clear (&cw);

  gum_mips_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (RA);
  EMIT_PUSH (S0);
  EMIT_PUSH (S1);

  EMIT_CALL_IMM (params->open_impl,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY),
      ARG_IMM (0));
  EMIT_MOVE (S0, V0);

  EMIT_CALL_IMM (params->write_impl,
      3,
      ARG_REG (S0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_CALL_IMM (params->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
      ARG_IMM (RTLD_LAZY));
  EMIT_MOVE (S1, V0);

  EMIT_CALL_IMM (params->dlsym_impl,
      2,
      ARG_REG (S1),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  EMIT_MOVE (T9, V0);

  EMIT_CALL_REG (T9,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_IMM (0) /* FIXME: unload_policy */,
      ARG_IMM (0) /* FIXME: injector_state */);

  EMIT_CALL_IMM (params->dlclose_impl,
      1,
      ARG_REG (S1));

  EMIT_CALL_IMM (params->close_impl,
      1,
      ARG_REG (S0));

  EMIT_POP (S1);
  EMIT_POP (S0);
  EMIT_POP (RA);
  EMIT_RET ();

  frida_inject_instance_commit_mips_code (&cw, code);
  gum_mips_writer_clear (&cw);
}

#endif

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
      if (!frida_wait_for_child_signal (pid, SIGSTOP, NULL))
        return FALSE;
      /* fall through */
    case SIGSTOP:
      if (frida_find_libc_base (pid) == 0)
      {
        if (ptrace (PTRACE_CONT, pid, NULL, NULL) != 0)
          return FALSE;
        sleep (1);
        kill (pid, SIGSTOP);
        if (!frida_wait_for_child_signal (pid, SIGSTOP, NULL))
          return FALSE;
        return frida_find_libc_base (pid) != 0;
      }
      return TRUE;
    default:
      break;
  }

  return FALSE;
}

static gboolean
frida_wait_for_child_signal (pid_t pid, int signal, gboolean * exited)
{
  gboolean success = FALSE;
  gboolean child_did_exit = TRUE;
  int status = 0;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || WIFEXITED (status))
    goto beach;

  child_did_exit = FALSE;

  if (!WIFSTOPPED (status))
    goto beach;

  success = WSTOPSIG (status) == signal;

beach:
  if (exited != NULL)
    *exited = child_did_exit;

  return success;
}

static gint
frida_get_regs (pid_t pid, FridaRegs * regs)
{
  if (frida_is_regset_supported)
  {
    struct iovec io = {
      .iov_base = regs,
      .iov_len = sizeof (FridaRegs)
    };
    long ret = ptrace (PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
    if (ret >= 0)
      return ret;
    else if (errno == EPERM || errno == ESRCH)
      return ret;
    else
      frida_is_regset_supported = FALSE;
  }

  return ptrace (PTRACE_GETREGS, pid, NULL, regs);
}

static gint
frida_set_regs (pid_t pid, const FridaRegs * regs)
{
  if (frida_is_regset_supported)
  {
    struct iovec io = {
      .iov_base = (void *) regs,
      .iov_len = sizeof (FridaRegs)
    };
    long ret = ptrace (PTRACE_SETREGSET, pid, NT_PRSTATUS, &io);
    if (ret >= 0)
      return ret;
    else if (errno == EPERM || errno == ESRCH)
      return ret;
    else
      frida_is_regset_supported = FALSE;
  }

  return ptrace (PTRACE_SETREGS, pid, NULL, (void *) regs);
}

static gboolean
frida_run_to_entry_point (pid_t pid, GError ** error)
{
  gchar * exe_link;
  ssize_t length;
  FridaProbeElfContext ctx;
  gpointer entry_point_address;
  long original_entry_code, patched_entry_code;
  long ret;
  FridaRegs regs;
  const gchar * failed_operation;
  gboolean success;

  ctx.pid = pid;
  exe_link = g_strdup_printf ("/proc/%d/exe", pid);
  length = readlink (exe_link, ctx.path, sizeof (ctx.path) - 1);
  g_free (exe_link);
  if (length == -1)
    goto handle_probe_error;
  ctx.path[length] = '\0';
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

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  if (ctx.word_size == 4)
  {
    if ((ctx.entry_point & 1) == 0)
    {
      /* ARM */
      patched_entry_code = 0xe7f001f0;
    }
    else
    {
      /* Thumb */
      patched_entry_code = 0xde01;
    }
  }
  else
  {
    /* ARM64 */
    patched_entry_code = 0xd4200000;
  }
#elif defined (HAVE_I386)
  /* x86 */
  patched_entry_code = 0xcc;
#elif defined (HAVE_MIPS)
  /* mips */
  patched_entry_code = 0x0000000d;
#else
# error Unsupported architecture
#endif

  ptrace (PTRACE_POKEDATA, pid, entry_point_address, GSIZE_TO_POINTER (patched_entry_code));

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, SIGTRAP, NULL);
  CHECK_OS_RESULT (success, !=, FALSE, "WAIT(SIGTRAP)");

  ptrace (PTRACE_POKEDATA, pid, entry_point_address, GSIZE_TO_POINTER (original_entry_code));

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.eip = GPOINTER_TO_SIZE (entry_point_address);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.rip = GPOINTER_TO_SIZE (entry_point_address);
#elif defined (HAVE_ARM)
  regs.ARM_pc = GPOINTER_TO_SIZE (entry_point_address);
#elif defined (HAVE_ARM64)
  regs.pc = GPOINTER_TO_SIZE (entry_point_address);
#elif defined (HAVE_MIPS)
  regs.pc = GPOINTER_TO_SIZE (entry_point_address);
#else
# error Unsupported architecture
#endif

  ret = frida_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  return TRUE;

handle_probe_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "failed to probe process");
    return FALSE;
  }
handle_os_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "%s failed: %d",
        failed_operation, errno);
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
  } value;
  guint16 type;

  if (details->file == NULL || details->file->offset != 0 || strcmp (details->file->path, ctx->path) != 0)
    return TRUE;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address + EI_NIDENT), NULL);
  type = value.u16;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address + EI_CLASS), NULL);
  ctx->word_size = value.u8 == ELFCLASS32 ? 4 : 8;

  value.word = ptrace (PTRACE_PEEKDATA, ctx->pid, GSIZE_TO_POINTER (details->range->base_address + FRIDA_OFFSET_E_ENTRY), NULL);
  ctx->entry_point = ctx->word_size == 4 ? value.u32 : value.u64;
  if (type == ET_DYN)
    ctx->entry_point += details->range->base_address;

  return FALSE;
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
  GumAddress retval;

  if (!frida_remote_call (pid, frida_resolve_libc_function (pid, "mmap"), args, G_N_ELEMENTS (args), &retval, NULL, error))
    return 0;

  if (retval == FRIDA_MAP_FAILED)
    return 0;

  return retval;
}

static gboolean
frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error)
{
  GumAddress args[] = {
    address,
    size
  };
  GumAddress retval;

  if (!frida_remote_call (pid, frida_resolve_libc_function (pid, "munmap"), args, G_N_ELEMENTS (args), &retval, NULL, error))
    return FALSE;

  return retval == 0;
}

static gboolean
frida_remote_mprotect (pid_t pid, GumAddress address, size_t size, int prot, GError ** error)
{
  GumAddress args[] = {
    address,
    size,
    prot
  };
  GumAddress retval;

  if (!frida_remote_call (pid, frida_resolve_libc_function (pid, "mprotect"), args, G_N_ELEMENTS (args), &retval, NULL, error))
    return FALSE;

  return retval == 0;
}

static gboolean
frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  GumAddress dst;
  const gsize * src;
  long ret;
  const gchar * failed_operation;
  gsize remainder, remainder_offset;

  dst = remote_address;
  src = data;

  while (dst < remote_address + size)
  {
    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (dst), GSIZE_TO_POINTER (*src));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA head");

    dst += sizeof (gsize);
    src++;
  }

  remainder_offset = (size / sizeof (gsize)) * sizeof (gsize);
  dst = remote_address + remainder_offset;
  src = data + remainder_offset;
  remainder = size % sizeof (gsize);
  if (remainder != 0)
  {
    gsize word = 0;

    memcpy (&word, src, remainder);

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (dst), GSIZE_TO_POINTER (word));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA tail");
  }

  return TRUE;

handle_os_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_write %s failed: %d",
        failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, gboolean * exited, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  FridaRegs regs;
  gint i;
  gboolean success;

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.esp -= ((gsize) regs.esp - (args_length * 4)) % FRIDA_STACK_ALIGNMENT;

  regs.orig_eax = -1;

  regs.eip = func;

  for (i = args_length - 1; i >= 0; i--)
  {
    regs.esp -= 4;

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.esp), GSIZE_TO_POINTER (args[i]));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
  }

  regs.esp -= 4;
  ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.esp), GSIZE_TO_POINTER (FRIDA_DUMMY_RETURN_ADDRESS));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.rsp -= FRIDA_RED_ZONE_SIZE;
  regs.rsp -= (regs.rsp - (MAX (args_length - 6, 0) * 8)) % FRIDA_STACK_ALIGNMENT;

  regs.orig_rax = -1;

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
  ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.rsp), GSIZE_TO_POINTER (FRIDA_DUMMY_RETURN_ADDRESS));
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
#elif defined (HAVE_ARM)
  regs.ARM_sp -= (regs.ARM_sp - (MAX (args_length - 4, 0) * 4)) % FRIDA_STACK_ALIGNMENT;

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

  regs.ARM_lr = FRIDA_DUMMY_RETURN_ADDRESS;
#elif defined (HAVE_ARM64)
  regs.sp -= regs.sp % FRIDA_STACK_ALIGNMENT;

  regs.pc = func;

  g_assert_cmpuint (args_length, <=, 8);
  for (i = 0; i != args_length; i++)
    regs.regs[i] = args[i];

  regs.regs[30] = FRIDA_DUMMY_RETURN_ADDRESS;
#elif defined (HAVE_MIPS)
  guint32 insn;

  insn = ptrace (PTRACE_PEEKDATA, pid, GSIZE_TO_POINTER (regs.pc - 4), NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_PEEKDATA");

  /*
   * If insn is a syscall, trying to hijack the thread won't work well because
   * a3 will be overwritten by the syscall on CONT. So we just set a bad PC and
   * then run until we SIGSEGV. We can then replace a3 correctly.
   */
  if ((insn & 0xfc00003f) == 0x0000000c)
  {
    /* Cause a SIGSEGV with a bad PC */
    regs.pc = 0x12345678;

    ret = frida_set_regs (pid, &regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

    ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

    ret = frida_wait_for_child_signal (pid, SIGSEGV, exited);
    CHECK_OS_RESULT (ret, !=, FALSE, "PTRACE_CONT wait");

    ret = frida_get_regs (pid, &regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");
  }

  /* We need to set t9 as well as pc, so that PIC functions work as expected */
  regs.t9 = func;
  regs.pc = func;

  for (i = 0; i < args_length && i < 4; i++)
  {
    switch (i)
    {
      case 0:
        regs.a0 = args[i];
        break;
      case 1:
        regs.a1 = args[i];
        break;
      case 2:
        regs.a2 = args[i];
        break;
      case 3:
        regs.a3 = args[i];
        break;
    }
  }

  for (i = args_length - 1; i >= 4; i--)
  {
    regs.sp -= 4;

    ret = ptrace (PTRACE_POKEDATA, pid, GSIZE_TO_POINTER (regs.sp), GSIZE_TO_POINTER (args[i]));
    CHECK_OS_RESULT (ret, ==, 0, "PTRACE_POKEDATA");
  }

  /*
   * We need to reserve 16 bytes for 'incoming arguments', as per
   * http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf section 3-15
   */
  regs.sp -= 16;

  regs.ra = FRIDA_DUMMY_RETURN_ADDRESS;
#else
# error Unsupported architecture
#endif

  ret = frida_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, SIGSEGV, exited);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  *retval = (guint32) regs.eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  *retval = regs.rax;
#elif defined (HAVE_ARM)
  *retval = regs.ARM_r0;
#elif defined (HAVE_ARM64)
  *retval = regs.regs[0];
#elif defined (HAVE_MIPS)
  *retval = regs.v0;
#else
# error Unsupported architecture
#endif

  return TRUE;

handle_os_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_call %s failed: %d",
        failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, gboolean * exited, GError ** error)
{
  long ret;
  const gchar * failed_operation;
  FridaRegs regs;
  gboolean success;

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.orig_eax = -1;

  regs.eip = remote_address;
  regs.esp = remote_stack;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.orig_rax = -1;

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
#elif defined (HAVE_ARM64)
  regs.pc = remote_address;
  regs.sp = remote_stack;
#elif defined (HAVE_MIPS)
  regs.pc = remote_address;
  regs.sp = remote_stack;
#else
# error Unsupported architecture
#endif

  ret = frida_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  ret = ptrace (PTRACE_CONT, pid, NULL, NULL);
  CHECK_OS_RESULT (ret, ==, 0, "PTRACE_CONT");

  success = frida_wait_for_child_signal (pid, SIGTRAP, exited);
  CHECK_OS_RESULT (success, !=, FALSE, "PTRACE_CONT wait");

  if (result != NULL)
  {
    ret = frida_get_regs (pid, &regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
    *result = (guint32) regs.eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    *result = regs.rax;
#elif defined (HAVE_ARM)
    *result = regs.ARM_r0;
#elif defined (HAVE_ARM64)
    *result = regs.regs[0];
#elif defined (HAVE_MIPS)
    *result = regs.v0;
#else
# error Unsupported architecture
#endif
  }

  return TRUE;

handle_os_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_exec %s failed: %d",
        failed_operation, errno);
    return FALSE;
  }
}

static GumAddress
frida_resolve_libc_function (pid_t pid, const gchar * function_name)
{
#if defined (HAVE_UCLIBC)
  return frida_resolve_library_function (pid, "libuClibc", function_name);
#else
  return frida_resolve_library_function (pid, "libc", function_name);
#endif
}

static GumAddress
frida_find_libc_base (pid_t pid)
{
#if defined (HAVE_UCLIBC)
  return frida_find_library_base (pid, "libuClibc", NULL);
#else
  return frida_find_library_base (pid, "libc", NULL);
#endif
}

#ifdef HAVE_ANDROID

static GumAddress
frida_resolve_linker_address (pid_t pid, gpointer func)
{
#if GLIB_SIZEOF_VOID_P == 4
  const gchar * linker_path = "/system/bin/linker";
#else
  const gchar * linker_path = "/system/bin/linker64";
#endif
  Dl_info info;
  GumAddress local_base, remote_base, remote_address;

  if (dladdr (func, &info))
  {
    linker_path = info.dli_fname;
  }

  local_base = frida_find_library_base (getpid (), linker_path, NULL);
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (pid, linker_path, NULL);
  g_assert (remote_base != 0);

  remote_address = remote_base + (GUM_ADDRESS (func) - local_base);

  return remote_address;
}

static GumAddress
frida_resolve_inner_dlopen (pid_t pid,
                            GumAddress * pic_value)
{
  gpointer impl;
  csh capstone;
  cs_err err;
  gsize dlopen_address;
  cs_insn * insn;
  size_t count;

  impl = dlopen;
  *pic_value = 0;

  if (frida_get_android_api_level () < 26)
  {
    return frida_resolve_linker_address (pid, impl);
  }

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  err = cs_open (CS_ARCH_X86, CS_MODE_32, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  dlopen_address = GPOINTER_TO_SIZE (impl);

  insn = NULL;
  count = cs_disasm (capstone, GSIZE_TO_POINTER (dlopen_address), 48, dlopen_address, 18, &insn);

  for (size_t i = 0; i != count; i++)
  {
    const cs_insn * cur = &insn[i];
    const cs_x86_op * op1 = &cur->detail->x86.operands[0];
    const cs_x86_op * op2 = &cur->detail->x86.operands[1];

    switch (cur->id)
    {
      case X86_INS_CALL:
        if (op1->type == X86_OP_IMM)
          impl = GSIZE_TO_POINTER (op1->imm);
        break;
      case X86_INS_POP:
        if (op1->reg == X86_REG_EBX && *pic_value == 0)
          *pic_value = cur->address;
        break;
      case X86_INS_ADD:
        if (op1->reg == X86_REG_EBX)
          *pic_value += op2->imm;
        break;
    }
  }

  if (*pic_value != 0)
    *pic_value = frida_resolve_linker_address (pid, GSIZE_TO_POINTER (*pic_value));
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  err = cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  dlopen_address = GPOINTER_TO_SIZE (impl);

  insn = NULL;
  count = cs_disasm (capstone, GSIZE_TO_POINTER (dlopen_address), 16, dlopen_address, 4, &insn);

  for (size_t i = 0; i != count; i++)
  {
    const cs_insn * cur = &insn[i];
    const cs_x86_op * op = &cur->detail->x86.operands[0];

    if (cur->id == X86_INS_JMP)
    {
      if (op->type == X86_OP_IMM)
        impl = GSIZE_TO_POINTER (op->imm);
      break;
    }
  }
#elif defined (HAVE_ARM)
  err = cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  dlopen_address = GPOINTER_TO_SIZE (impl) & (gsize) ~1;

  insn = NULL;
  count = cs_disasm (capstone, GSIZE_TO_POINTER (dlopen_address), 10, dlopen_address, 4, &insn);
  if (count == 4 &&
      insn[0].id == ARM_INS_PUSH &&
      (insn[1].id == ARM_INS_MOV &&
          insn[1].detail->arm.operands[0].reg == ARM_REG_R2 &&
          insn[1].detail->arm.operands[1].reg == ARM_REG_LR) &&
      (insn[2].id == ARM_INS_BL || insn[2].id == ARM_INS_BLX) &&
      insn[3].id == ARM_INS_POP)
  {
    impl = GSIZE_TO_POINTER (insn[2].detail->arm.operands[0].imm);
  }
#elif defined (HAVE_ARM64)
  err = cs_open (CS_ARCH_ARM64, CS_MODE_ARM, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  dlopen_address = GPOINTER_TO_SIZE (impl);

  insn = NULL;
  count = cs_disasm (capstone, GSIZE_TO_POINTER (dlopen_address), 6 * sizeof (guint32), dlopen_address, 6, &insn);
  if (count == 6 &&
      insn[0].id == ARM64_INS_STP &&
      insn[1].id == ARM64_INS_MOV &&
      (insn[2].id == ARM64_INS_MOV &&
          insn[2].detail->arm64.operands[0].reg == ARM64_REG_X2 &&
          insn[2].detail->arm64.operands[1].reg == ARM64_REG_LR) &&
      insn[3].id == ARM64_INS_BL &&
      insn[4].id == ARM64_INS_LDP &&
      insn[5].id == ARM64_INS_RET)
  {
    impl = GSIZE_TO_POINTER (insn[3].detail->arm64.operands[0].imm);
  }
#else
# error Unsupported architecture
#endif

  cs_free (insn, count);

  cs_close (&capstone);

  return frida_resolve_linker_address (pid, impl);
}

static guint
frida_get_android_api_level (void)
{
  gchar sdk_version[PROP_VALUE_MAX];

  sdk_version[0] = '\0';
  __system_property_get ("ro.build.version.sdk", sdk_version);

  return atoi (sdk_version);
}

#elif defined (HAVE_UCLIBC)

static GumAddress
frida_resolve_linker_address (pid_t pid, gpointer func)
{
  const gchar * linker_file_name = "libdl";
  gchar * linker_path;
  GumAddress local_base, remote_base, remote_address;

  local_base = frida_find_library_base (getpid (), linker_file_name, &linker_path);
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (pid, linker_file_name, NULL);
  if (remote_base == 0)
  {
    gpointer rpnt, rpnt_next, tpnt;
    gboolean success;
    GumAddress remote_dl_symbol_tables, remote_address;
    const gchar * ldso_file_name = "ld-uClibc";
    gchar * ldso_path;
    GumAddress args[] = {
      0,
      GUM_ADDRESS (&rpnt),
      GUM_ADDRESS (NULL),
      GUM_ADDRESS (linker_path),
      GUM_ADDRESS (NULL),
    };
    GumAddress retval = 0;

    frida_find_library_base (pid, ldso_file_name, &ldso_path);

    remote_dl_symbol_tables = frida_resolve_library_function (pid, ldso_path, "_dl_symbol_tables");
    rpnt = (gpointer) ptrace (PTRACE_PEEKDATA, pid, remote_dl_symbol_tables, NULL);
    while (TRUE)
    {
      rpnt_next = (gpointer) ptrace (PTRACE_PEEKDATA, pid, rpnt + 0x10, NULL);
      if (rpnt_next == 0)
        break;
      rpnt = rpnt_next;
    }

    remote_address = frida_remote_alloc (pid, gum_query_page_size (), PROT_READ | PROT_WRITE, NULL);
    g_assert (remote_address != GUM_ADDRESS (NULL));

    success = frida_remote_write (pid, remote_address, &rpnt, 4, NULL);
    g_assert (success);
    success = frida_remote_write (pid, GUM_ADDRESS (remote_address + 4), linker_path, strlen (linker_path) + 1, NULL);
    g_assert (success);

    args[1] = remote_address;
    args[3] = remote_address + 4;
    success = frida_remote_call (pid, frida_resolve_library_function (pid, ldso_path, "_dl_load_shared_library"), args, G_N_ELEMENTS (args), &retval, NULL, NULL);
    g_assert (success);
    tpnt = GSIZE_TO_POINTER (retval);
    g_assert (retval != 0);

    GumAddress args_perform_mips_global_got_relocations[] = {
      GUM_ADDRESS (tpnt),
      0
    };
    success = frida_remote_call (pid, frida_resolve_library_function (pid, ldso_path, "_dl_perform_mips_global_got_relocations"), args_perform_mips_global_got_relocations, G_N_ELEMENTS (args_perform_mips_global_got_relocations), &retval, NULL, NULL);
    g_assert (success);

    success = frida_remote_dealloc (pid, remote_address, gum_query_page_size (), NULL);
    g_assert (success);

    remote_base = frida_find_library_base (pid, linker_path, NULL);

    g_free (ldso_path);
  }
  g_assert (remote_base != 0);

  remote_address = remote_base + (GUM_ADDRESS (func) - local_base);

  g_free (linker_path);

  return remote_address;
}

#endif

static GumAddress
frida_resolve_library_function (pid_t pid, const gchar * library_name, const gchar * function_name)
{
  gchar * local_library_path, * remote_library_path, * canonical_library_name;
  GumAddress local_base, remote_base, remote_address;
  gpointer module, local_address;

  local_base = frida_find_library_base (getpid (), library_name, &local_library_path);
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (pid, library_name, &remote_library_path);
  g_assert (remote_base != 0);

  g_assert_cmpstr (local_library_path, ==, remote_library_path);

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

        if (g_str_has_prefix (p, library_name) && strstr (p, ".so"))
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

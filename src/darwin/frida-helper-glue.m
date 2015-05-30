#define ENABLE_MAPPER 1

#include "frida-helper.h"

#include "mapper.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <spawn.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#include <gum/gum.h>
#include <gum/gumdarwin.h>
#include <mach/mach.h>

#define FRIDA_AGENT_ENTRYPOINT_NAME      "frida_agent_main"

#define FRIDA_SYSTEM_LIBC                "/usr/lib/libSystem.B.dylib"

/* TODO: check page size dynamically */
#ifdef HAVE_ARM64
# define FRIDA_PAGE_SIZE                 (16384)
#else
# define FRIDA_PAGE_SIZE                 (4096)
#endif
#define FRIDA_STACK_GUARD_SIZE           FRIDA_PAGE_SIZE
#define FRIDA_STACK_SIZE                 (32 * 1024)
#define FRIDA_PTHREAD_DATA_SIZE          (16384)

#define FRIDA_SPAWN_CODE_OFFSET          (0 * FRIDA_PAGE_SIZE)
#define FRIDA_SPAWN_DATA_OFFSET          (1 * FRIDA_PAGE_SIZE)
#define FRIDA_SPAWN_PAYLOAD_SIZE         (2 * FRIDA_PAGE_SIZE)

#define FRIDA_INJECT_CODE_OFFSET         (0)
#define FRIDA_INJECT_MACH_CODE_OFFSET    (0)
#define FRIDA_INJECT_PTHREAD_CODE_OFFSET (512)
#define FRIDA_INJECT_DATA_OFFSET         FRIDA_PAGE_SIZE
#define FRIDA_INJECT_STACK_GUARD_OFFSET  (FRIDA_INJECT_DATA_OFFSET + FRIDA_PAGE_SIZE)
#define FRIDA_INJECT_STACK_BOTTOM_OFFSET (FRIDA_INJECT_STACK_GUARD_OFFSET + FRIDA_STACK_GUARD_SIZE)
#define FRIDA_INJECT_STACK_TOP_OFFSET    (FRIDA_INJECT_STACK_BOTTOM_OFFSET + FRIDA_STACK_SIZE)
#define FRIDA_INJECT_THREAD_SELF_OFFSET  (FRIDA_INJECT_STACK_TOP_OFFSET)

#define FRIDA_INJECT_BASE_PAYLOAD_SIZE   (FRIDA_INJECT_THREAD_SELF_OFFSET + FRIDA_PTHREAD_DATA_SIZE)

#define FRIDA_PSR_THUMB                  (0x20)

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _FridaHelperContext FridaHelperContext;
typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaSpawnMessageTx FridaSpawnMessageTx;
typedef struct _FridaSpawnMessageRx FridaSpawnMessageRx;
typedef struct _FridaSpawnApi FridaSpawnApi;
typedef struct _FridaSpawnFillContext FridaSpawnFillContext;
typedef struct _FridaInjectInstance FridaInjectInstance;
typedef struct _FridaAgentDetails FridaAgentDetails;
typedef struct _FridaAgentContext FridaAgentContext;
typedef struct _FridaAgentEmitContext FridaAgentEmitContext;
typedef struct _FridaAgentFillContext FridaAgentFillContext;

struct _FridaHelperContext
{
  dispatch_queue_t dispatch_queue;
};

struct _FridaSpawnInstance
{
  FridaHelperService * service;
  guint pid;
  GumCpuType cpu_type;
  mach_port_t task;
  dispatch_source_t task_monitor_source;

  GumAddress entrypoint;
  mach_vm_address_t payload_address;
  guint8 * overwritten_code;
  guint overwritten_code_size;

  mach_port_name_t server_port;
  mach_port_name_t reply_port;
  dispatch_source_t server_recv_source;
};

struct _FridaSpawnMessageTx
{
  mach_msg_header_t header;
};

struct _FridaSpawnMessageRx
{
  mach_msg_header_t header;
  mach_msg_trailer_t trailer;
};

struct _FridaSpawnApi
{
  GumAddress mach_task_self_impl;
  GumAddress mach_port_allocate_impl;
  GumAddress mach_port_deallocate_impl;
  GumAddress mach_msg_impl;
  GumAddress abort_impl;
};

struct _FridaSpawnFillContext
{
  FridaSpawnApi * api;
  guint remaining;
};

struct _FridaInjectInstance
{
  FridaHelperService * service;
  guint id;
  mach_port_t task;
  mach_vm_address_t payload_address;
  mach_vm_size_t payload_size;
  mach_port_t thread;
  dispatch_source_t thread_monitor_source;
};

struct _FridaAgentDetails
{
  guint pid;
  const char * dylib_path;
  const char * data_string;
  GumCpuType cpu_type;
  mach_port_name_t task;
};

struct _FridaAgentContext
{
  GumAddress _pthread_set_self_impl;
  GumAddress cthread_set_self_impl;
  GumAddress thread_self_data;

  GumAddress pthread_create_impl;
  GumAddress pthread_create_start_routine;
  GumAddress pthread_create_arg;

  GumAddress pthread_join_impl;

  GumAddress thread_terminate_impl;

  GumAddress mach_thread_self_impl;

  GumAddress dlopen_impl;
  int dlopen_mode;

  GumAddress dlsym_impl;
  GumAddress entrypoint_name;
  GumAddress data_string;
  GumAddress mapped_range;
  GumThreadId thread_id;

  GumAddress dlclose_impl;

  GumAddress dylib_path;

  gchar entrypoint_name_data[32];
  gchar data_string_data[256];
  GumMemoryRange mapped_range_data;
  gchar dylib_path_data[256];
};

struct _FridaAgentEmitContext
{
  guint8 * code;
#ifdef HAVE_I386
  GumX86Writer cw;
#else
  GumThumbWriter tw;
  GumArm64Writer aw;
#endif
  FridaMapper * mapper;
};

struct _FridaAgentFillContext
{
  FridaAgentContext * agent;
  guint remaining;
};

static FridaSpawnInstance * frida_spawn_instance_new (FridaHelperService * service);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static void frida_spawn_instance_on_task_dead (void * context);
static void frida_spawn_instance_on_server_recv (void * context);

static gboolean frida_spawn_instance_find_remote_api (FridaSpawnInstance * self, FridaSpawnApi * api, GError ** error);
static gboolean frida_spawn_fill_context_process_export (const GumExportDetails * details, gpointer user_data);

static gboolean frida_spawn_instance_emit_redirect_code (FridaSpawnInstance * self, guint8 * code, guint * code_size, GError ** error);
static gboolean frida_spawn_instance_emit_sync_code (FridaSpawnInstance * self, const FridaSpawnApi * api, guint8 * code, guint * code_size, GError ** error);

static FridaInjectInstance * frida_inject_instance_new (FridaHelperService * service, guint id);
static void frida_inject_instance_free (FridaInjectInstance * instance);

static void frida_inject_instance_on_event (void * context);

static gboolean frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GError ** error);
static gboolean frida_agent_context_init_functions (FridaAgentContext * self, const FridaAgentDetails * details,
    GError ** error);
static gboolean frida_agent_fill_context_process_export (const GumExportDetails * details, gpointer user_data);

static void frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, FridaMapper * mapper);
static void frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, FridaMapper * mapper);

void
_frida_helper_service_create_context (FridaHelperService * self)
{
  FridaHelperContext * ctx;

  ctx = g_slice_new (FridaHelperContext);
  ctx->dispatch_queue = dispatch_queue_create ("re.frida.helper.queue", NULL);

  self->context = ctx;
}

void
_frida_helper_service_destroy_context (FridaHelperService * self)
{
  FridaHelperContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_slice_free (FridaHelperContext, ctx);
}

guint
_frida_helper_service_do_spawn (FridaHelperService * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  FridaHelperContext * ctx = self->context;
  FridaSpawnInstance * instance = NULL;
  pid_t pid;
  posix_spawnattr_t attr;
  sigset_t signal_mask_set;
  int spawn_errno, result;
  const gchar * failed_operation;
  kern_return_t ret;
  mach_port_name_t task;
  FridaSpawnApi api;
  mach_vm_address_t payload_address = 0;
  guint8 redirect_code[512];
  guint redirect_code_size;
  guint8 sync_code[512];
  guint sync_code_size;
  FridaSpawnMessageTx msg;
  mach_port_name_t name;
  dispatch_source_t source;

  if (!g_file_test (path, G_FILE_TEST_EXISTS))
    goto handle_path_error;

  instance = frida_spawn_instance_new (self);

  posix_spawnattr_init (&attr);
  sigemptyset (&signal_mask_set);
  posix_spawnattr_setsigmask (&attr, &signal_mask_set);
  posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED);

  result = posix_spawn (&pid, path, NULL, &attr, argv, envp);
  spawn_errno = errno;

  posix_spawnattr_destroy (&attr);

  if (result != 0)
    goto handle_spawn_error;

  instance->pid = pid;

  if (!gum_darwin_cpu_type_from_pid (instance->pid, &instance->cpu_type))
    goto handle_cpu_type_error;

  ret = task_for_pid (mach_task_self (), pid, &task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");
  instance->task = task;

  instance->entrypoint = gum_darwin_find_entrypoint (task);
  if (instance->entrypoint == 0)
    goto handle_entrypoint_error;

  if (!frida_spawn_instance_find_remote_api (instance, &api, error))
    goto error_epilogue;

  ret = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &instance->server_port);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate server");

  ret = mach_vm_allocate (task, &payload_address, FRIDA_SPAWN_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_allocate");
  instance->payload_address = payload_address;

  if (!frida_spawn_instance_emit_redirect_code (instance, redirect_code, &redirect_code_size, error))
    goto error_epilogue;
  instance->overwritten_code = gum_darwin_read (task, instance->entrypoint, redirect_code_size, NULL);
  instance->overwritten_code_size = redirect_code_size;
  ret = mach_vm_protect (task, instance->entrypoint, redirect_code_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");
  ret = mach_vm_write (task, instance->entrypoint, (vm_offset_t) redirect_code, redirect_code_size);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_write(redirect_code)");
  ret = mach_vm_protect (task, instance->entrypoint, redirect_code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");

  if (!frida_spawn_instance_emit_sync_code (instance, &api, sync_code, &sync_code_size, error))
    goto error_epilogue;
  ret = mach_vm_write (task, payload_address + FRIDA_SPAWN_CODE_OFFSET, (vm_offset_t) sync_code, sync_code_size);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_write(sync_code)");

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND_ONCE, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  msg.header.msgh_size = sizeof (msg);
  name = 0x1336;
  do
  {
    name++;
    ret = mach_port_insert_right (task, name, instance->server_port, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  }
  while ((ret == KERN_NAME_EXISTS || ret == KERN_FAILURE) && name < 0xffffffff);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_insert_right");
  msg.header.msgh_remote_port = name;
  msg.header.msgh_local_port = MACH_PORT_NULL; /* filled in by the sync code */
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 1337;
  ret = mach_vm_write (task, payload_address + FRIDA_SPAWN_DATA_OFFSET, (vm_offset_t) &msg, sizeof (msg));
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_write(data)");

  ret = mach_vm_protect (task, payload_address + FRIDA_SPAWN_CODE_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");

  ret = mach_vm_protect (task, payload_address + FRIDA_SPAWN_DATA_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instance_by_pid), GUINT_TO_POINTER (pid), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, task, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  instance->task_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_spawn_instance_on_task_dead);
  dispatch_resume (source);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV, instance->server_port, 0, ctx->dispatch_queue);
  instance->server_recv_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_spawn_instance_on_server_recv);
  dispatch_resume (source);

  kill (pid, SIGCONT);

  return pid;

handle_path_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_EXECUTABLE_NOT_FOUND,
        "Unable to find executable at '%s'",
        path);
    goto error_epilogue;
  }
handle_spawn_error:
  {
    if (spawn_errno == EAGAIN)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': unsupported file format",
          path);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': %s",
          path, g_strerror (spawn_errno));
    }
    goto error_epilogue;
  }
handle_cpu_type_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing CPU type of child process '%s'",
        path);
    goto error_epilogue;
  }
handle_entrypoint_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing entrypoint of child process '%s'",
        path);
    goto error_epilogue;
  }
handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while spawning child process '%s' (%s returned '%s')",
        path, failed_operation, mach_error_string (ret));
    goto error_epilogue;
  }
error_epilogue:
  {
    if (instance != NULL)
    {
      if (instance->pid != 0)
        kill (instance->pid, SIGKILL);
      frida_spawn_instance_free (instance);
    }

    return 0;
  }
}

#ifdef HAVE_IOS

#import "springboard.h"

void
_frida_helper_service_do_launch (FridaHelperService * self, const gchar * identifier, GError ** error)
{
  NSAutoreleasePool * pool;
  UInt32 res;

  pool = [[NSAutoreleasePool alloc] init];

  res = _frida_get_springboard_api ()->SBSLaunchApplicationWithIdentifier (
      [NSString stringWithUTF8String:identifier],
      SBSApplicationLaunchUnlockDevice);
  if (res != 0)
  {
    g_printerr ("SBSLaunchApplicationWithIdentifier(%s) failed: %u\n", identifier, (guint) res);
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while trying to launch iOS app: %u", (guint) res);
  }

  [pool release];
}

#else

void
_frida_helper_service_do_launch (FridaHelperService * self, const gchar * identifier, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not yet able to launch apps on Mac");
}

#endif

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
_frida_helper_service_do_inject (FridaHelperService * self, guint pid, const gchar * dylib_path, const char * data_string, GError ** error)
{
  guint result = 0;
  FridaHelperContext * ctx = self->context;
  FridaInjectInstance * instance;
  FridaAgentDetails details = { 0, };
  const gchar * failed_operation;
  kern_return_t ret;
  FridaMapper * mapper = NULL;
  mach_vm_address_t payload_address = 0;
  guint8 mach_stub_code[512] = { 0, };
  guint8 pthread_stub_code[512] = { 0, };
  FridaAgentContext agent_ctx;
#ifdef HAVE_I386
  x86_thread_state_t state;
#else
  arm_thread_state_t state32;
  arm_unified_thread_state_t state64;
#endif
  thread_state_t state_data;
  mach_msg_type_number_t state_count;
  thread_state_flavor_t state_flavor;
  dispatch_source_t source;

  instance = frida_inject_instance_new (self, self->last_id++);

  details.pid = pid;
  details.dylib_path = dylib_path;
  details.data_string = data_string;

  if (!gum_darwin_cpu_type_from_pid (pid, &details.cpu_type))
    goto handle_cpu_type_error;

  ret = task_for_pid (mach_task_self (), pid, &details.task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");
  instance->task = details.task;

#if ENABLE_MAPPER
  mapper = frida_mapper_new (dylib_path, details.task, details.cpu_type);
#endif

  instance->payload_size = FRIDA_INJECT_BASE_PAYLOAD_SIZE;
  if (mapper != NULL)
    instance->payload_size += frida_mapper_size (mapper);

  ret = mach_vm_allocate (details.task, &payload_address, instance->payload_size, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_allocate");
  instance->payload_address = payload_address;

  if (mapper != NULL)
    frida_mapper_map (mapper, payload_address + FRIDA_INJECT_BASE_PAYLOAD_SIZE);

  ret = mach_vm_protect (details.task, payload_address + FRIDA_INJECT_STACK_GUARD_OFFSET, FRIDA_STACK_GUARD_SIZE, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");

  if (!frida_agent_context_init (&agent_ctx, &details, payload_address, instance->payload_size, error))
    goto error_epilogue;

  frida_agent_context_emit_mach_stub_code (&agent_ctx, mach_stub_code, details.cpu_type, mapper);
  ret = mach_vm_write (details.task, payload_address + FRIDA_INJECT_MACH_CODE_OFFSET,
      (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_write (mach_stub_code)");

  frida_agent_context_emit_pthread_stub_code (&agent_ctx, pthread_stub_code, details.cpu_type, mapper);
  ret = mach_vm_write (details.task, payload_address + FRIDA_INJECT_PTHREAD_CODE_OFFSET,
      (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_write(pthread_stub_code)");

  ret = mach_vm_write (details.task, payload_address + FRIDA_INJECT_DATA_OFFSET, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_write(data)");

  ret = mach_vm_protect (details.task, payload_address + FRIDA_INJECT_CODE_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");

  ret = mach_vm_protect (details.task, payload_address + FRIDA_INJECT_DATA_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_vm_protect");

#ifdef HAVE_I386
  bzero (&state, sizeof (state));

  if (details.cpu_type == GUM_CPU_AMD64)
  {
    x86_thread_state64_t * ts;

    state.tsh.flavor = x86_THREAD_STATE64;
    state.tsh.count = x86_THREAD_STATE64_COUNT;

    ts = &state.uts.ts64;

    ts->__rbp = payload_address + FRIDA_INJECT_DATA_OFFSET;

    ts->__rsp = payload_address + FRIDA_INJECT_STACK_TOP_OFFSET;
    ts->__rip = payload_address + FRIDA_INJECT_MACH_CODE_OFFSET;
  }
  else
  {
    x86_thread_state32_t * ts;

    state.tsh.flavor = x86_THREAD_STATE32;
    state.tsh.count = x86_THREAD_STATE32_COUNT;

    ts = &state.uts.ts32;

    ts->__ebp = payload_address + FRIDA_INJECT_DATA_OFFSET;

    ts->__esp = payload_address + FRIDA_INJECT_STACK_TOP_OFFSET;
    ts->__eip = payload_address + FRIDA_INJECT_MACH_CODE_OFFSET;
  }

  state_data = (thread_state_t) &state;
  state_count = x86_THREAD_STATE_COUNT;
  state_flavor = x86_THREAD_STATE;
#else
  if (details.cpu_type == GUM_CPU_ARM64)
  {
    arm_thread_state64_t * ts;

    bzero (&state64, sizeof (state64));

    state64.ash.flavor = ARM_THREAD_STATE64;
    state64.ash.count = ARM_THREAD_STATE64_COUNT;

    ts = &state64.ts_64;

    ts->__x[20] = payload_address + FRIDA_INJECT_DATA_OFFSET;

    ts->__sp = payload_address + FRIDA_INJECT_STACK_TOP_OFFSET;
    ts->__lr = 0xcafebabe;
    ts->__pc = payload_address + FRIDA_INJECT_MACH_CODE_OFFSET;

    state_data = (thread_state_t) &state64;
    state_count = ARM_UNIFIED_THREAD_STATE_COUNT;
    state_flavor = ARM_UNIFIED_THREAD_STATE;
  }
  else
  {
    bzero (&state32, sizeof (state32));

    state32.__r[7] = payload_address + FRIDA_INJECT_DATA_OFFSET;

    state32.__sp = payload_address + FRIDA_INJECT_STACK_TOP_OFFSET;
    state32.__lr = 0xcafebabe;
    state32.__pc = payload_address + FRIDA_INJECT_MACH_CODE_OFFSET;
    state32.__cpsr = FRIDA_PSR_THUMB;

    state_data = (thread_state_t) &state32;
    state_count = ARM_THREAD_STATE_COUNT;
    state_flavor = ARM_THREAD_STATE;
  }
#endif

  ret = thread_create_running (details.task, state_flavor, state_data, state_count, &instance->thread);
  CHECK_MACH_RESULT (ret, ==, 0, "thread_create_running");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, instance->thread, DISPATCH_MACH_SEND_DEAD,
      ctx->dispatch_queue);
  instance->thread_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_inject_instance_on_event);
  dispatch_resume (source);

  result = instance->id;
  goto beach;

handle_cpu_type_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing CPU type of process with pid %u",
        pid);
    goto error_epilogue;
  }
handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u (%s returned '%s')",
        pid, failed_operation, mach_error_string (ret));
    goto error_epilogue;
  }
error_epilogue:
  {
    frida_inject_instance_free (instance);
    goto beach;
  }
beach:
  {
    if (mapper != NULL)
      frida_mapper_free (mapper);

    return result;
  }
}

void
_frida_helper_service_free_inject_instance (FridaHelperService * self, void * instance)
{
  frida_inject_instance_free (instance);
}

void
_frida_helper_service_do_make_pipe_endpoints (guint local_pid, guint remote_pid, FridaPipeEndpoints * result, GError ** error)
{
  gboolean remote_pid_exists;
  mach_port_t self_task;
  mach_port_t local_task = MACH_PORT_NULL;
  mach_port_t remote_task = MACH_PORT_NULL;
  mach_port_name_t local_rx = MACH_PORT_NULL;
  mach_port_name_t local_tx = MACH_PORT_NULL;
  mach_port_name_t remote_rx = MACH_PORT_NULL;
  mach_port_name_t remote_tx = MACH_PORT_NULL;
  mach_port_name_t tx = MACH_PORT_NULL;
  kern_return_t ret;
  const gchar * failed_operation;
  mach_msg_type_name_t acquired_type;
  gchar * local_address, * remote_address;

  remote_pid_exists = kill (remote_pid, 0) == 0 || errno == EPERM;
  if (!remote_pid_exists)
    goto handle_pid_error;

  self_task = mach_task_self ();

  ret = task_for_pid (self_task, local_pid, &local_task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid() for local pid");

  ret = task_for_pid (self_task, remote_pid, &remote_task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid() for remote pid");

  ret = mach_port_allocate (local_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate local_rx");

  ret = mach_port_allocate (remote_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate remote_rx");

  ret = mach_port_extract_right (remote_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_extract_right local_tx");
  local_tx = local_rx;
  do
  {
    local_tx++;
    ret = mach_port_insert_right (local_task, local_tx, tx, MACH_MSG_TYPE_COPY_SEND);
  }
  while ((ret == KERN_NAME_EXISTS || ret == KERN_FAILURE) && remote_tx < 0xffffffff);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_insert_right local_tx");
  mach_port_mod_refs (self_task, tx, MACH_PORT_RIGHT_SEND, -1);
  tx = MACH_PORT_NULL;

  ret = mach_port_extract_right (local_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_extract_right remote_tx");
  remote_tx = remote_rx;
  do
  {
    remote_tx++;
    ret = mach_port_insert_right (remote_task, remote_tx, tx, MACH_MSG_TYPE_COPY_SEND);
  }
  while ((ret == KERN_NAME_EXISTS || ret == KERN_FAILURE) && remote_tx < 0xffffffff);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_insert_right remote_tx");
  mach_port_mod_refs (self_task, tx, MACH_PORT_RIGHT_SEND, -1);
  tx = MACH_PORT_NULL;

  local_address = g_strdup_printf ("pipe:rx=%d,tx=%d", local_rx, local_tx);
  remote_address = g_strdup_printf ("pipe:rx=%d,tx=%d", remote_rx, remote_tx);
  frida_pipe_endpoints_init (result, local_address, remote_address);
  g_free (remote_address);
  g_free (local_address);

  goto beach;

handle_pid_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PROCESS_NOT_FOUND,
        "Unable to find process with pid %u",
        remote_pid);
    goto beach;
  }
handle_mach_error:
  {
    if (remote_task == MACH_PORT_NULL && ret == KERN_FAILURE)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to access process with pid %u from the current user account",
          remote_pid);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while preparing pipe endpoints for process with pid %u (%s returned '%s')",
          remote_pid, failed_operation, mach_error_string (ret));
    }

    if (tx != MACH_PORT_NULL)
      mach_port_mod_refs (self_task, tx, MACH_PORT_RIGHT_SEND, -1);
    if (remote_tx != MACH_PORT_NULL)
      mach_port_mod_refs (remote_task, remote_tx, MACH_PORT_RIGHT_SEND, -1);
    if (local_tx != MACH_PORT_NULL)
      mach_port_mod_refs (local_task, local_tx, MACH_PORT_RIGHT_SEND, -1);
    if (remote_rx != MACH_PORT_NULL)
      mach_port_mod_refs (remote_task, remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
    if (local_rx != MACH_PORT_NULL)
      mach_port_mod_refs (local_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    goto beach;
  }
beach:
  {
    if (remote_task != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_task);
    if (local_task != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_task);

    return;
  }
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaHelperService * service)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
  instance->service = g_object_ref (service);
  instance->task = MACH_PORT_NULL;
  instance->task_monitor_source = NULL;

  instance->overwritten_code = NULL;

  instance->server_port = MACH_PORT_NULL;
  instance->reply_port = MACH_PORT_NULL;
  instance->server_recv_source = NULL;

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  task_t self_task = mach_task_self ();

  if (instance->server_recv_source != NULL)
    dispatch_release (instance->server_recv_source);
  if (instance->reply_port != MACH_PORT_NULL)
    mach_port_mod_refs (self_task, instance->reply_port, MACH_PORT_RIGHT_SEND_ONCE, -1);
  if (instance->server_port != MACH_PORT_NULL)
    mach_port_mod_refs (self_task, instance->server_port, MACH_PORT_RIGHT_RECEIVE, -1);

  g_free (instance->overwritten_code);

  if (instance->task_monitor_source != NULL)
    dispatch_release (instance->task_monitor_source);
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->service);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  FridaSpawnMessageTx msg;

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_remote_port = self->reply_port;
  msg.header.msgh_local_port = MACH_PORT_NULL;
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 1437;
  mach_msg_send (&msg.header);

  self->reply_port = MACH_PORT_NULL;
}

static void
frida_spawn_instance_on_task_dead (void * context)
{
  FridaSpawnInstance * self = context;

  _frida_helper_service_on_spawn_instance_dead (self->service, self->pid);
}

static void
frida_spawn_instance_on_server_recv (void * context)
{
  FridaSpawnInstance * self = context;
  FridaSpawnMessageRx msg;
  kern_return_t ret;

  bzero (&msg, sizeof (msg));
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_local_port = self->server_port;
  ret = mach_msg_receive (&msg.header);
  g_assert_cmpint (ret, ==, 0);
  g_assert_cmpint (msg.header.msgh_id, ==, 1337);
  self->reply_port = msg.header.msgh_remote_port;

  mach_vm_protect (self->task, self->entrypoint, self->overwritten_code_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  mach_vm_write (self->task, self->entrypoint, (vm_offset_t) self->overwritten_code, self->overwritten_code_size);
  mach_vm_protect (self->task, self->entrypoint, self->overwritten_code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

  _frida_helper_service_on_spawn_instance_ready (self->service, self->pid);
}

static gboolean
frida_spawn_instance_find_remote_api (FridaSpawnInstance * self, FridaSpawnApi * api, GError ** error)
{
  FridaSpawnFillContext fill_ctx;

  fill_ctx.api = api;
  fill_ctx.remaining = 5;
  gum_darwin_enumerate_exports (self->task, FRIDA_SYSTEM_LIBC, frida_spawn_fill_context_process_export, &fill_ctx);

  if (fill_ctx.remaining > 0)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving functions");
    return FALSE;
  }

  return TRUE;
}

#define FRIDA_SPAWN_API_ASSIGN_AND_RETURN_IF_MATCHING(field) \
  if (strcmp (details->name, G_STRINGIFY (field)) == 0) \
  { \
    ctx->api->field##_impl = details->address; \
    ctx->remaining--; \
    return ctx->remaining != 0; \
  }

static gboolean
frida_spawn_fill_context_process_export (const GumExportDetails * details, gpointer user_data)
{
  FridaSpawnFillContext * ctx = user_data;

  if (details->type != GUM_EXPORT_FUNCTION)
    return TRUE;

  FRIDA_SPAWN_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_task_self);
  FRIDA_SPAWN_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_port_allocate);
  FRIDA_SPAWN_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_port_deallocate);
  FRIDA_SPAWN_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_msg);
  FRIDA_SPAWN_API_ASSIGN_AND_RETURN_IF_MATCHING (abort);

  return TRUE;
}

#if defined (HAVE_ARM) || defined (HAVE_ARM64)

static gboolean
frida_spawn_instance_emit_redirect_code (FridaSpawnInstance * self, guint8 * code, guint * code_size, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not yet implemented for ARM");
  return FALSE;
}

static gboolean
frida_spawn_instance_emit_sync_code (FridaSpawnInstance * self, const FridaSpawnApi * api, guint8 * code, guint * code_size, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not yet implemented for ARM");
  return FALSE;
}

#else

static gboolean
frida_spawn_instance_emit_redirect_code (FridaSpawnInstance * self, guint8 * code, guint * code_size, GError ** error)
{
  GumX86Writer cw;

  gum_x86_writer_init (&cw, code);
  gum_x86_writer_set_target_cpu (&cw, self->cpu_type);

  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder for entrypoint */
  gum_x86_writer_put_pushax (&cw);

  /* fill in the entrypoint so we can ret to it later */
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, self->entrypoint);
  if (self->cpu_type == GUM_CPU_IA32)
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_XSP, 8 * sizeof (guint32), GUM_REG_XAX);
  else
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_XSP, 16 * sizeof (guint64), GUM_REG_XAX);

  /* transfer to the sync code */
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, self->payload_address + FRIDA_SPAWN_CODE_OFFSET);
  gum_x86_writer_put_jmp_reg (&cw, GUM_REG_XAX);

  gum_x86_writer_flush (&cw);
  *code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_free (&cw);

  return TRUE;
}

static gboolean
frida_spawn_instance_emit_sync_code (FridaSpawnInstance * self, const FridaSpawnApi * api, guint8 * code, guint * code_size, GError ** error)
{
  GumX86Writer cw;
  gconstpointer panic_label = "frida_spawn_instance_panic";

  gum_x86_writer_init (&cw, code);
  gum_x86_writer_set_target_cpu (&cw, self->cpu_type);

  /* xax = mach_task_self (); */
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, api->mach_task_self_impl);
  gum_x86_writer_put_call_reg (&cw, GUM_REG_XAX);

  /* mach_port_allocate (xax, MACH_PORT_RIGHT_RECEIVE, &xbp); */
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, api->mach_port_allocate_impl);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* reserve space */
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XBP, GUM_REG_XSP);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XBX, 3,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_POINTER, GSIZE_TO_POINTER (MACH_PORT_RIGHT_RECEIVE),
      GUM_ARG_REGISTER, GUM_REG_XBP);
  gum_x86_writer_put_mov_reg_reg_ptr (&cw, GUM_REG_XBP, GUM_REG_XBP);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX); /* release space */

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, api->mach_msg_impl);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, self->payload_address + FRIDA_SPAWN_DATA_OFFSET);

  /* xbx->header.msgh_local_port = *xbp; */
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_XBX, G_STRUCT_OFFSET (FridaSpawnMessageTx, header.msgh_local_port), GUM_REG_EBP);

  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX, 7,
      GUM_ARG_REGISTER, GUM_REG_XBX,                                    /* header           */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (MACH_SEND_MSG | MACH_RCV_MSG), /* flags            */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (sizeof (FridaSpawnMessageTx)), /* send size        */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (sizeof (FridaSpawnMessageRx)), /* max receive size */
      GUM_ARG_REGISTER, GUM_REG_XBP,                                    /* receive port     */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (MACH_MSG_TIMEOUT_NONE),        /* timeout          */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (MACH_PORT_NULL)                /* notification     */
  );
  gum_x86_writer_put_test_reg_reg (&cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jcc_short_label (&cw, GUM_X86_JNZ, panic_label, GUM_UNLIKELY);

  /* mach_port_deallocate (mach_task_self (), xbp); */
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, api->mach_task_self_impl);
  gum_x86_writer_put_call_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, api->mach_port_deallocate_impl);
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XBX, 2,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_REGISTER, GUM_REG_XBP);

  gum_x86_writer_put_popax (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, panic_label);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, api->abort_impl);
  gum_x86_writer_put_call_reg (&cw, GUM_REG_XBX);

  gum_x86_writer_flush (&cw);
  *code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_free (&cw);

  return TRUE;
}

#endif

static FridaInjectInstance *
frida_inject_instance_new (FridaHelperService * service, guint id)
{
  FridaInjectInstance * instance;

  instance = g_slice_new (FridaInjectInstance);
  instance->service = g_object_ref (service);
  instance->id = id;
  instance->task = MACH_PORT_NULL;
  instance->payload_address = 0;
  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  return instance;
}

static void
frida_inject_instance_free (FridaInjectInstance * instance)
{
  task_t self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);
  if (instance->payload_address != 0)
    mach_vm_deallocate (instance->task, instance->payload_address, instance->payload_size);
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->service);
  g_slice_free (FridaInjectInstance, instance);
}

static void
frida_inject_instance_on_event (void * context)
{
  FridaInjectInstance * instance = context;

  _frida_helper_service_on_inject_instance_dead (instance->service, instance->id);
}

static gboolean
frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GError ** error)
{
  memset (self, 0, sizeof (FridaAgentContext));

  if (!frida_agent_context_init_functions (self, details, error))
    return FALSE;

  self->thread_self_data = payload_base + FRIDA_INJECT_THREAD_SELF_OFFSET;

  if (details->cpu_type == GUM_CPU_ARM)
    self->pthread_create_start_routine = payload_base + FRIDA_INJECT_PTHREAD_CODE_OFFSET + 1;
  else
    self->pthread_create_start_routine = payload_base + FRIDA_INJECT_PTHREAD_CODE_OFFSET;
  self->pthread_create_arg = payload_base + FRIDA_INJECT_DATA_OFFSET;

  self->dylib_path = payload_base + FRIDA_INJECT_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, dylib_path_data);
  strcpy (self->dylib_path_data, details->dylib_path);
  self->dlopen_mode = RTLD_LAZY;

  self->entrypoint_name = payload_base + FRIDA_INJECT_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, entrypoint_name_data);
  strcpy (self->entrypoint_name_data, FRIDA_AGENT_ENTRYPOINT_NAME);
  self->data_string = payload_base + FRIDA_INJECT_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, data_string_data);
  g_assert_cmpint (strlen (details->data_string), <, sizeof (self->data_string_data));
  strcpy (self->data_string_data, details->data_string);
  self->mapped_range = payload_base + FRIDA_INJECT_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, mapped_range_data);
  self->mapped_range_data.base_address = payload_base;
  self->mapped_range_data.size = payload_size;

  return TRUE;
}

static gboolean
frida_agent_context_init_functions (FridaAgentContext * self, const FridaAgentDetails * details, GError ** error)
{
  FridaAgentFillContext fill_ctx;
  gboolean resolved_all;
  gboolean resolved_all_except_cthread_set_self;

  fill_ctx.agent = self;
  fill_ctx.remaining = 9;
  gum_darwin_enumerate_exports (details->task, FRIDA_SYSTEM_LIBC, frida_agent_fill_context_process_export, &fill_ctx);

  resolved_all = fill_ctx.remaining == 0;
  resolved_all_except_cthread_set_self = fill_ctx.remaining == 1 && self->cthread_set_self_impl == 0;

  if (!resolved_all && !resolved_all_except_cthread_set_self)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving functions");
    return FALSE;
  }

  return TRUE;
}

#define FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING(field) \
  if (strcmp (details->name, G_STRINGIFY (field)) == 0) \
  { \
    ctx->agent->field##_impl = details->address; \
    ctx->remaining--; \
    return ctx->remaining != 0; \
  }

static gboolean
frida_agent_fill_context_process_export (const GumExportDetails * details, gpointer user_data)
{
  FridaAgentFillContext * ctx = user_data;

  if (details->type != GUM_EXPORT_FUNCTION)
    return TRUE;

  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (_pthread_set_self);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (cthread_set_self);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (pthread_create);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (pthread_join);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (thread_terminate);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (mach_thread_self);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (dlopen);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (dlsym);
  FRIDA_AGENT_CTX_ASSIGN_AND_RETURN_IF_MATCHING (dlclose);

  return TRUE;
}

#ifdef HAVE_I386

static void frida_agent_context_emit_thread_id_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_pthread_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_pthread_create_and_join (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_thread_terminate (FridaAgentContext * self, FridaAgentEmitContext * ctx);

static void frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);

static void
frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, FridaMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, cpu_type);
  ctx.mapper = mapper;

  frida_agent_context_emit_thread_id_setup (self, &ctx);
  frida_agent_context_emit_pthread_setup (self, &ctx);
  frida_agent_context_emit_pthread_create_and_join (self, &ctx);
  frida_agent_context_emit_thread_terminate (self, &ctx);
  gum_x86_writer_put_breakpoint (&ctx.cw);

  gum_x86_writer_free (&ctx.cw);
}

static void
frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, FridaMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, cpu_type);
  ctx.mapper = mapper;

  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XSI);

  if (ctx.cw.target_cpu == GUM_CPU_IA32)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx.cw, GUM_REG_XBP,
        GUM_REG_XSP, 16);
  }
  else
  {
    gum_x86_writer_put_mov_reg_reg (&ctx.cw, GUM_REG_XBP, GUM_REG_XDI);
  }

  frida_agent_context_emit_pthread_stub_body (self, &ctx);

  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XSI);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&ctx.cw);

  gum_x86_writer_free (&ctx.cw);
}

#define FRIDA_EMIT_LOAD(reg, field) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_##reg, GUM_REG_XBP, G_STRUCT_OFFSET (FridaAgentContext, field))
#define FRIDA_EMIT_STORE(field, reg) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_REG_XBP, G_STRUCT_OFFSET (FridaAgentContext, field), GUM_REG_##reg)
#define FRIDA_EMIT_MOVE(dstreg, srcreg) \
    gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_##dstreg, GUM_REG_##srcreg)
#define FRIDA_EMIT_CALL(fun, ...) \
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XBP, G_STRUCT_OFFSET (FridaAgentContext, fun), __VA_ARGS__)

static void
frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  if (ctx->mapper != NULL)
  {
    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, frida_mapper_constructor (ctx->mapper));
    gum_x86_writer_put_call_reg (&ctx->cw, GUM_REG_XAX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, frida_mapper_resolve (ctx->mapper, FRIDA_AGENT_ENTRYPOINT_NAME));
    FRIDA_EMIT_LOAD (XCX, data_string);
    FRIDA_EMIT_LOAD (XSI, mapped_range);
    FRIDA_EMIT_LOAD (XDX, thread_id);
    gum_x86_writer_put_call_reg_with_arguments (&ctx->cw,
        GUM_CALL_CAPI, GUM_REG_XAX, 3,
        GUM_ARG_REGISTER, GUM_REG_XCX,
        GUM_ARG_REGISTER, GUM_REG_XSI,
        GUM_ARG_REGISTER, GUM_REG_XDX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, frida_mapper_destructor (ctx->mapper));
    gum_x86_writer_put_call_reg (&ctx->cw, GUM_REG_XAX);
  }
  else
  {
    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 8);

    FRIDA_EMIT_LOAD (XAX, dylib_path);
    FRIDA_EMIT_LOAD (XDX, dlopen_mode);
    FRIDA_EMIT_CALL (dlopen_impl, 2,
        GUM_ARG_REGISTER, GUM_REG_XAX,
        GUM_ARG_REGISTER, GUM_REG_XDX);
    FRIDA_EMIT_MOVE (XBX, XAX);

    FRIDA_EMIT_LOAD (XAX, entrypoint_name);
    FRIDA_EMIT_CALL (dlsym_impl, 2,
        GUM_ARG_REGISTER, GUM_REG_XBX,
        GUM_ARG_REGISTER, GUM_REG_XAX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

    FRIDA_EMIT_LOAD (XCX, data_string);
    FRIDA_EMIT_LOAD (XDX, thread_id);
    gum_x86_writer_put_call_reg_with_arguments (&ctx->cw,
        GUM_CALL_CAPI, GUM_REG_XAX, 3,
        GUM_ARG_REGISTER, GUM_REG_XCX,
        GUM_ARG_POINTER, NULL,
        GUM_ARG_REGISTER, GUM_REG_XDX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 8);

    FRIDA_EMIT_CALL (dlclose_impl, 1,
        GUM_ARG_REGISTER, GUM_REG_XBX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 12);
  }
}

static void
frida_agent_context_emit_thread_id_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  FRIDA_EMIT_CALL (mach_thread_self_impl, 0);
  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XBX, GUM_REG_XAX);
  FRIDA_EMIT_STORE (thread_id, XBX);
}

static void
frida_agent_context_emit_pthread_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  FRIDA_EMIT_LOAD (XAX, thread_self_data);
  FRIDA_EMIT_CALL (_pthread_set_self_impl, 1, GUM_ARG_REGISTER, GUM_REG_XAX);

  if (self->cthread_set_self_impl != 0)
  {
    FRIDA_EMIT_LOAD (XAX, thread_self_data);
    FRIDA_EMIT_CALL (cthread_set_self_impl, 1, GUM_ARG_REGISTER, GUM_REG_XAX);
  }
}

static void
frida_agent_context_emit_pthread_create_and_join (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 16);
  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XAX, GUM_REG_XSP);
  FRIDA_EMIT_LOAD (XDX, pthread_create_start_routine);
  FRIDA_EMIT_LOAD (XCX, pthread_create_arg);
  FRIDA_EMIT_CALL (pthread_create_impl, 4,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_POINTER, NULL,
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_x86_writer_put_pop_reg (&ctx->cw, GUM_REG_XAX);
  gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 8);
  FRIDA_EMIT_CALL (pthread_join_impl, 2,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_POINTER, NULL);
}

static void
frida_agent_context_emit_thread_terminate (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  FRIDA_EMIT_CALL (thread_terminate_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XBX);
}

#undef FRIDA_EMIT_LOAD
#undef FRIDA_EMIT_STORE
#undef FRIDA_EMIT_MOVE
#undef FRIDA_EMIT_CALL

#else

/*
 * ARM 32- and 64-bit
 */

static void frida_agent_context_emit_arm_mach_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper);
static void frida_agent_context_emit_arm_pthread_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper);
static void frida_agent_context_emit_arm_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_thread_id_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_pthread_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_pthread_create_and_join (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_thread_terminate (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw);
static void frida_agent_context_emit_arm_store_reg_in_ctx_value (guint field_offset, GumArmReg reg, GumThumbWriter * tw);

static void frida_agent_context_emit_arm64_mach_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper);
static void frida_agent_context_emit_arm64_pthread_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper);
static void frida_agent_context_emit_arm64_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm64_thread_id_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm64_pthread_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm64_pthread_create_and_join (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm64_thread_terminate (FridaAgentContext * self, FridaAgentEmitContext * ctx);

static void
frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, FridaMapper * mapper)
{
  if (cpu_type == GUM_CPU_ARM)
    frida_agent_context_emit_arm_mach_stub_code (self, code, mapper);
  else
    frida_agent_context_emit_arm64_mach_stub_code (self, code, mapper);
}

static void
frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, FridaMapper * mapper)
{
  if (cpu_type == GUM_CPU_ARM)
    frida_agent_context_emit_arm_pthread_stub_code (self, code, mapper);
  else
    frida_agent_context_emit_arm64_pthread_stub_code (self, code, mapper);
}


/*
 * ARM 32-bit
 */

static void
frida_agent_context_emit_arm_mach_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);
  ctx.mapper = mapper;

  frida_agent_context_emit_arm_thread_id_setup (self, &ctx);
  frida_agent_context_emit_arm_pthread_setup (self, &ctx);
  frida_agent_context_emit_arm_pthread_create_and_join (self, &ctx);
  frida_agent_context_emit_arm_thread_terminate (self, &ctx);

  gum_thumb_writer_free (&ctx.tw);
}

static void
frida_agent_context_emit_arm_pthread_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);
  ctx.mapper = mapper;

  gum_thumb_writer_put_push_regs (&ctx.tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_LR);
  gum_thumb_writer_put_mov_reg_reg (&ctx.tw, GUM_AREG_R7, GUM_AREG_R0);
  frida_agent_context_emit_arm_pthread_stub_body (self, &ctx);
  gum_thumb_writer_put_pop_regs (&ctx.tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_PC);

  gum_thumb_writer_free (&ctx.tw);
}

#define EMIT_ARM_LOAD(reg, field) \
    frida_agent_context_emit_arm_load_reg_with_ctx_value (GUM_AREG_##reg, G_STRUCT_OFFSET (FridaAgentContext, field), &ctx->tw)
#define EMIT_ARM_STORE(field, reg) \
    frida_agent_context_emit_arm_store_reg_in_ctx_value (G_STRUCT_OFFSET (FridaAgentContext, field), GUM_AREG_##reg, &ctx->tw)
#define EMIT_ARM_LOAD_U32(reg, val) \
    gum_thumb_writer_put_ldr_reg_u32 (&ctx->tw, GUM_AREG_##reg, val)
#define EMIT_ARM_MOVE(dstreg, srcreg) \
    gum_thumb_writer_put_mov_reg_reg (&ctx->tw, GUM_AREG_##dstreg, GUM_AREG_##srcreg)
#define EMIT_ARM_CALL(reg) \
    gum_thumb_writer_put_blx_reg (&ctx->tw, GUM_AREG_##reg)

static void
frida_agent_context_emit_arm_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  if (ctx->mapper != NULL)
  {
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, GUM_AREG_R0, frida_mapper_constructor (ctx->mapper));
    EMIT_ARM_CALL (R0);

    EMIT_ARM_LOAD (R2, thread_id);
    EMIT_ARM_LOAD (R1, mapped_range);
    EMIT_ARM_LOAD (R0, data_string);
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, GUM_AREG_R5, frida_mapper_resolve (ctx->mapper, FRIDA_AGENT_ENTRYPOINT_NAME));
    EMIT_ARM_CALL (R5);

    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, GUM_AREG_R0, frida_mapper_destructor (ctx->mapper));
    EMIT_ARM_CALL (R0);
  }
  else
  {
    EMIT_ARM_LOAD (R1, dlopen_mode);
    EMIT_ARM_LOAD (R0, dylib_path);
    EMIT_ARM_LOAD (R3, dlopen_impl);
    EMIT_ARM_CALL (R3);
    EMIT_ARM_MOVE (R4, R0);

    EMIT_ARM_LOAD (R1, entrypoint_name);
    EMIT_ARM_MOVE (R0, R4);
    EMIT_ARM_LOAD (R3, dlsym_impl);
    EMIT_ARM_CALL (R3);
    EMIT_ARM_MOVE (R5, R0);

    EMIT_ARM_LOAD (R2, thread_id);
    EMIT_ARM_LOAD_U32 (R1, 0);
    EMIT_ARM_LOAD (R0, data_string);
    EMIT_ARM_CALL (R5);

    EMIT_ARM_MOVE (R0, R4);
    EMIT_ARM_LOAD (R3, dlclose_impl);
    EMIT_ARM_CALL (R3);
  }
}

static void
frida_agent_context_emit_arm_thread_id_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM_LOAD (R4, mach_thread_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_MOVE (R6, R0);
  EMIT_ARM_STORE (thread_id, R6);
}

static void
frida_agent_context_emit_arm_pthread_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM_LOAD (R5, thread_self_data);

  EMIT_ARM_MOVE (R0, R5);
  EMIT_ARM_LOAD (R4, _pthread_set_self_impl);
  EMIT_ARM_CALL (R4);

  if (self->cthread_set_self_impl != 0)
  {
    EMIT_ARM_MOVE (R0, R5);
    EMIT_ARM_LOAD (R4, cthread_set_self_impl);
    EMIT_ARM_CALL (R4);
  }
}

static void
frida_agent_context_emit_arm_pthread_create_and_join (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM_LOAD (R3, pthread_create_arg);
  EMIT_ARM_LOAD (R2, pthread_create_start_routine);
  EMIT_ARM_LOAD_U32 (R1, 0);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, GUM_AREG_R0);
  EMIT_ARM_MOVE (R0, SP);
  EMIT_ARM_LOAD (R4, pthread_create_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_LOAD_U32 (R1, 0);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, GUM_AREG_R0);
  EMIT_ARM_LOAD (R4, pthread_join_impl);
  EMIT_ARM_CALL (R4);
}

static void
frida_agent_context_emit_arm_thread_terminate (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM_MOVE (R0, R6);
  EMIT_ARM_LOAD (R4, thread_terminate_impl);
  EMIT_ARM_CALL (R4);
}

#undef EMIT_ARM_LOAD
#undef EMIT_ARM_STORE
#undef EMIT_ARM_MOVE
#undef EMIT_ARM_CALL

static void
frida_agent_context_emit_arm_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw)
{
  GumArmReg tmp_reg = reg != GUM_AREG_R0 ? GUM_AREG_R0 : GUM_AREG_R1;
  gum_thumb_writer_put_push_regs (tw, 1, tmp_reg);
  gum_thumb_writer_put_ldr_reg_u32 (tw, tmp_reg, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, reg, GUM_AREG_R7, tmp_reg);
  gum_thumb_writer_put_ldr_reg_reg (tw, reg, reg);
  gum_thumb_writer_put_pop_regs (tw, 1, tmp_reg);
}

static void
frida_agent_context_emit_arm_store_reg_in_ctx_value (guint field_offset, GumArmReg reg, GumThumbWriter * tw)
{
  GumArmReg tmp_reg = reg != GUM_AREG_R0 ? GUM_AREG_R0 : GUM_AREG_R1;
  gum_thumb_writer_put_push_regs (tw, 1, tmp_reg);
  gum_thumb_writer_put_ldr_reg_u32 (tw, tmp_reg, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, tmp_reg, GUM_AREG_R7, tmp_reg);
  gum_thumb_writer_put_str_reg_reg (tw, reg, tmp_reg);
  gum_thumb_writer_put_pop_regs (tw, 1, tmp_reg);
}


/*
 * ARM 64-bit
 */

static void
frida_agent_context_emit_arm64_mach_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_arm64_writer_init (&ctx.aw, ctx.code);
  ctx.mapper = mapper;

  gum_arm64_writer_put_push_reg_reg (&ctx.aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, GUM_A64REG_FP, GUM_A64REG_SP);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, GUM_A64REG_X21, GUM_A64REG_X22);
  frida_agent_context_emit_arm64_thread_id_setup (self, &ctx);
  frida_agent_context_emit_arm64_pthread_setup (self, &ctx);
  frida_agent_context_emit_arm64_pthread_create_and_join (self, &ctx);
  frida_agent_context_emit_arm64_thread_terminate (self, &ctx);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, GUM_A64REG_X21, GUM_A64REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_ret (&ctx.aw);

  gum_arm64_writer_free (&ctx.aw);
}

static void
frida_agent_context_emit_arm64_pthread_stub_code (FridaAgentContext * self, guint8 * code, FridaMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_arm64_writer_init (&ctx.aw, ctx.code);
  ctx.mapper = mapper;

  gum_arm64_writer_put_push_reg_reg (&ctx.aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, GUM_A64REG_FP, GUM_A64REG_SP);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, GUM_A64REG_X20, GUM_A64REG_X0);
  frida_agent_context_emit_arm64_pthread_stub_body (self, &ctx);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_ret (&ctx.aw);
  gum_arm64_writer_free (&ctx.aw);
}

#define EMIT_ARM64_LOAD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&ctx->aw, GUM_A64REG_##reg, GUM_A64REG_X20, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_ARM64_LOAD_U64(reg, val) \
    gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, GUM_A64REG_##reg, val)
#define EMIT_ARM64_STORE(field, reg) \
    gum_arm64_writer_put_str_reg_reg_offset (&ctx->aw, GUM_A64REG_##reg, GUM_A64REG_X20, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_ARM64_MOVE(dstreg, srcreg) \
    gum_arm64_writer_put_mov_reg_reg (&ctx->aw, GUM_A64REG_##dstreg, GUM_A64REG_##srcreg)
#define EMIT_ARM64_CALL(reg) \
    gum_arm64_writer_put_blr_reg (&ctx->aw, GUM_A64REG_##reg)

static void
frida_agent_context_emit_arm64_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  if (ctx->mapper != NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, GUM_A64REG_X0, frida_mapper_constructor (ctx->mapper));
    EMIT_ARM64_CALL (X0);

    EMIT_ARM64_LOAD (X2, thread_id);
    EMIT_ARM64_LOAD (X1, mapped_range);
    EMIT_ARM64_LOAD (X0, data_string);
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, GUM_A64REG_X8, frida_mapper_resolve (ctx->mapper, FRIDA_AGENT_ENTRYPOINT_NAME));
    EMIT_ARM64_CALL (X8);

    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, GUM_A64REG_X0, frida_mapper_destructor (ctx->mapper));
    EMIT_ARM64_CALL (X0);
  }
  else
  {
    EMIT_ARM64_LOAD (X1, dlopen_mode);
    EMIT_ARM64_LOAD (X0, dylib_path);
    EMIT_ARM64_LOAD (X8, dlopen_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X19, X0);

    EMIT_ARM64_LOAD (X1, entrypoint_name);
    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X8, dlsym_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X8, X0);

    EMIT_ARM64_LOAD (X2, thread_id);
    EMIT_ARM64_LOAD_U64 (X1, 0);
    EMIT_ARM64_LOAD (X0, data_string);
    EMIT_ARM64_CALL (X8);

    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X8, dlclose_impl);
    EMIT_ARM64_CALL (X8);
  }
}

static void
frida_agent_context_emit_arm64_thread_id_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM64_LOAD (X8, mach_thread_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_MOVE (X21, X0);
  EMIT_ARM64_STORE (thread_id, X21);
}

static void
frida_agent_context_emit_arm64_pthread_setup (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM64_LOAD (X19, thread_self_data);

  EMIT_ARM64_MOVE (X0, X19);
  EMIT_ARM64_LOAD (X8, _pthread_set_self_impl);
  EMIT_ARM64_CALL (X8);

  if (self->cthread_set_self_impl != 0)
  {
    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X8, cthread_set_self_impl);
    EMIT_ARM64_CALL (X8);
  }
}

static void
frida_agent_context_emit_arm64_pthread_create_and_join (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM64_LOAD (X3, pthread_create_arg);
  EMIT_ARM64_LOAD (X2, pthread_create_start_routine);
  EMIT_ARM64_LOAD_U64 (X1, 0);
  gum_arm64_writer_put_push_reg_reg (&ctx->aw, GUM_A64REG_X0, GUM_A64REG_X1);
  EMIT_ARM64_MOVE (X0, SP);
  EMIT_ARM64_LOAD (X8, pthread_create_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD_U64 (X1, 0);
  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, GUM_A64REG_X0, GUM_A64REG_X1);
  EMIT_ARM64_LOAD (X8, pthread_join_impl);
  EMIT_ARM64_CALL (X8);
}

static void
frida_agent_context_emit_arm64_thread_terminate (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  EMIT_ARM64_MOVE (X0, X21);
  EMIT_ARM64_LOAD (X8, thread_terminate_impl);
  EMIT_ARM64_CALL (X8);
}

#undef EMIT_ARM64_LOAD
#undef EMIT_ARM64_STORE
#undef EMIT_ARM64_MOVE
#undef EMIT_ARM64_CALL

#endif

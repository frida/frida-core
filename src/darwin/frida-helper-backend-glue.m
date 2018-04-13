#include "frida-helper-backend.h"

#include <capstone.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#import <Foundation/Foundation.h>
#include <glib-unix.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumarmwriter.h>
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#include <gum/gum.h>
#include <gum/gumdarwin.h>
#include <mach-o/loader.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#define FRIDA_PSR_THUMB                  0x20

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }
#define CHECK_BSD_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_bsd_error; \
  }

typedef struct _FridaHelperContext FridaHelperContext;
typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaSpawnInstanceDyldData FridaSpawnInstanceDyldData;
typedef guint FridaBreakpointPhase;
typedef struct _FridaInjectInstance FridaInjectInstance;
typedef struct _FridaInjectPayloadLayout FridaInjectPayloadLayout;
typedef struct _FridaAgentDetails FridaAgentDetails;
typedef struct _FridaAgentContext FridaAgentContext;
typedef struct _FridaAgentEmitContext FridaAgentEmitContext;

typedef struct _FridaExceptionPortSet FridaExceptionPortSet;
typedef union _FridaDebugState FridaDebugState;

struct _FridaHelperContext
{
  dispatch_queue_t dispatch_queue;
};

struct _FridaExceptionPortSet
{
  mach_msg_type_number_t count;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
};

union _FridaDebugState
{
#ifdef HAVE_I386
  x86_debug_state_t state;
#else
  arm_debug_state_t s32;
  arm_debug_state64_t s64;
#endif
};

struct _FridaSpawnInstance
{
  FridaDarwinHelperBackend * backend;
  guint pid;
  GumCpuType cpu_type;
  mach_port_t thread;
  FridaDebugState previous_debug_state;
  FridaDebugState dlerror_clear_debug_state;
  FridaDebugState ret_gadget_debug_state;
  FridaDebugState breakpoint_debug_state;

  mach_port_t server_port;
  dispatch_source_t server_recv_source;
  FridaExceptionPortSet previous_ports;

  __Request__exception_raise_state_identity_t pending_request;

  FridaBreakpointPhase breakpoint_phase;
  mach_vm_address_t lib_name;
  mach_vm_address_t fake_helpers;
  mach_vm_address_t dyld_data;
  GumAddress modern_entry_address;
  GumAddress dlopen_address;
  GumAddress info_address;
  GumAddress register_helpers_address;
  GumAddress helpers_ptr_address;
  GumAddress ret_gadget;
  mach_port_t task;
  GumDarwinUnifiedThreadState previous_thread_state;
};

enum _FridaBreakpointPhase
{
  FRIDA_BREAKPOINT_DETECT_FLAVOR,
  FRIDA_BREAKPOINT_SET_HELPERS,
  FRIDA_BREAKPOINT_DLOPEN_LIBC,
  FRIDA_BREAKPOINT_SKIP_CLEAR,
  FRIDA_BREAKPOINT_JUST_RETURN,
  FRIDA_BREAKPOINT_CLEANUP,
  FRIDA_BREAKPOINT_DONE
};

struct _FridaSpawnInstanceDyldData
{
  const char libc[32];
  guint8 helpers[32];
};

struct _FridaInjectInstance
{
  guint id;

  mach_port_t task;

  mach_vm_address_t payload_address;
  mach_vm_size_t payload_size;
  FridaAgentContext * agent_context;
  mach_vm_address_t remote_agent_context;
  mach_vm_size_t agent_context_size;
  gboolean is_mapped;

  mach_port_t thread;
  dispatch_source_t thread_monitor_source;
#ifdef HAVE_I386
  x86_thread_state_t thread_state;
#else
  arm_thread_state_t thread_state32;
  arm_unified_thread_state_t thread_state64;
#endif
  thread_state_t thread_state_data;
  mach_msg_type_number_t thread_state_count;
  thread_state_flavor_t thread_state_flavor;

  FridaDarwinHelperBackend * backend;
};

struct _FridaInjectPayloadLayout
{
  guint stack_guard_size;
  guint stack_size;

  guint code_offset;
  guint mach_code_offset;
  guint pthread_code_offset;
  guint data_offset;
  guint data_size;
  guint stack_guard_offset;
  guint stack_bottom_offset;
  guint stack_top_offset;
};

struct _FridaAgentDetails
{
  guint pid;
  const gchar * dylib_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;
  GumCpuType cpu_type;
};

struct _FridaAgentContext
{
  /* State */
  FridaUnloadPolicy unload_policy;
  mach_port_t task;
  mach_port_t mach_thread;
  mach_port_t posix_thread;
  gboolean constructed;
  gpointer module_handle;

  /* Mach thread */
  GumAddress mach_task_self_impl;
  GumAddress mach_thread_self_impl;

  GumAddress mach_port_allocate_impl;
  mach_port_right_t mach_port_allocate_right;
  mach_port_t receive_port;

  GumAddress pthread_create_impl;
  GumAddress pthread_create_from_mach_thread_impl;
  GumAddress pthread_create_start_routine;
  GumAddress pthread_create_arg;

  GumAddress mach_msg_receive_impl;
  GumAddress message_that_never_arrives;

  /* POSIX thread */
  GumAddress dlopen_impl;
  GumAddress dylib_path;
  int dlopen_mode;

  GumAddress dlsym_impl;
  GumAddress entrypoint_name;

  GumAddress entrypoint_data;
  GumAddress mapped_range;

  GumAddress dlclose_impl;

  GumAddress pthread_detach_impl;
  GumAddress pthread_self_impl;

  GumAddress mach_port_destroy_impl;

  GumAddress thread_terminate_impl;

  /* Storage -- at the end to make the above field offsets smaller */
  mach_msg_empty_rcv_t message_that_never_arrives_storage;
  gchar dylib_path_storage[256];
  gchar entrypoint_name_storage[256];
  gchar entrypoint_data_storage[256];
  GumMemoryRange mapped_range_storage;
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
  GumDarwinMapper * mapper;
};

static FridaSpawnInstance * frida_spawn_instance_new (FridaDarwinHelperBackend * backend);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static void frida_spawn_instance_receive_breakpoint_request (FridaSpawnInstance * self);
static void frida_spawn_instance_send_breakpoint_response (FridaSpawnInstance * self);
static void frida_spawn_instance_create_dyld_data (FridaSpawnInstance * self);
static void frida_spawn_instance_destroy_dyld_data (FridaSpawnInstance * self);
static void frida_spawn_instance_unset_helpers (FridaSpawnInstance * self);
static gboolean frida_spawn_instance_is_libc_initialized (FridaSpawnInstance * self);
static void frida_spawn_instance_on_server_recv (void * context);
static void frida_spawn_instance_call_set_helpers (FridaSpawnInstance * self, GumDarwinUnifiedThreadState state, mach_vm_address_t helpers);
static void frida_spawn_instance_call_dlopen (FridaSpawnInstance * self, GumDarwinUnifiedThreadState state, mach_vm_address_t lib_name, int mode);

static void frida_make_pipe (int fds[2]);

static FridaInjectInstance * frida_inject_instance_new (FridaDarwinHelperBackend * backend, guint id);
static FridaInjectInstance * frida_inject_instance_clone (const FridaInjectInstance * instance, guint id);
static void frida_inject_instance_free (FridaInjectInstance * instance);
static gboolean frida_inject_instance_task_did_not_exec (FridaInjectInstance * instance);
static gboolean frida_inject_instance_is_resident (FridaInjectInstance * instance);

static gboolean frida_inject_instance_start_thread (FridaInjectInstance * self, GError ** error);
static void frida_inject_instance_on_mach_thread_dead (void * context);
static void frida_inject_instance_join_posix_thread (FridaInjectInstance * self, mach_port_t posix_thread);
static void frida_inject_instance_on_posix_thread_dead (void * context);

static gboolean frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details, const FridaInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error);
static gboolean frida_agent_context_init_functions (FridaAgentContext * self, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper,
    GError ** error);

static void frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper);
static void frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper);

static kern_return_t frida_get_debug_state (mach_port_t thread, gpointer state, GumCpuType cpu_type);
static kern_return_t frida_set_debug_state (mach_port_t thread, gconstpointer state, GumCpuType cpu_type);
static void frida_set_nth_hardware_breakpoint (gpointer state, guint n, GumAddress break_at, GumCpuType cpu_type);

static GumAddress frida_find_run_initializers_call (mach_port_t task, GumCpuType cpu_type, GumAddress start);
static GumAddress frida_find_function_end (mach_port_t task, GumCpuType cpu_type, GumAddress start, gsize max_size);
static csh frida_create_capstone (GumCpuType cpu_type, GumAddress start);

static void frida_mapper_library_blob_deallocate (FridaMappedLibraryBlob * self);

extern int fileport_makeport (int fd, mach_port_t * port);

void
frida_darwin_helper_backend_make_pipe_endpoints (guint local_task, guint remote_pid, guint remote_task, FridaPipeEndpoints * result, GError ** error)
{
  mach_port_t self_task;
  int status, sockets[2] = { -1, -1 };
  mach_port_t local_wrapper = MACH_PORT_NULL;
  mach_port_t remote_wrapper = MACH_PORT_NULL;
  mach_port_t local_rx = MACH_PORT_NULL;
  mach_port_t local_tx = MACH_PORT_NULL;
  mach_port_t remote_rx = MACH_PORT_NULL;
  mach_port_t remote_tx = MACH_PORT_NULL;
  mach_msg_type_name_t acquired_type;
  mach_msg_header_t init;
  gchar * local_address, * remote_address;
  kern_return_t kr;
  const gchar * failed_operation;

  self_task = mach_task_self ();

  if (local_task == MACH_PORT_NULL)
    local_task = self_task;

  status = socketpair (AF_UNIX, SOCK_STREAM, 0, sockets);
  CHECK_BSD_RESULT (status, ==, 0, "socketpair");

  status = fileport_makeport (sockets[0], &local_wrapper);
  CHECK_BSD_RESULT (status, ==, KERN_SUCCESS, "fileport_makeport local");

  status = fileport_makeport (sockets[1], &remote_wrapper);
  CHECK_BSD_RESULT (status, ==, KERN_SUCCESS, "fileport_makeport remote");

  kr = mach_port_allocate (local_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate local_rx");

  kr = mach_port_allocate (remote_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate remote_rx");

  kr = mach_port_extract_right (local_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &local_tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right local_rx");

  kr = mach_port_extract_right (remote_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &remote_tx, &acquired_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_extract_right remote_rx");

  init.msgh_size = sizeof (init);
  init.msgh_reserved = 0;
  init.msgh_id = 3;

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_remote_port = local_tx;
  init.msgh_local_port = local_wrapper;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send local_tx");
  local_tx = MACH_PORT_NULL;
  local_wrapper = MACH_PORT_NULL;

  init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  init.msgh_remote_port = remote_tx;
  init.msgh_local_port = remote_wrapper;
  kr = mach_msg_send (&init);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_msg_send remote_tx");
  remote_tx = MACH_PORT_NULL;
  remote_wrapper = MACH_PORT_NULL;

  local_address = g_strdup_printf ("pipe:port=0x%x", local_rx);
  remote_address = g_strdup_printf ("pipe:port=0x%x", remote_rx);
  local_rx = MACH_PORT_NULL;
  remote_rx = MACH_PORT_NULL;
  frida_pipe_endpoints_init (result, local_address, remote_address);
  g_free (remote_address);
  g_free (local_address);

  goto beach;

handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoints for process with pid %u (%s returned '%s')",
        remote_pid, failed_operation, mach_error_string (kr));
    goto beach;
  }
handle_bsd_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoints for process with pid %u (%s returned '%s')",
        remote_pid, failed_operation, strerror (errno));
    goto beach;
  }
beach:
  {
    guint i;

    if (remote_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_tx);
    if (local_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_tx);

    if (remote_rx != MACH_PORT_NULL)
      mach_port_mod_refs (remote_task, remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
    if (local_rx != MACH_PORT_NULL)
      mach_port_mod_refs (local_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    if (remote_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_wrapper);
    if (local_wrapper != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_wrapper);

    for (i = 0; i != G_N_ELEMENTS (sockets); i++)
    {
      int fd = sockets[i];
      if (fd != -1)
        close (fd);
    }

    return;
  }
}

guint
frida_darwin_helper_backend_task_for_pid_fallback (guint pid, GError ** error)
{
  gboolean remote_pid_exists;
  mach_port_t task;
  kern_return_t kr;

  remote_pid_exists = kill (pid, 0) == 0 || errno == EPERM;
  if (!remote_pid_exists)
    goto handle_pid_error;

  kr = task_for_pid (mach_task_self (), pid, &task);
  if (kr != KERN_SUCCESS)
    goto handle_task_for_pid_error;

  return task;

handle_pid_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PROCESS_NOT_FOUND,
        "Unable to find process with pid %u",
        pid);
    return 0;
  }
handle_task_for_pid_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u from the current user account",
        pid);
    return 0;
  }
}

void
frida_darwin_helper_backend_deallocate_port (guint port)
{
  mach_port_deallocate (mach_task_self (), port);
}

gboolean
frida_darwin_helper_backend_is_mmap_available (void)
{
#ifdef HAVE_MAPPER
  return TRUE;
#else
  return FALSE;
#endif
}

void
frida_darwin_helper_backend_mmap (guint task, GBytes * blob, FridaMappedLibraryBlob * result, GError ** error)
{
  gconstpointer data;
  gsize size, aligned_size, page_size;
  mach_vm_address_t mapped_address;
  vm_prot_t cur_protection, max_protection;
  kern_return_t kr;

  if (task == MACH_PORT_NULL)
    task = mach_task_self ();

  data = g_bytes_get_data (blob, &size);

  mapped_address = 0;
  page_size = getpagesize ();
  aligned_size = (size + page_size - 1) & ~(page_size - 1);

  kr = mach_vm_remap (task, &mapped_address, aligned_size, 0, VM_FLAGS_ANYWHERE,
      mach_task_self (), GPOINTER_TO_SIZE (data), TRUE, &cur_protection, &max_protection,
      VM_INHERIT_COPY);
  if (kr != KERN_SUCCESS)
    goto handle_error;

  kr = mach_vm_protect (task, mapped_address, aligned_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr != KERN_SUCCESS)
  {
    mach_vm_deallocate (task, mapped_address, aligned_size);
    goto handle_error;
  }

  frida_mapped_library_blob_init (result, mapped_address, size, aligned_size);

  return;

handle_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to mmap (%s)",
        mach_error_string (kr));
  }
}

void
_frida_darwin_helper_backend_create_context (FridaDarwinHelperBackend * self)
{
  FridaHelperContext * ctx;

  ctx = g_slice_new (FridaHelperContext);
  ctx->dispatch_queue = dispatch_queue_create ("re.frida.helper.queue", DISPATCH_QUEUE_SERIAL);

  self->context = ctx;
}

void
_frida_darwin_helper_backend_destroy_context (FridaDarwinHelperBackend * self)
{
  FridaHelperContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_slice_free (FridaHelperContext, ctx);
}

guint
_frida_darwin_helper_backend_spawn (FridaDarwinHelperBackend * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, FridaStdioPipes ** pipes, GError ** error)
{
  FridaSpawnInstance * instance = NULL;
  int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
  pid_t pid = 0;
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attributes;
  sigset_t signal_mask_set;
  int spawn_errno, result;

  *pipes = NULL;

  if (!g_file_test (path, G_FILE_TEST_EXISTS))
    goto handle_path_error;

  instance = frida_spawn_instance_new (self);

  frida_make_pipe (stdin_pipe);
  frida_make_pipe (stdout_pipe);
  frida_make_pipe (stderr_pipe);

  *pipes = frida_stdio_pipes_new (stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);

  posix_spawn_file_actions_init (&file_actions);
  posix_spawn_file_actions_adddup2 (&file_actions, stdin_pipe[0], 0);
  posix_spawn_file_actions_adddup2 (&file_actions, stdout_pipe[1], 1);
  posix_spawn_file_actions_adddup2 (&file_actions, stderr_pipe[1], 2);

  posix_spawnattr_init (&attributes);
  sigemptyset (&signal_mask_set);
  posix_spawnattr_setsigmask (&attributes, &signal_mask_set);
  posix_spawnattr_setflags (&attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED);

  result = posix_spawn (&pid, path, &file_actions, &attributes, argv, envp);
  spawn_errno = errno;

  posix_spawnattr_destroy (&attributes);

  posix_spawn_file_actions_destroy (&file_actions);

  close (stdin_pipe[0]);
  close (stdout_pipe[1]);
  close (stderr_pipe[1]);

  if (result != 0)
    goto handle_spawn_error;

  instance->pid = pid;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instance_by_pid), GUINT_TO_POINTER (pid), instance);

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

static void frida_kill_application (NSString * identifier);

void
_frida_darwin_helper_backend_launch (FridaDarwinHelperBackend * self, const gchar * identifier, const gchar * url,
    FridaDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  FridaSpringboardApi * api;
  NSAutoreleasePool * pool;
  NSString * identifier_value;
  NSURL * url_value;
  NSDictionary * params, * options;

  api = _frida_get_springboard_api ();

  pool = [[NSAutoreleasePool alloc] init];

  identifier_value = [NSString stringWithUTF8String:identifier];
  url_value = (url != NULL) ? [NSURL URLWithString:[NSString stringWithUTF8String:url]] : nil;
  params = [NSDictionary dictionary];
  options = [NSDictionary dictionaryWithObject:@YES forKey:api->SBSApplicationLaunchOptionUnlockDeviceKey];

  dispatch_async (dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    UInt32 res;
    GError * error = NULL;

    if (url_value != nil)
    {
      res = api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions (
          identifier_value,
          url_value,
          params,
          options,
          NO);
    }
    else
    {
      res = api->SBSLaunchApplicationWithIdentifierAndLaunchOptions (
          identifier_value,
          options,
          NO);
    }

    if (res != 0)
    {
      error = g_error_new (
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unable to launch iOS app: %s",
          [api->SBSApplicationLaunchingErrorString (res) UTF8String]);
    }

    on_complete (error, on_complete_target);

    g_clear_error (&error);
  });

  [pool release];
}

void
_frida_darwin_helper_backend_kill_process (FridaDarwinHelperBackend * self, guint pid)
{
  NSAutoreleasePool * pool;
  NSString * identifier;

  pool = [[NSAutoreleasePool alloc] init];

  identifier = _frida_get_springboard_api ()->SBSCopyDisplayIdentifierForProcessID (pid);
  if (identifier != nil)
  {
    frida_kill_application (identifier);

    [identifier release];
  }
  else
  {
    kill (pid, SIGKILL);
  }

  [pool release];
}

void
_frida_darwin_helper_backend_kill_application (FridaDarwinHelperBackend * self, const gchar * identifier)
{
  NSAutoreleasePool * pool;

  pool = [[NSAutoreleasePool alloc] init];

  frida_kill_application ([NSString stringWithUTF8String:identifier]);

  [pool release];
}

static void
frida_kill_application (NSString * identifier)
{
  FridaSpringboardApi * api;
  GTimer * timer;
  const double kill_timeout = 3.0;

  api = _frida_get_springboard_api ();

  if (api->FBSSystemService != nil)
  {
    FBSSystemService * service;

    service = [api->FBSSystemService sharedService];

    [service terminateApplication:identifier
                        forReason:FBProcessKillReasonUser
                        andReport:NO
                  withDescription:@"killed from Frida"];

    timer = g_timer_new ();

    while ([service pidForApplication:identifier] > 0 && g_timer_elapsed (timer, NULL) < kill_timeout)
    {
      g_usleep (10000);
    }

    g_timer_destroy (timer);
  }
  else
  {
    int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    struct kinfo_proc * entries;
    size_t length;
    gint err;
    gboolean found;
    guint count, i;

    err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
    g_assert_cmpint (err, !=, -1);

    entries = g_malloc0 (length);

    err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
    g_assert_cmpint (err, !=, -1);
    count = length / sizeof (struct kinfo_proc);

    for (i = 0, found = FALSE; i != count && !found; i++)
    {
      struct kinfo_proc * e = &entries[i];
      UInt32 pid = e->kp_proc.p_pid;
      NSString * cur;

      cur = api->SBSCopyDisplayIdentifierForProcessID (pid);
      if ([cur isEqualToString:identifier])
      {
        kill (pid, SIGKILL);

        timer = g_timer_new ();

        while (g_timer_elapsed (timer, NULL) < kill_timeout)
        {
          NSString * identifier_of_dying_process = api->SBSCopyDisplayIdentifierForProcessID (pid);
          if (identifier_of_dying_process == nil)
            break;
          [identifier_of_dying_process release];
          g_usleep (10000);
        }

        g_timer_destroy (timer);

        found = TRUE;

        [cur release];
      }
    }

    g_free (entries);
  }
}

#else

void
_frida_darwin_helper_backend_launch (FridaDarwinHelperBackend * self, const gchar * identifier, const gchar * url,
    FridaDarwinHelperBackendLaunchCompletionHandler on_complete, void * on_complete_target)
{
  dispatch_async (dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    GError * error;

    error = g_error_new (
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Not yet able to launch apps on Mac");

    on_complete (error, on_complete_target);

    g_error_free (error);
  });
}

void
_frida_darwin_helper_backend_kill_process (FridaDarwinHelperBackend * self, guint pid)
{
  kill (pid, SIGKILL);
}

void
_frida_darwin_helper_backend_kill_application (FridaDarwinHelperBackend * self, const gchar * identifier)
{
}

#endif

gboolean
_frida_darwin_helper_backend_is_suspended (FridaDarwinHelperBackend * self, guint task, GError ** error)
{
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO;
  const gchar * failed_operation;
  kern_return_t kr;

  kr = task_info (task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "task_info");

  return info.suspend_count >= 1;

handle_mach_error:
  {
    if (kr == MACH_SEND_INVALID_DEST)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PROCESS_NOT_FOUND,
          "Mach task is gone");
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while interrogating target process (%s returned '%s')",
          failed_operation, mach_error_string (kr));
    }
    return FALSE;
  }
}

void
_frida_darwin_helper_backend_resume_process (FridaDarwinHelperBackend * self, guint task, GError ** error)
{
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t info_count = MACH_TASK_BASIC_INFO;

  if (task_info (task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count) != KERN_SUCCESS)
    goto handle_process_not_found;

  if (info.suspend_count <= 0)
    goto handle_process_not_suspended;

  task_resume (task);

  return;

handle_process_not_found:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PROCESS_NOT_FOUND,
        "No such process");
    return;
  }
handle_process_not_suspended:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_OPERATION,
        "Process is not suspended");
    return;
  }
}

void
_frida_darwin_helper_backend_resume_process_fast (FridaDarwinHelperBackend * self, guint task, GError ** error)
{
  kern_return_t kr;

  kr = task_resume (task);
  if (kr != KERN_SUCCESS)
    goto unexpected_error;

  return;

unexpected_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while resuming process: %s",
        mach_error_string (kr));
    return;
  }
}

void *
_frida_darwin_helper_backend_create_spawn_instance (FridaDarwinHelperBackend * self, guint pid)
{
  FridaSpawnInstance * instance;

  instance = frida_spawn_instance_new (self);
  instance->pid = pid;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instance_by_pid), GUINT_TO_POINTER (pid), instance);

  return instance;
}

void
_frida_darwin_helper_backend_prepare_spawn_instance_for_injection (FridaDarwinHelperBackend * self, void * opaque_instance, guint task, GError ** error)
{
  FridaSpawnInstance * instance = opaque_instance;
  FridaHelperContext * ctx = self->context;
  const gchar * failed_operation;
  kern_return_t kr;
  mach_port_t self_task, child_thread;
  guint page_size;
  thread_act_array_t threads;
  guint thread_index;
  mach_msg_type_number_t thread_count = 0;
  GumDarwinUnifiedThreadState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  GumAddress dyld_start, dyld_granularity, dyld_chunk, dyld_header;
  GumAddress legacy_entry_address, modern_entry_address, launch_with_closure_address, dlerror_clear_address;
  GumDarwinModule * dyld;
  FridaExceptionPortSet * previous_ports;
  dispatch_source_t source;

  /*
   * We POSIX_SPAWN_START_SUSPENDED which means that the kernel will create
   * the task and its main thread, with the main thread's instruction pointer
   * pointed at __dyld_start. At this point neither dyld nor libc have been
   * initialized, so we won't be able to inject frida-agent at this point.
   *
   * So here's what we'll do before we try to inject our dylib:
   * - Get hold of the main thread to read its instruction pointer, which will
   *   tell us where dyld is in memory.
   * - Walk backwards to find dyld's Mach-O header.
   * - Walk its symbols and find a function that's called at a point where the process is
   *   sufficiently initialized to load frida-agent, but still early enough so the app's
   *   initializer(s) didn't get a chance to run.
   * - For processes using dyld v3's closure support we put a hardware breakpoint inside
   *   dyld::launchWithClosure() right after setInitialImageList() has been called.
   *   At that point we have a fully initialized libSystem and are ready to go.
   *   For all other processes we also put a breakpoint on dyld::initializeMainExecutable().
   *   At the beginning of this function dyld is initialized but libSystem is still missing.
   * - Swap out the thread's exception ports with our own.
   * - Resume the task.
   * - Wait until we get a message on our exception port, meaning one of our two breakpoints
   *   was hit.
   * - If the breakpoint hit was the one in dyld::launchWithClosure(), then great, we are done.
   *   Otherwise we hijack the thread's instruction pointer to call:
   *   dlopen("/usr/lib/libSystem.B.dylib", RTLD_GLOBAL | RTLD_LAZY)
   *   and then return back to the beginning of initializeMainExecutable() and restore the
   *   previous thread state.
   * - Swap back the thread's orginal exception ports.
   * - Clear the hardware breakpoint by restoring the thread's debug registers.
   *
   * For processes not using the new closure support it's actually more complex than that,
   * because:
   * - This doesn't work on newer versions of dyld because to call dlopen() it's
   *   necessary to registerThreadHelpers() first, which is normally done by libSystem
   *   itself during its initialization.
   * - To overcome this catch-22 we alloc a fake LibSystemHelpers object and register
   *   it (also by hijacking thread's instruction pointer as described above).
   * - On older dyld versions, registering helpers before loading libSystem led to
   *   crashes, so we detect this condition and unset the helpers before calling dlopen(),
   *   by writing a NULL directly into the global dyld::gLibSystemHelpers because in
   *   some dyld versions calling registerThreadHelpers(NULL) causes a NULL dereference.
   * - At the end of dlopen(), we set the global "libSystemInitialized" flag present in
   *   the global dyld::qProcessInfo structure, because on newer dyld versions that doesn't
   *   happen automatically due to the presence of our fake helpers.
   * - One of the functions provided by the helper should return a buffer for the errors,
   *   but since our fake helpers object implements its functions only using a return,
   *   it will not return any buffer. To avoid this to happen, we set a breakpoint also
   *   on dyld:dlerrorClear function and inject an immediate return,
   *   effectively disabling the function.
   * - At the end of dlopen() we finally deallocate our fake helpers (because now they've
   *   been replaced by real libSystem ones) and the string we used as a parameter for dlopen.
   *
   * Then later when resume() is called:
   * - Send a response to the message we got on our exception port, so the
   *   kernel considers it handled and resumes the main thread for us.
   */

  self_task = mach_task_self ();

  if (!gum_darwin_cpu_type_from_pid (instance->pid, &instance->cpu_type))
    goto handle_cpu_type_error;

  if (!gum_darwin_query_page_size (task, &page_size))
    goto handle_page_size_error;

  kr = task_threads (task, &threads, &thread_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "task_threads");

  child_thread = threads[0];
  instance->thread = child_thread;
  instance->task = task;

  for (thread_index = 1; thread_index < thread_count; thread_index++)
    mach_port_deallocate (self_task, threads[thread_index]);
  vm_deallocate (self_task, (vm_address_t) threads, thread_count * sizeof (thread_t));
  threads = NULL;

  kr = thread_get_state (child_thread, state_flavor, (thread_state_t) &state, &state_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_get_state");

#ifdef HAVE_I386
  dyld_start = (instance->cpu_type == GUM_CPU_AMD64) ? state.uts.ts64.__rip : state.uts.ts32.__eip;
#else
  dyld_start = (instance->cpu_type == GUM_CPU_ARM64) ? state.ts_64.__pc : state.ts_32.__pc;
#endif

  dyld_header = 0;
  dyld_granularity = 4096;
  for (dyld_chunk = (dyld_start & (dyld_granularity - 1)) == 0 ? (dyld_start - dyld_granularity) : (dyld_start & ~(dyld_granularity - 1));
      dyld_header == 0;
      dyld_chunk -= dyld_granularity)
  {
    guint32 * magic;

    magic = (guint32 *) gum_darwin_read (task, dyld_chunk, sizeof (magic), NULL);
    if (magic == NULL)
      goto handle_probe_dyld_error;

    if (*magic == MH_MAGIC || *magic == MH_MAGIC_64)
      dyld_header = dyld_chunk;

    g_free (magic);
  }

  dyld = gum_darwin_module_new_from_memory ("/usr/lib/dyld", task, instance->cpu_type, page_size, dyld_header);

  legacy_entry_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyld24initializeMainExecutableEv");

  modern_entry_address = 0;
  launch_with_closure_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyldL17launchWithClosureEPKN5dyld312launch_cache13binary_format7ClosureEPK15DyldSharedCachePK11mach_headermiPPKcSE_SE_PmSF_");
  if (launch_with_closure_address != 0)
  {
    modern_entry_address = frida_find_run_initializers_call (task, instance->cpu_type, launch_with_closure_address);
  }
  instance->modern_entry_address = modern_entry_address;

  instance->dlopen_address = gum_darwin_module_resolve_symbol_address (dyld, "_dlopen");
  instance->register_helpers_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZL21registerThreadHelpersPKN4dyld16LibSystemHelpersE");
  dlerror_clear_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZL12dlerrorClearv");
  instance->info_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyld12gProcessInfoE");
  instance->helpers_ptr_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZN4dyld17gLibSystemHelpersE");

  g_object_unref (dyld);

  if (legacy_entry_address == 0 || instance->dlopen_address == 0 || instance->register_helpers_address == 0
      || dlerror_clear_address == 0 || instance->info_address == 0)
    goto handle_probe_dyld_error;

  if (instance->cpu_type == GUM_CPU_ARM)
  {
    instance->dlopen_address |= 1;
    instance->register_helpers_address |= 1;
  }

  instance->ret_gadget = frida_find_function_end (task, instance->cpu_type, instance->register_helpers_address, 128);
  if (instance->ret_gadget == 0)
    goto handle_probe_dyld_error;

  if (instance->cpu_type == GUM_CPU_ARM)
    instance->ret_gadget |= 1;

  frida_spawn_instance_create_dyld_data (instance);

  kr = frida_get_debug_state (child_thread, &instance->previous_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "frida_get_debug_state");

  memcpy (&instance->breakpoint_debug_state, &instance->previous_debug_state, sizeof (instance->breakpoint_debug_state));
  frida_set_nth_hardware_breakpoint (&instance->breakpoint_debug_state, 0, legacy_entry_address, instance->cpu_type);
  if (modern_entry_address != 0)
  {
    frida_set_nth_hardware_breakpoint (&instance->breakpoint_debug_state, 1, modern_entry_address, instance->cpu_type);
  }

  memcpy (&instance->dlerror_clear_debug_state, &instance->previous_debug_state, sizeof (instance->previous_debug_state));
  frida_set_nth_hardware_breakpoint (&instance->dlerror_clear_debug_state, 0, dlerror_clear_address, instance->cpu_type);

  memcpy (&instance->ret_gadget_debug_state, &instance->previous_debug_state, sizeof (instance->previous_debug_state));
  frida_set_nth_hardware_breakpoint (&instance->ret_gadget_debug_state, 0, instance->ret_gadget & ~1, instance->cpu_type);

  kr = frida_set_debug_state (child_thread, &instance->breakpoint_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "frida_set_debug_state");

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &instance->server_port);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_allocate server");

  kr = mach_port_insert_right (self_task, instance->server_port, instance->server_port, MACH_MSG_TYPE_MAKE_SEND);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_port_insert_right server");

  previous_ports = &instance->previous_ports;
  kr = thread_swap_exception_ports (child_thread,
      EXC_MASK_BREAKPOINT,
      instance->server_port,
      EXCEPTION_DEFAULT,
      state_flavor,
      previous_ports->masks,
      &previous_ports->count,
      previous_ports->ports,
      previous_ports->behaviors,
      previous_ports->flavors);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_swap_exception_ports");

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV, instance->server_port, 0, ctx->dispatch_queue);
  instance->server_recv_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_spawn_instance_on_server_recv);
  dispatch_resume (source);

  return;

handle_cpu_type_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing CPU type of target process");
    goto error_epilogue;
  }
handle_page_size_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing page size of target process");
    goto error_epilogue;
  }
handle_probe_dyld_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing dyld of target process");
    goto error_epilogue;
  }
handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing target process for injection (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    goto error_epilogue;
  }
error_epilogue:
  {
    kill (instance->pid, SIGKILL);

    gee_abstract_map_unset (GEE_ABSTRACT_MAP (self->spawn_instance_by_pid), GUINT_TO_POINTER (instance->pid), NULL);
    frida_spawn_instance_free (instance);

    return;
  }
}

void
_frida_darwin_helper_backend_resume_spawn_instance (FridaDarwinHelperBackend * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_darwin_helper_backend_free_spawn_instance (FridaDarwinHelperBackend * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

guint
_frida_darwin_helper_backend_inject_into_task (FridaDarwinHelperBackend * self, guint pid, guint task, const gchar * path_or_name, FridaMappedLibraryBlob * blob,
    const gchar * entrypoint, const gchar * data, GError ** error)
{
  guint result = 0;
  mach_port_t self_task;
  FridaInjectInstance * instance;
  GumDarwinModuleResolver * resolver = NULL;
  GumDarwinMapper * mapper = NULL;
  FridaAgentDetails details = { 0, };
  guint page_size;
  FridaInjectPayloadLayout layout;
  kern_return_t kr;
  const gchar * failed_operation;
  guint base_payload_size;
  mach_vm_address_t payload_address = 0;
  mach_vm_address_t agent_context_address = 0;
  mach_vm_address_t data_address;
  vm_prot_t cur_protection, max_protection;
  guint8 mach_stub_code[512] = { 0, };
  guint8 pthread_stub_code[512] = { 0, };
  FridaAgentContext agent_ctx;

  self_task = mach_task_self ();

  instance = frida_inject_instance_new (self, self->next_id++);
  mach_port_mod_refs (self_task, task, MACH_PORT_RIGHT_SEND, 1);
  instance->task = task;

  resolver = gum_darwin_module_resolver_new (task);

  details.pid = pid;
  details.dylib_path = (blob == NULL) ? path_or_name : NULL;
  details.entrypoint_name = entrypoint;
  details.entrypoint_data = data;
  details.cpu_type = resolver->cpu_type;

  page_size = resolver->page_size;

#ifdef HAVE_MAPPER
  if (blob != NULL)
  {
    mapper = gum_darwin_mapper_new_take_blob (path_or_name,
        g_bytes_new_with_free_func (GSIZE_TO_POINTER (blob->_address), blob->_size,
            (GDestroyNotify) frida_mapper_library_blob_deallocate, frida_mapped_library_blob_dup (blob)),
        resolver);
  }
  else
  {
    mapper = gum_darwin_mapper_new_from_file (path_or_name, resolver);
  }
#else
  (void) frida_mapper_library_blob_deallocate;
#endif

  layout.stack_guard_size = page_size;
  layout.stack_size = 32 * 1024;

  layout.code_offset = 0;
  layout.mach_code_offset = 0;
  layout.pthread_code_offset = 512;
  layout.data_offset = page_size;
  layout.data_size = MAX (page_size, gum_query_page_size ());
  layout.stack_guard_offset = layout.data_offset + layout.data_size;
  layout.stack_bottom_offset = layout.stack_guard_offset + layout.stack_guard_size;
  layout.stack_top_offset = layout.stack_bottom_offset + layout.stack_size;

  base_payload_size = layout.stack_top_offset;

  instance->payload_size = base_payload_size;
  if (mapper != NULL)
    instance->payload_size += gum_darwin_mapper_size (mapper);

  kr = mach_vm_allocate (task, &payload_address, instance->payload_size, VM_FLAGS_ANYWHERE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_allocate(payload)");
  instance->payload_address = payload_address;

  kr = mach_vm_allocate (self_task, &agent_context_address, layout.data_size, VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
  instance->agent_context = (FridaAgentContext *) agent_context_address;
  instance->agent_context_size = layout.data_size;

  data_address = payload_address + layout.data_offset;
  kr = mach_vm_remap (task, &data_address, layout.data_size, 0, VM_FLAGS_OVERWRITE, self_task, agent_context_address,
      FALSE, &cur_protection, &max_protection, VM_INHERIT_SHARE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(data)");
  instance->remote_agent_context = data_address;

  if (mapper != NULL)
  {
    gum_darwin_mapper_map (mapper, payload_address + base_payload_size);

    instance->is_mapped = TRUE;
  }

  kr = mach_vm_protect (task, payload_address + layout.stack_guard_offset, layout.stack_guard_size, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect");

  if (!frida_agent_context_init (&agent_ctx, &details, &layout, payload_address, instance->payload_size, resolver, mapper, error))
    goto error_epilogue;

  frida_agent_context_emit_mach_stub_code (&agent_ctx, mach_stub_code, details.cpu_type, mapper);

  frida_agent_context_emit_pthread_stub_code (&agent_ctx, pthread_stub_code, details.cpu_type, mapper);

  if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
  {
    kr = mach_vm_write (task, payload_address + layout.mach_code_offset,
        (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(mach_stub_code)");

    kr = mach_vm_write (task, payload_address + layout.pthread_code_offset,
        (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(pthread_stub_code)");

    kr = mach_vm_protect (task, payload_address + layout.code_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect");
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;
    mach_vm_address_t code_address;

    segment = gum_code_segment_new (page_size, NULL);

    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page + layout.mach_code_offset, mach_stub_code, sizeof (mach_stub_code));
    memcpy (scratch_page + layout.pthread_code_offset, pthread_stub_code, sizeof (pthread_stub_code));

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, page_size, scratch_page);

    code_address = payload_address + layout.code_offset;
    kr = mach_vm_remap (task, &code_address, page_size, 0, VM_FLAGS_OVERWRITE, self_task, (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);

    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(code)");
  }

  kr = mach_vm_write (task, payload_address + layout.data_offset, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(data)");

  kr = mach_vm_protect (task, payload_address + layout.data_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect");

#ifdef HAVE_I386
  {
    x86_thread_state_t * state = &instance->thread_state;

    bzero (state, sizeof (x86_thread_state_t));

    if (details.cpu_type == GUM_CPU_AMD64)
    {
      x86_thread_state64_t * ts;

      state->tsh.flavor = x86_THREAD_STATE64;
      state->tsh.count = x86_THREAD_STATE64_COUNT;

      ts = &state->uts.ts64;

      ts->__rbx = payload_address + layout.data_offset;

      ts->__rsp = payload_address + layout.stack_top_offset;
      ts->__rip = payload_address + layout.mach_code_offset;
    }
    else
    {
      x86_thread_state32_t * ts;

      state->tsh.flavor = x86_THREAD_STATE32;
      state->tsh.count = x86_THREAD_STATE32_COUNT;

      ts = &state->uts.ts32;

      ts->__ebx = payload_address + layout.data_offset;

      ts->__esp = payload_address + layout.stack_top_offset;
      ts->__eip = payload_address + layout.mach_code_offset;
    }

    instance->thread_state_data = (thread_state_t) state;
    instance->thread_state_count = x86_THREAD_STATE_COUNT;
    instance->thread_state_flavor = x86_THREAD_STATE;
  }
#else
  if (details.cpu_type == GUM_CPU_ARM64)
  {
    arm_unified_thread_state_t * state64 = &instance->thread_state64;
    arm_thread_state64_t * ts;

    bzero (state64, sizeof (arm_unified_thread_state_t));

    state64->ash.flavor = ARM_THREAD_STATE64;
    state64->ash.count = ARM_THREAD_STATE64_COUNT;

    ts = &state64->ts_64;

    ts->__x[20] = payload_address + layout.data_offset;

    ts->__sp = payload_address + layout.stack_top_offset;
    ts->__lr = 0xcafebabe;
    ts->__pc = payload_address + layout.mach_code_offset;

    instance->thread_state_data = (thread_state_t) state64;
    instance->thread_state_count = ARM_UNIFIED_THREAD_STATE_COUNT;
    instance->thread_state_flavor = ARM_UNIFIED_THREAD_STATE;
  }
  else
  {
    arm_thread_state_t * state32 = &instance->thread_state32;

    bzero (state32, sizeof (arm_thread_state_t));

    state32->__r[7] = payload_address + layout.data_offset;

    state32->__sp = payload_address + layout.stack_top_offset;
    state32->__lr = 0xcafebabe;
    state32->__pc = payload_address + layout.mach_code_offset;
    state32->__cpsr = FRIDA_PSR_THUMB;

    instance->thread_state_data = (thread_state_t) state32;
    instance->thread_state_count = ARM_THREAD_STATE_COUNT;
    instance->thread_state_flavor = ARM_THREAD_STATE;
  }
#endif

  if (!frida_inject_instance_start_thread (instance, error))
    goto error_epilogue;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  result = instance->id;
  goto beach;

handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u (%s returned '%s')",
        pid, failed_operation, mach_error_string (kr));
    goto error_epilogue;
  }
error_epilogue:
  {
    frida_inject_instance_free (instance);
    goto beach;
  }
beach:
  {
    g_clear_object (&mapper);
    g_clear_object (&resolver);

    return result;
  }
}

guint
_frida_darwin_helper_backend_demonitor_and_clone_injectee_state (FridaDarwinHelperBackend * self, void * raw_instance)
{
  FridaInjectInstance * instance = raw_instance;
  FridaInjectInstance * clone;

  dispatch_release (instance->thread_monitor_source);
  instance->thread_monitor_source = NULL;

  mach_port_deallocate (mach_task_self (), instance->thread);
  instance->thread = MACH_PORT_NULL;

  clone = frida_inject_instance_clone (instance, self->next_id++);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (clone->id), clone);

  return clone->id;
}

void
_frida_darwin_helper_backend_recreate_injectee_thread (FridaDarwinHelperBackend * self, void * raw_instance, guint pid, guint task, GError ** error)
{
  FridaInjectInstance * instance = raw_instance;
  FridaAgentContext * agent_context = instance->agent_context;
  mach_port_t self_task;
  gboolean is_uninitialized_clone;
  const gchar * failed_operation;
  kern_return_t kr;

  agent_context->unload_policy = FRIDA_UNLOAD_POLICY_IMMEDIATE;
  agent_context->task = MACH_PORT_NULL;
  agent_context->mach_thread = MACH_PORT_NULL;
  agent_context->posix_thread = MACH_PORT_NULL;

  self_task = mach_task_self ();

  is_uninitialized_clone = instance->task == MACH_PORT_NULL;

  if (is_uninitialized_clone)
  {
    mach_vm_address_t data_address;
    vm_prot_t cur_protection, max_protection;

    mach_port_mod_refs (self_task, task, MACH_PORT_RIGHT_SEND, 1);
    instance->task = task;

    data_address = instance->remote_agent_context;
    kr = mach_vm_remap (task, &data_address, instance->agent_context_size, 0, VM_FLAGS_OVERWRITE, self_task, (mach_vm_address_t) agent_context,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_SHARE);
    CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(data)");
  }

  if (!frida_inject_instance_start_thread (instance, error))
    goto error_epilogue;

  goto beach;

handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while recreating thread in process with pid %u (%s returned '%s')",
        pid, failed_operation, mach_error_string (kr));
    goto error_epilogue;
  }
error_epilogue:
  {
    _frida_darwin_helper_backend_destroy_inject_instance (self, instance->id);
    goto beach;
  }
beach:
  {
    return;
  }
}

static gboolean
frida_inject_instance_start_thread (FridaInjectInstance * self, GError ** error)
{
  gboolean success = FALSE;
  kern_return_t kr;
  const gchar * failed_operation;
  FridaHelperContext * ctx = self->backend->context;
  dispatch_source_t source;

  kr = thread_create (self->task, &self->thread);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_create");

  kr = act_set_state (self->thread, self->thread_state_flavor, self->thread_state_data, self->thread_state_count);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "act_set_state");

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, self->thread, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  self->thread_monitor_source = source;
  dispatch_set_context (source, self);
  dispatch_source_set_event_handler_f (source, frida_inject_instance_on_mach_thread_dead);
  dispatch_resume (source);

  kr = thread_resume (self->thread);
  CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "thread_resume");

  success = TRUE;

  goto beach;

handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while starting thread (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    goto beach;
  }
beach:
  {
    return success;
  }
}

static void
frida_inject_instance_on_mach_thread_dead (void * context)
{
  FridaInjectInstance * self = context;
  mach_port_t posix_thread_right_in_remote_task = self->agent_context->posix_thread;
  mach_port_t posix_thread_right_in_local_task = MACH_PORT_NULL;

  if (posix_thread_right_in_remote_task != MACH_PORT_NULL)
  {
    mach_msg_type_name_t acquired_type;

    mach_port_extract_right (self->task, posix_thread_right_in_remote_task, MACH_MSG_TYPE_MOVE_SEND, &posix_thread_right_in_local_task, &acquired_type);
  }

  _frida_darwin_helper_backend_on_mach_thread_dead (self->backend, self->id, GSIZE_TO_POINTER (posix_thread_right_in_local_task));
}

void
_frida_darwin_helper_backend_join_inject_instance_posix_thread (FridaDarwinHelperBackend * self, void * instance, void * posix_thread)
{
  frida_inject_instance_join_posix_thread (instance, GPOINTER_TO_SIZE (posix_thread));
}

static void
frida_inject_instance_join_posix_thread (FridaInjectInstance * self, mach_port_t posix_thread)
{
  FridaHelperContext * ctx = self->backend->context;
  mach_port_t self_task;
  dispatch_source_t source;

  self_task = mach_task_self ();

  mach_port_deallocate (self_task, self->thread);
  self->thread = posix_thread;

  dispatch_release (self->thread_monitor_source);
  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, self->thread, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  self->thread_monitor_source = source;
  dispatch_set_context (source, self);
  dispatch_source_set_event_handler_f (source, frida_inject_instance_on_posix_thread_dead);
  dispatch_resume (source);
}

static void
frida_inject_instance_on_posix_thread_dead (void * context)
{
  FridaInjectInstance * self = context;

  _frida_darwin_helper_backend_on_posix_thread_dead (self->backend, self->id);
}

gboolean
_frida_darwin_helper_backend_is_instance_resident (FridaDarwinHelperBackend * self, void * instance)
{
  return frida_inject_instance_is_resident (instance);
}

void
_frida_darwin_helper_backend_free_inject_instance (FridaDarwinHelperBackend * self, void * instance)
{
  frida_inject_instance_free (instance);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaDarwinHelperBackend * backend)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
  instance->backend = backend;
  instance->thread = MACH_PORT_NULL;

  instance->server_port = MACH_PORT_NULL;
  instance->server_recv_source = NULL;

  instance->pending_request.thread.name = MACH_PORT_NULL;
  instance->pending_request.task.name = MACH_PORT_NULL;

  instance->breakpoint_phase = FRIDA_BREAKPOINT_DETECT_FLAVOR;

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  task_t self_task;
  mach_port_t port;
  FridaExceptionPortSet * previous_ports;
  mach_msg_type_number_t port_index;

  self_task = mach_task_self ();

  port = instance->pending_request.Head.msgh_remote_port;
  if (port != MACH_PORT_NULL)
    mach_port_deallocate (self_task, port);
  port = instance->pending_request.thread.name;
  if (port != MACH_PORT_NULL)
    mach_port_deallocate (self_task, port);
  port = instance->pending_request.task.name;
  if (port != MACH_PORT_NULL)
    mach_port_deallocate (self_task, port);

  previous_ports = &instance->previous_ports;
  for (port_index = 0; port_index != previous_ports->count; port_index++)
  {
    mach_port_deallocate (self_task, previous_ports->ports[port_index]);
  }
  if (instance->server_recv_source != NULL)
    dispatch_release (instance->server_recv_source);
  if (instance->server_port != MACH_PORT_NULL)
  {
    mach_port_mod_refs (self_task, instance->server_port, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs (self_task, instance->server_port, MACH_PORT_RIGHT_RECEIVE, -1);
  }

  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  if (self->breakpoint_phase != FRIDA_BREAKPOINT_DONE)
  {
    guint task;
    GError * error = NULL;

    task = frida_darwin_helper_backend_steal_task_for_remote_pid (self->backend, self->pid, &error);
    if (error == NULL)
    {
      _frida_darwin_helper_backend_resume_process (self->backend, task, &error);
    }

    g_clear_error (&error);

    return;
  }

  frida_spawn_instance_send_breakpoint_response (self);
}

static void
frida_spawn_instance_receive_breakpoint_request (FridaSpawnInstance * self)
{
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  mach_msg_header_t * header;
  kern_return_t kr;

  bzero (request, sizeof (*request));
  header = &request->Head;
  header->msgh_size = sizeof (*request);
  header->msgh_local_port = self->server_port;
  kr = mach_msg_receive (header);
  g_assert_cmpint (kr, ==, 0);
}

static void
frida_spawn_instance_send_breakpoint_response (FridaSpawnInstance * self)
{
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  __Reply__exception_raise_t response;
  mach_msg_header_t * header;
  kern_return_t kr;

  bzero (&response, sizeof (response));
  header = &response.Head;
  header->msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  header->msgh_size = sizeof (response);
  header->msgh_remote_port = request->Head.msgh_remote_port;
  header->msgh_local_port = MACH_PORT_NULL;
  header->msgh_reserved = 0;
  header->msgh_id = request->Head.msgh_id + 100;
  response.NDR = NDR_record;
  response.RetCode = KERN_SUCCESS;
  kr = mach_msg_send (header);
  if (kr == KERN_SUCCESS)
    request->Head.msgh_remote_port = MACH_PORT_NULL;
}

static void
frida_spawn_instance_create_dyld_data (FridaSpawnInstance * self)
{
  kern_return_t kr;
  gboolean write_succeeded;
  FridaSpawnInstanceDyldData data = { "/usr/lib/libSystem.B.dylib", { 0, } };

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 * helpers32 = (guint32 *) &data.helpers[0];

      /* version */
      helpers32[0] = 1;
      /* acquireGlobalDyldLock (unused) */
      helpers32[1] = 0;
      /* releaseGlobalDyldLock */
      helpers32[2] = (guint32) self->ret_gadget;
      /* getThreadBufferFor_dlerror (unused) */
      helpers32[3] = 0;

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 * helpers64 = (guint64 *) &data.helpers[0];

      /* version */
      helpers64[0] = 1;
      /* acquireGlobalDyldLock (unused) */
      helpers64[1] = 0;
      /* releaseGlobalDyldLock */
      helpers64[2] = (guint64) self->ret_gadget;
      /* getThreadBufferFor_dlerror (unused) */
      helpers64[3] = 0;

      break;
    }

    default:
      g_assert_not_reached ();
  }

  kr = mach_vm_allocate (self->task, &self->dyld_data, sizeof (data), VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  write_succeeded = gum_darwin_write (self->task, self->dyld_data, (const guint8 *) &data, sizeof (data));
  g_assert (write_succeeded);

  self->fake_helpers = self->dyld_data + offsetof (FridaSpawnInstanceDyldData, helpers);
  self->lib_name = self->dyld_data + offsetof (FridaSpawnInstanceDyldData, libc);
}

static void
frida_spawn_instance_destroy_dyld_data (FridaSpawnInstance * self)
{
  kern_return_t kr;

  if (self->dyld_data == 0)
    return;

  kr = vm_deallocate (self->task, (vm_address_t) self->dyld_data, sizeof (FridaSpawnInstanceDyldData));
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  self->dyld_data = 0;
}

static void
frida_spawn_instance_unset_helpers (FridaSpawnInstance * self)
{
  gboolean write_succeeded;

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 null_ptr = 0;

      write_succeeded = gum_darwin_write (self->task, self->helpers_ptr_address, (const guint8 *) &null_ptr, sizeof (null_ptr));

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 null_ptr = 0;

      write_succeeded = gum_darwin_write (self->task, self->helpers_ptr_address, (const guint8 *) &null_ptr, sizeof (null_ptr));

      break;
    }

    default:
      g_assert_not_reached ();
  }

  g_assert (write_succeeded);
}

static void
frida_spawn_instance_set_libc_initialized (FridaSpawnInstance * self)
{
  GumAddress initialized_address;
  gboolean write_succeeded;
  guint8 yes = 1;

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 * info_ptr;

      info_ptr = (guint32 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 17;
      g_free (info_ptr);

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 * info_ptr;

      info_ptr = (guint64 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 25;
      g_free (info_ptr);

      break;
    }

    default:
      g_assert_not_reached ();
  }

  write_succeeded = gum_darwin_write (self->task, initialized_address, &yes, 1);
  g_assert (write_succeeded);
}

static gboolean
frida_spawn_instance_is_libc_initialized (FridaSpawnInstance * self)
{
  gboolean initialized;
  GumAddress initialized_address;
  guint8 * yes;

  switch (self->cpu_type)
  {
    case GUM_CPU_ARM:
    case GUM_CPU_IA32:
    {
      guint32 * info_ptr;

      info_ptr = (guint32 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 17;
      g_free (info_ptr);

      break;
    }

    case GUM_CPU_ARM64:
    case GUM_CPU_AMD64:
    {
      guint64 * info_ptr;

      info_ptr = (guint64 *) gum_darwin_read (self->task, self->info_address, sizeof (info_ptr), NULL);
      initialized_address = (*info_ptr) + 25;
      g_free (info_ptr);

      break;
    }

    default:
      g_assert_not_reached ();
  }

  yes = (guint8 *) gum_darwin_read (self->task, initialized_address, sizeof (yes), NULL);
  initialized = *yes;
  g_free (yes);

  return initialized;
}

static void
frida_spawn_instance_on_server_recv (void * context)
{
  FridaSpawnInstance * self = context;
  kern_return_t kr;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  GumDarwinUnifiedThreadState state;

  frida_spawn_instance_receive_breakpoint_request (self);

  if (self->breakpoint_phase == FRIDA_BREAKPOINT_DETECT_FLAVOR)
  {
    GumAddress pc;

    kr = thread_get_state (self->thread, state_flavor, (thread_state_t) &state, &state_count);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);

    memcpy (&self->previous_thread_state, &state, sizeof (state));

#ifdef HAVE_I386
    if (self->cpu_type == GUM_CPU_AMD64)
      pc = state.uts.ts64.__rip;
    else
      pc = state.uts.ts32.__eip;
#else
    if (self->cpu_type == GUM_CPU_ARM64)
      pc = state.ts_64.__pc;
    else
      pc = state.ts_32.__pc;
#endif

    self->breakpoint_phase = (pc == self->modern_entry_address) ? FRIDA_BREAKPOINT_CLEANUP : FRIDA_BREAKPOINT_SET_HELPERS;
  }

  switch (self->breakpoint_phase)
  {
    case FRIDA_BREAKPOINT_SET_HELPERS:
      frida_spawn_instance_call_set_helpers (self, state, self->fake_helpers);

      self->breakpoint_phase = FRIDA_BREAKPOINT_DLOPEN_LIBC;
      frida_spawn_instance_send_breakpoint_response (self);

      break;

    case FRIDA_BREAKPOINT_DLOPEN_LIBC:
      if (frida_spawn_instance_is_libc_initialized (self))
        frida_spawn_instance_unset_helpers (self);

      memcpy (&state, &self->previous_thread_state, sizeof (state));

      frida_spawn_instance_call_dlopen (self, state, self->lib_name, RTLD_GLOBAL | RTLD_LAZY);

      frida_set_debug_state (self->thread, &self->dlerror_clear_debug_state, self->cpu_type);
      self->breakpoint_phase = FRIDA_BREAKPOINT_SKIP_CLEAR;

      frida_spawn_instance_send_breakpoint_response (self);

      break;

    case FRIDA_BREAKPOINT_SKIP_CLEAR:
    case FRIDA_BREAKPOINT_JUST_RETURN:
      kr = thread_get_state (self->thread, state_flavor, (thread_state_t) &state, &state_count);
      g_assert_cmpint (kr, ==, KERN_SUCCESS);

#ifdef HAVE_I386
      if (self->cpu_type == GUM_CPU_AMD64)
        state.uts.ts64.__rip = self->ret_gadget;
      else
        state.uts.ts32.__eip = self->ret_gadget;
#else
      if (self->cpu_type == GUM_CPU_ARM64)
        state.ts_64.__pc = state.ts_64.__lr;
      else
        state.ts_32.__pc = state.ts_32.__lr;
#endif

      kr = thread_set_state (self->thread, state_flavor, (thread_state_t) &state, state_count);
      g_assert_cmpint (kr, ==, KERN_SUCCESS);

      if (self->breakpoint_phase == FRIDA_BREAKPOINT_SKIP_CLEAR && self->cpu_type == GUM_CPU_ARM)
      {
        frida_set_debug_state (self->thread, &self->ret_gadget_debug_state, self->cpu_type);
        self->breakpoint_phase = FRIDA_BREAKPOINT_JUST_RETURN;
      }
      else
      {
        frida_set_debug_state (self->thread, &self->breakpoint_debug_state, self->cpu_type);
        self->breakpoint_phase = FRIDA_BREAKPOINT_CLEANUP;
      }

      frida_spawn_instance_send_breakpoint_response (self);

      break;

    case FRIDA_BREAKPOINT_CLEANUP:
    {
      task_t self_task;
      FridaExceptionPortSet * previous_ports;
      mach_msg_type_number_t port_index;

      self_task = mach_task_self ();

      previous_ports = &self->previous_ports;
      for (port_index = 0; port_index != previous_ports->count; port_index++)
      {
        kr = thread_set_exception_ports (self->thread,
            previous_ports->masks[port_index],
            previous_ports->ports[port_index],
            previous_ports->behaviors[port_index],
            previous_ports->flavors[port_index]);
        if (kr != KERN_SUCCESS)
        {
          mach_port_deallocate (self_task, previous_ports->ports[port_index]);
        }
      }
      previous_ports->count = 0;

      kr = thread_set_state (self->thread, state_flavor, (thread_state_t) &self->previous_thread_state, state_count);
      g_assert_cmpint (kr, ==, KERN_SUCCESS);

      frida_spawn_instance_destroy_dyld_data (self);

      frida_set_debug_state (self->thread, &self->previous_debug_state, self->cpu_type);

      frida_spawn_instance_set_libc_initialized (self);

      self->breakpoint_phase = FRIDA_BREAKPOINT_DONE;

      _frida_darwin_helper_backend_on_spawn_instance_ready (self->backend, self->pid);

      break;
    }

    default:
      g_assert_not_reached ();
  }
}

static void
frida_spawn_instance_call_set_helpers (FridaSpawnInstance * self, GumDarwinUnifiedThreadState state, mach_vm_address_t helpers)
{
  kern_return_t kr;
  GumAddress current_pc;

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
  {
    gboolean write_succeeded;

    current_pc = state.uts.ts64.__rip;
    state.uts.ts64.__rip = self->register_helpers_address;
    state.uts.ts64.__rdi = helpers;

    state.uts.ts64.__rsp -= 8;
    write_succeeded = gum_darwin_write (self->task, state.uts.ts64.__rsp, (const guint8 *) &current_pc, sizeof (current_pc));
    g_assert (write_succeeded);
  }
  else
  {
    guint32 temp[2];
    gboolean write_succeeded;

    current_pc = state.uts.ts32.__eip;
    state.uts.ts32.__eip = self->register_helpers_address;

    temp[0] = current_pc;
    temp[1] = helpers;
    state.uts.ts32.__esp -= 8;
    write_succeeded = gum_darwin_write (self->task, state.uts.ts32.__esp, (const guint8 *) &temp, sizeof (temp));
    g_assert (write_succeeded);
  }
#else
  if (self->cpu_type == GUM_CPU_ARM64)
  {
    current_pc = state.ts_64.__pc;
    state.ts_64.__pc = self->register_helpers_address;
    state.ts_64.__lr = current_pc;
    state.ts_64.__x[0] = helpers;
  }
  else
  {
    current_pc = state.ts_32.__pc;
    state.ts_32.__pc = self->register_helpers_address;
    state.ts_32.__lr = current_pc | 1;
    state.ts_32.__r[0] = helpers;
  }
#endif

  kr = thread_set_state (self->thread, GUM_DARWIN_THREAD_STATE_FLAVOR,
      (thread_state_t) &state, GUM_DARWIN_THREAD_STATE_COUNT);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
}

static void
frida_spawn_instance_call_dlopen (FridaSpawnInstance * self, GumDarwinUnifiedThreadState state, mach_vm_address_t lib_name, int mode)
{
  kern_return_t kr;
  GumAddress current_pc;

#ifdef HAVE_I386
  if (self->cpu_type == GUM_CPU_AMD64)
  {
    gboolean write_succeeded;

    current_pc = state.uts.ts64.__rip;
    state.uts.ts64.__rip = self->dlopen_address;
    state.uts.ts64.__rdi = lib_name;
    state.uts.ts64.__rsi = mode;

    state.uts.ts64.__rsp -= 16;
    write_succeeded = gum_darwin_write (self->task, state.uts.ts64.__rsp, (const guint8 *) &current_pc, sizeof (current_pc));
    g_assert (write_succeeded);
  }
  else
  {
    guint32 temp[3];
    gboolean write_succeeded;

    current_pc = state.uts.ts32.__eip;
    state.uts.ts32.__eip = self->dlopen_address;

    temp[0] = current_pc;
    temp[1] = lib_name;
    temp[2] = mode;
    state.uts.ts32.__esp -= 16;
    write_succeeded = gum_darwin_write (self->task, state.uts.ts32.__esp, (const guint8 *) &temp, sizeof (temp));
    g_assert (write_succeeded);
  }
#else
  if (self->cpu_type == GUM_CPU_ARM64)
  {
    current_pc = state.ts_64.__pc;
    state.ts_64.__pc = self->dlopen_address;
    state.ts_64.__lr = current_pc;
    state.ts_64.__x[0] = lib_name;
    state.ts_64.__x[1] = mode;
  }
  else
  {
    current_pc = state.ts_32.__pc;
    state.ts_32.__pc = self->dlopen_address;
    state.ts_32.__lr = current_pc | 1;
    state.ts_32.__r[0] = lib_name;
    state.ts_32.__r[1] = mode;
  }
#endif

  kr = thread_set_state (self->thread, GUM_DARWIN_THREAD_STATE_FLAVOR,
      (thread_state_t) &state, GUM_DARWIN_THREAD_STATE_COUNT);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
}

static void
frida_make_pipe (int fds[2])
{
  gboolean pipe_opened;
  int res;

  pipe_opened = g_unix_open_pipe (fds, FD_CLOEXEC, NULL);
  g_assert (pipe_opened);

  res = fcntl (fds[0], F_SETNOSIGPIPE, TRUE);
  g_assert_cmpint (res, ==, 0);

  res = fcntl (fds[1], F_SETNOSIGPIPE, TRUE);
  g_assert_cmpint (res, ==, 0);
}

static FridaInjectInstance *
frida_inject_instance_new (FridaDarwinHelperBackend * backend, guint id)
{
  FridaInjectInstance * instance;

  instance = g_slice_new (FridaInjectInstance);
  instance->id = id;

  instance->task = MACH_PORT_NULL;

  instance->payload_address = 0;
  instance->payload_size = 0;
  instance->agent_context = NULL;
  instance->agent_context_size = 0;
  instance->is_mapped = FALSE;

  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  instance->backend = g_object_ref (backend);

  return instance;
}

static FridaInjectInstance *
frida_inject_instance_clone (const FridaInjectInstance * instance, guint id)
{
  FridaInjectInstance * clone;
  mach_port_t self_task;
  mach_vm_address_t agent_context_address = 0;
  kern_return_t kr;

  clone = g_slice_dup (FridaInjectInstance, instance);
  clone->id = id;

  clone->task = MACH_PORT_NULL;

  self_task = mach_task_self ();

  kr = mach_vm_allocate (self_task, &agent_context_address, instance->agent_context_size, VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  clone->agent_context = (FridaAgentContext *) agent_context_address;
  memcpy (clone->agent_context, instance->agent_context, instance->agent_context_size);

  clone->thread = MACH_PORT_NULL;
  clone->thread_monitor_source = NULL;

  g_object_ref (clone->backend);

  return clone;
}

static void
frida_inject_instance_free (FridaInjectInstance * instance)
{
  FridaAgentContext * agent_context = instance->agent_context;
  task_t self_task;
  gboolean can_deallocate_payload;

  self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);

  can_deallocate_payload = !(agent_context != NULL && agent_context->unload_policy != FRIDA_UNLOAD_POLICY_IMMEDIATE && instance->is_mapped);
  if (instance->payload_address != 0 &&
      can_deallocate_payload &&
      frida_inject_instance_task_did_not_exec (instance))
  {
    mach_vm_deallocate (instance->task, instance->payload_address, instance->payload_size);
  }

  if (agent_context != NULL)
    mach_vm_deallocate (self_task, (mach_vm_address_t) agent_context, instance->agent_context_size);

  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);

  g_object_unref (instance->backend);

  g_slice_free (FridaInjectInstance, instance);
}

static gboolean
frida_inject_instance_task_did_not_exec (FridaInjectInstance * instance)
{
  gchar * local_cookie, * remote_cookie;
  gboolean shared_memory_still_mapped;

  local_cookie = g_uuid_string_random ();

  strcpy ((gchar *) instance->agent_context, local_cookie);

  remote_cookie = (gchar *) gum_darwin_read (instance->task, instance->remote_agent_context, strlen (local_cookie) + 1, NULL);
  if (remote_cookie != NULL)
  {
    /*
     * This is racy and the only way to avoid this TOCTOU issue is to perform the mach_vm_deallocate() from
     * the remote process. That would however be very tricky to implement, so we mitigate this by deferring
     * cleanup a couple of seconds.
     *
     * Note that this is not an issue on newer kernels like on iOS 10, where the task port gets invalidated
     * by exec transitions.
     */
    shared_memory_still_mapped = strcmp (remote_cookie, local_cookie) == 0;
  }
  else
  {
    shared_memory_still_mapped = FALSE;
  }

  g_free (remote_cookie);
  g_free (local_cookie);

  return shared_memory_still_mapped;
}

static gboolean
frida_inject_instance_is_resident (FridaInjectInstance * instance)
{
  return instance->agent_context->unload_policy != FRIDA_UNLOAD_POLICY_IMMEDIATE;
}

static gboolean
frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details, const FridaInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error)
{
  bzero (self, sizeof (FridaAgentContext));

  self->unload_policy = FRIDA_UNLOAD_POLICY_IMMEDIATE;
  self->task = MACH_PORT_NULL;
  self->mach_thread = MACH_PORT_NULL;
  self->posix_thread = MACH_PORT_NULL;
  self->constructed = FALSE;
  self->module_handle = NULL;

  if (!frida_agent_context_init_functions (self, resolver, mapper, error))
    return FALSE;

  self->mach_port_allocate_right = MACH_PORT_RIGHT_RECEIVE;

  if (details->cpu_type == GUM_CPU_ARM)
    self->pthread_create_start_routine = payload_base + layout->pthread_code_offset + 1;
  else
    self->pthread_create_start_routine = payload_base + layout->pthread_code_offset;
  self->pthread_create_arg = payload_base + layout->data_offset;

  self->message_that_never_arrives = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (FridaAgentContext, message_that_never_arrives_storage);
  self->message_that_never_arrives_storage.header.msgh_size = sizeof (mach_msg_empty_rcv_t);

  self->dylib_path = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (FridaAgentContext, dylib_path_storage);
  if (details->dylib_path != NULL)
    strcpy (self->dylib_path_storage, details->dylib_path);
  self->dlopen_mode = RTLD_LAZY;

  self->entrypoint_name = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (FridaAgentContext, entrypoint_name_storage);
  strcpy (self->entrypoint_name_storage, details->entrypoint_name);

  self->entrypoint_data = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (FridaAgentContext, entrypoint_data_storage);
  g_assert_cmpint (strlen (details->entrypoint_data), <, sizeof (self->entrypoint_data_storage));
  strcpy (self->entrypoint_data_storage, details->entrypoint_data);

  self->mapped_range = (mapper != NULL)
      ? payload_base + layout->data_offset + G_STRUCT_OFFSET (FridaAgentContext, mapped_range_storage)
      : 0;
  self->mapped_range_storage.base_address = payload_base;
  self->mapped_range_storage.size = payload_size;

  return TRUE;
}

#define FRIDA_AGENT_CONTEXT_RESOLVE(field) \
  G_STMT_START \
  { \
    FRIDA_AGENT_CONTEXT_TRY_RESOLVE (field); \
    if (self->field##_impl == 0) \
      goto handle_resolve_error; \
  } \
  G_STMT_END
#define FRIDA_AGENT_CONTEXT_TRY_RESOLVE(field) \
  self->field##_impl = gum_darwin_module_resolver_find_export_address (resolver, module, G_STRINGIFY (field))

static gboolean
frida_agent_context_init_functions (FridaAgentContext * self, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error)
{
  GumDarwinModule * module;

  module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/libsystem_kernel.dylib");
  if (module == NULL)
    goto handle_libc_error;
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_task_self);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_thread_self);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_port_allocate);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_msg_receive);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_port_destroy);
  FRIDA_AGENT_CONTEXT_RESOLVE (thread_terminate);

  module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/libsystem_pthread.dylib");
  if (module == NULL)
    module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/introspection/libsystem_pthread.dylib");
  if (module == NULL)
    goto handle_libc_error;
  FRIDA_AGENT_CONTEXT_TRY_RESOLVE (pthread_create_from_mach_thread);
  if (self->pthread_create_from_mach_thread_impl != 0)
    self->pthread_create_impl = self->pthread_create_from_mach_thread_impl;
  else
    FRIDA_AGENT_CONTEXT_RESOLVE (pthread_create);
  FRIDA_AGENT_CONTEXT_RESOLVE (pthread_detach);
  FRIDA_AGENT_CONTEXT_RESOLVE (pthread_self);

  if (mapper == NULL)
  {
    module = gum_darwin_module_resolver_find_module (resolver, "/usr/lib/system/libdyld.dylib");
    if (module == NULL)
      goto handle_libc_error;
    FRIDA_AGENT_CONTEXT_RESOLVE (dlopen);
    FRIDA_AGENT_CONTEXT_RESOLVE (dlsym);
    FRIDA_AGENT_CONTEXT_RESOLVE (dlclose);
  }

  return TRUE;

handle_libc_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to attach to processes without Apple's libc (for now)");
    goto error_epilogue;
  }
handle_resolve_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving functions");
    goto error_epilogue;
  }
error_epilogue:
  {
    return FALSE;
  }
}

#ifdef HAVE_I386

static void frida_agent_context_emit_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);

static void
frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, cpu_type);
  ctx.mapper = mapper;

  frida_agent_context_emit_mach_stub_body (self, &ctx);
  gum_x86_writer_put_breakpoint (&ctx.cw);

  gum_x86_writer_clear (&ctx.cw);
}

static void
frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper)
{
  FridaAgentEmitContext ctx;
  guint locals_size;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, cpu_type);
  ctx.mapper = mapper;

  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_mov_reg_reg (&ctx.cw, GUM_REG_XBP, GUM_REG_XSP);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XDI);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XSI);

  locals_size = (ctx.cw.target_cpu == GUM_CPU_IA32) ? 12 : 8;
  gum_x86_writer_put_sub_reg_imm (&ctx.cw, GUM_REG_XSP, locals_size);

  if (ctx.cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx.cw, GUM_REG_XBX, GUM_REG_XBP, 8);
  else
    gum_x86_writer_put_mov_reg_reg (&ctx.cw, GUM_REG_XBX, GUM_REG_XDI);

  frida_agent_context_emit_pthread_stub_body (self, &ctx);

  gum_x86_writer_put_add_reg_imm (&ctx.cw, GUM_REG_XSP, locals_size);

  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XSI);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XDI);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_leave (&ctx.cw);
  gum_x86_writer_put_ret (&ctx.cw);

  gum_x86_writer_clear (&ctx.cw);
}

#define EMIT_MOVE(dstreg, srcreg) \
    gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_##dstreg, GUM_REG_##srcreg)
#define EMIT_LEA(dst, src, offset) \
    gum_x86_writer_put_lea_reg_reg_offset (&ctx->cw, GUM_REG_##dst, GUM_REG_##src, offset)
#define EMIT_LOAD(reg, field) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_##reg, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_LOAD_ADDRESS_OF(reg, field) \
    gum_x86_writer_put_lea_reg_reg_offset (&ctx->cw, GUM_REG_##reg, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_STORE(field, reg) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, field), GUM_REG_##reg)
#define EMIT_CALL(fun, ...) \
    gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, fun), __VA_ARGS__)

static void
frida_agent_context_emit_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * again = "again";

  EMIT_CALL (mach_task_self_impl, 0);
  EMIT_STORE (task, EAX);

  EMIT_CALL (mach_thread_self_impl, 0);
  EMIT_STORE (mach_thread, EAX);

  gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 16);

  EMIT_LOAD (EDI, task);
  EMIT_LOAD (ESI, mach_port_allocate_right);
  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XDX, GUM_REG_XSP);
  EMIT_CALL (mach_port_allocate_impl,
      3,
      GUM_ARG_REGISTER, GUM_REG_EDI,
      GUM_ARG_REGISTER, GUM_REG_ESI,
      GUM_ARG_REGISTER, GUM_REG_XDX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_EAX, GUM_REG_XSP, 0);
  EMIT_STORE (receive_port, EAX);
  EMIT_LOAD (XDI, message_that_never_arrives);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_REG_XDI, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port), GUM_REG_EAX);

  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XDI, GUM_REG_XSP);
  EMIT_LOAD (XDX, pthread_create_start_routine);
  EMIT_LOAD (XCX, pthread_create_arg);
  EMIT_CALL (pthread_create_impl,
      4,
      GUM_ARG_REGISTER, GUM_REG_XDI,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 16);

  gum_x86_writer_put_label (&ctx->cw, again);

  EMIT_LOAD (XAX, message_that_never_arrives);
  EMIT_CALL (mach_msg_receive_impl,
      1,
      GUM_ARG_REGISTER, GUM_REG_XAX);

  gum_x86_writer_put_jmp_short_label (&ctx->cw, again);
}

static void
frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  gssize pointer_size, injector_state_offset;
  const gchar * skip_construction = "skip_construction";
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_destruction = "skip_destruction";
  const gchar * skip_detach = "skip_detach";

  EMIT_CALL (mach_thread_self_impl, 0);
  EMIT_STORE (posix_thread, EAX);

  EMIT_LOAD (EDI, task);
  EMIT_LOAD (ESI, receive_port);
  EMIT_CALL (mach_port_destroy_impl,
      2,
      GUM_ARG_REGISTER, GUM_REG_EDI,
      GUM_ARG_REGISTER, GUM_REG_ESI);

  EMIT_LOAD (EDI, mach_thread);
  EMIT_CALL (thread_terminate_impl,
      1,
      GUM_ARG_REGISTER, GUM_REG_EDI);

  pointer_size = (ctx->cw.target_cpu == GUM_CPU_IA32) ? 4 : 8;

  injector_state_offset = -(3 + 1) * pointer_size;
  EMIT_LOAD (XDX, mapped_range);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw,
      GUM_REG_XBP, injector_state_offset + G_STRUCT_OFFSET (FridaDarwinInjectorState, mapped_range),
      GUM_REG_XDX);

  if (ctx->mapper != NULL)
  {
    EMIT_LOAD (EAX, constructed);
    gum_x86_writer_put_test_reg_reg (&ctx->cw, GUM_REG_EAX, GUM_REG_EAX);
    gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JNE, skip_construction, GUM_NO_HINT);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, gum_darwin_mapper_constructor (ctx->mapper));
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XAX, 0);
    gum_x86_writer_put_mov_reg_u32 (&ctx->cw, GUM_REG_EAX, TRUE);
    EMIT_STORE (constructed, EAX);

    gum_x86_writer_put_label (&ctx->cw, skip_construction);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_LOAD (XDI, entrypoint_data);
    EMIT_LOAD_ADDRESS_OF (XSI, unload_policy);
    EMIT_LEA (XDX, XBP, injector_state_offset);
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XAX,
        3,
        GUM_ARG_REGISTER, GUM_REG_XDI,
        GUM_ARG_REGISTER, GUM_REG_XSI,
        GUM_ARG_REGISTER, GUM_REG_XDX);
  }
  else
  {
    EMIT_LOAD (XAX, module_handle);
    gum_x86_writer_put_test_reg_reg (&ctx->cw, GUM_REG_XAX, GUM_REG_XAX);
    gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JNE, skip_dlopen, GUM_NO_HINT);

    EMIT_LOAD (XDI, dylib_path);
    EMIT_LOAD (ESI, dlopen_mode);
    EMIT_CALL (dlopen_impl,
        2,
        GUM_ARG_REGISTER, GUM_REG_XDI,
        GUM_ARG_REGISTER, GUM_REG_ESI);
    EMIT_STORE (module_handle, XAX);

    gum_x86_writer_put_label (&ctx->cw, skip_dlopen);

    EMIT_LOAD (XSI, entrypoint_name);
    EMIT_CALL (dlsym_impl,
        2,
        GUM_ARG_REGISTER, GUM_REG_XAX,
        GUM_ARG_REGISTER, GUM_REG_XSI);

    EMIT_LOAD (XDI, entrypoint_data);
    EMIT_LOAD_ADDRESS_OF (XSI, unload_policy);
    EMIT_LEA (XDX, XBP, injector_state_offset);
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XAX,
        3,
        GUM_ARG_REGISTER, GUM_REG_XDI,
        GUM_ARG_REGISTER, GUM_REG_XSI,
        GUM_ARG_REGISTER, GUM_REG_XDX);
  }

  EMIT_LOAD (EAX, unload_policy);
  gum_x86_writer_put_cmp_reg_i32 (&ctx->cw, GUM_REG_EAX, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JNE, skip_destruction, GUM_NO_HINT);

  if (ctx->mapper != NULL)
  {
    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, gum_darwin_mapper_destructor (ctx->mapper));
    gum_x86_writer_put_call_reg_with_aligned_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XAX, 0);
  }
  else
  {
    EMIT_LOAD (XDI, module_handle);
    EMIT_CALL (dlclose_impl,
        1,
        GUM_ARG_REGISTER, GUM_REG_XDI);
  }

  gum_x86_writer_put_label (&ctx->cw, skip_destruction);

  EMIT_LOAD (EAX, unload_policy);
  gum_x86_writer_put_cmp_reg_i32 (&ctx->cw, GUM_REG_EAX, FRIDA_UNLOAD_POLICY_DEFERRED);
  gum_x86_writer_put_jcc_short_label (&ctx->cw, X86_INS_JE, skip_detach, GUM_NO_HINT);

  EMIT_CALL (pthread_self_impl, 0);

  EMIT_CALL (pthread_detach_impl,
      1,
      GUM_ARG_REGISTER, GUM_REG_XAX);

  gum_x86_writer_put_label (&ctx->cw, skip_detach);
}

#else

/*
 * ARM 32- and 64-bit
 */

static void frida_agent_context_emit_arm_mach_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper);
static void frida_agent_context_emit_arm_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper);
static void frida_agent_context_emit_arm_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm_load_reg_with_ctx_value (arm_reg reg, guint field_offset, GumThumbWriter * tw);
static void frida_agent_context_emit_arm_store_reg_in_ctx_value (guint field_offset, arm_reg reg, GumThumbWriter * tw);

static void frida_agent_context_emit_arm64_mach_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper);
static void frida_agent_context_emit_arm64_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper);
static void frida_agent_context_emit_arm64_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);
static void frida_agent_context_emit_arm64_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx);

static void
frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper)
{
  if (cpu_type == GUM_CPU_ARM)
    frida_agent_context_emit_arm_mach_stub_code (self, code, mapper);
  else
    frida_agent_context_emit_arm64_mach_stub_code (self, code, mapper);
}

static void
frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper)
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
frida_agent_context_emit_arm_mach_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);
  ctx.mapper = mapper;

  frida_agent_context_emit_arm_mach_stub_body (self, &ctx);

  gum_thumb_writer_clear (&ctx.tw);
}

static void
frida_agent_context_emit_arm_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);
  ctx.mapper = mapper;

  gum_thumb_writer_put_push_regs (&ctx.tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
  gum_thumb_writer_put_mov_reg_reg (&ctx.tw, ARM_REG_R7, ARM_REG_R0);
  frida_agent_context_emit_arm_pthread_stub_body (self, &ctx);
  gum_thumb_writer_put_pop_regs (&ctx.tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);

  gum_thumb_writer_clear (&ctx.tw);
}

#define EMIT_ARM_LOAD(reg, field) \
    frida_agent_context_emit_arm_load_reg_with_ctx_value (ARM_REG_##reg, G_STRUCT_OFFSET (FridaAgentContext, field), &ctx->tw)
#define EMIT_ARM_LOAD_ADDRESS_OF(reg, field) \
    gum_thumb_writer_put_add_reg_reg_imm (&ctx->tw, ARM_REG_##reg, ARM_REG_R7, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_ARM_LOAD_U32(reg, val) \
    gum_thumb_writer_put_ldr_reg_u32 (&ctx->tw, ARM_REG_##reg, val)
#define EMIT_ARM_STORE(field, reg) \
    frida_agent_context_emit_arm_store_reg_in_ctx_value (G_STRUCT_OFFSET (FridaAgentContext, field), ARM_REG_##reg, &ctx->tw)
#define EMIT_ARM_MOVE(dstreg, srcreg) \
    gum_thumb_writer_put_mov_reg_reg (&ctx->tw, ARM_REG_##dstreg, ARM_REG_##srcreg)
#define EMIT_ARM_CALL(reg) \
    gum_thumb_writer_put_blx_reg (&ctx->tw, ARM_REG_##reg)
#define EMIT_ARM_STACK_ADJUSTMENT(delta) \
    gum_thumb_writer_put_sub_reg_imm (&ctx->tw, ARM_REG_SP, delta * 4)

static void
frida_agent_context_emit_arm_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * again = "again";

  EMIT_ARM_LOAD (R4, mach_task_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_STORE (task, R0);

  EMIT_ARM_LOAD (R4, mach_thread_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_STORE (mach_thread, R0);

  EMIT_ARM_LOAD (R0, task);
  EMIT_ARM_LOAD (R1, mach_port_allocate_right);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, ARM_REG_R0);
  EMIT_ARM_MOVE (R2, SP);
  EMIT_ARM_LOAD (R4, mach_port_allocate_impl);
  EMIT_ARM_CALL (R4);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, ARM_REG_R0);
  EMIT_ARM_STORE (receive_port, R0);
  EMIT_ARM_LOAD (R1, message_that_never_arrives);
  gum_thumb_writer_put_str_reg_reg_offset (&ctx->tw, ARM_REG_R0, ARM_REG_R1, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port));

  gum_thumb_writer_put_push_regs (&ctx->tw, 1, ARM_REG_R0);
  EMIT_ARM_MOVE (R0, SP);
  EMIT_ARM_LOAD_U32 (R1, 0);
  EMIT_ARM_LOAD (R2, pthread_create_start_routine);
  EMIT_ARM_LOAD (R3, pthread_create_arg);
  EMIT_ARM_LOAD (R4, pthread_create_impl);
  EMIT_ARM_CALL (R4);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, ARM_REG_R0);

  gum_thumb_writer_put_label (&ctx->tw, again);

  EMIT_ARM_LOAD (R0, message_that_never_arrives);
  EMIT_ARM_LOAD (R4, mach_msg_receive_impl);
  EMIT_ARM_CALL (R4);

  gum_thumb_writer_put_b_label (&ctx->tw, again);
}

static void
frida_agent_context_emit_arm_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * skip_construction = "skip_construction";
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_destruction = "skip_destruction";
  const gchar * skip_detach = "skip_detach";

  EMIT_ARM_LOAD (R4, mach_thread_self_impl);
  EMIT_ARM_CALL (R4);
  EMIT_ARM_STORE (posix_thread, R0);

  EMIT_ARM_LOAD (R0, task);
  EMIT_ARM_LOAD (R1, receive_port);
  EMIT_ARM_LOAD (R4, mach_port_destroy_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_LOAD (R0, mach_thread);
  EMIT_ARM_LOAD (R4, thread_terminate_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_STACK_ADJUSTMENT (3);
  EMIT_ARM_LOAD (R0, mapped_range);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, ARM_REG_R0); /* DarwinInjectorState */

  if (ctx->mapper != NULL)
  {
    EMIT_ARM_LOAD (R0, constructed);
    gum_thumb_writer_put_cbnz_reg_label (&ctx->tw, ARM_REG_R0, skip_construction);

    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM_CALL (R4);
    gum_thumb_writer_put_mov_reg_u8 (&ctx->tw, ARM_REG_R0, TRUE);
    EMIT_ARM_STORE (constructed, R0);

    gum_thumb_writer_put_label (&ctx->tw, skip_construction);

    EMIT_ARM_LOAD (R0, entrypoint_data);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, unload_policy);
    EMIT_ARM_MOVE (R2, SP);
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_ARM_CALL (R4);
  }
  else
  {
    EMIT_ARM_LOAD (R5, module_handle);
    gum_thumb_writer_put_cbnz_reg_label (&ctx->tw, ARM_REG_R5, skip_dlopen);

    EMIT_ARM_LOAD (R0, dylib_path);
    EMIT_ARM_LOAD (R1, dlopen_mode);
    EMIT_ARM_LOAD (R4, dlopen_impl);
    EMIT_ARM_CALL (R4);
    EMIT_ARM_MOVE (R5, R0);
    EMIT_ARM_STORE (module_handle, R5);

    gum_thumb_writer_put_label (&ctx->tw, skip_dlopen);

    EMIT_ARM_MOVE (R0, R5);
    EMIT_ARM_LOAD (R1, entrypoint_name);
    EMIT_ARM_LOAD (R4, dlsym_impl);
    EMIT_ARM_CALL (R4);
    EMIT_ARM_MOVE (R4, R0);

    EMIT_ARM_LOAD (R0, entrypoint_data);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, unload_policy);
    EMIT_ARM_MOVE (R2, SP);
    EMIT_ARM_CALL (R4);
  }

  EMIT_ARM_STACK_ADJUSTMENT (-4);

  EMIT_ARM_LOAD (R0, unload_policy);
  gum_thumb_writer_put_cmp_reg_imm (&ctx->tw, ARM_REG_R0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  gum_thumb_writer_put_bne_label (&ctx->tw, skip_destruction);

  if (ctx->mapper != NULL)
  {
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_destructor (ctx->mapper));
    EMIT_ARM_CALL (R4);
  }
  else
  {
    EMIT_ARM_MOVE (R0, R5);
    EMIT_ARM_LOAD (R4, dlclose_impl);
    EMIT_ARM_CALL (R4);
  }

  gum_thumb_writer_put_label (&ctx->tw, skip_destruction);

  EMIT_ARM_LOAD (R0, unload_policy);
  gum_thumb_writer_put_cmp_reg_imm (&ctx->tw, ARM_REG_R0, FRIDA_UNLOAD_POLICY_DEFERRED);
  gum_thumb_writer_put_beq_label (&ctx->tw, skip_detach);

  EMIT_ARM_LOAD (R4, pthread_self_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_LOAD (R4, pthread_detach_impl);
  EMIT_ARM_CALL (R4);

  gum_thumb_writer_put_label (&ctx->tw, skip_detach);
}

static void
frida_agent_context_emit_arm_load_reg_with_ctx_value (arm_reg reg, guint field_offset, GumThumbWriter * tw)
{
  arm_reg tmp_reg = (reg != ARM_REG_R0) ? ARM_REG_R0 : ARM_REG_R1;
  gum_thumb_writer_put_push_regs (tw, 1, tmp_reg);
  gum_thumb_writer_put_ldr_reg_u32 (tw, tmp_reg, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, reg, ARM_REG_R7, tmp_reg);
  gum_thumb_writer_put_ldr_reg_reg (tw, reg, reg);
  gum_thumb_writer_put_pop_regs (tw, 1, tmp_reg);
}

static void
frida_agent_context_emit_arm_store_reg_in_ctx_value (guint field_offset, arm_reg reg, GumThumbWriter * tw)
{
  arm_reg tmp_reg = (reg != ARM_REG_R0) ? ARM_REG_R0 : ARM_REG_R1;
  gum_thumb_writer_put_push_regs (tw, 1, tmp_reg);
  gum_thumb_writer_put_ldr_reg_u32 (tw, tmp_reg, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, tmp_reg, ARM_REG_R7, tmp_reg);
  gum_thumb_writer_put_str_reg_reg (tw, reg, tmp_reg);
  gum_thumb_writer_put_pop_regs (tw, 1, tmp_reg);
}


/*
 * ARM 64-bit
 */

static void
frida_agent_context_emit_arm64_mach_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_arm64_writer_init (&ctx.aw, ctx.code);
  ctx.mapper = mapper;

  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_X21, ARM64_REG_X22);
  frida_agent_context_emit_arm64_mach_stub_body (self, &ctx);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&ctx.aw);

  gum_arm64_writer_clear (&ctx.aw);
}

static void
frida_agent_context_emit_arm64_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumDarwinMapper * mapper)
{
  FridaAgentEmitContext ctx;

  ctx.code = code;
  gum_arm64_writer_init (&ctx.aw, ctx.code);
  ctx.mapper = mapper;

  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_mov_reg_reg (&ctx.aw, ARM64_REG_X20, ARM64_REG_X0);
  frida_agent_context_emit_arm64_pthread_stub_body (self, &ctx);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&ctx.aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&ctx.aw);
  gum_arm64_writer_clear (&ctx.aw);
}

#define EMIT_ARM64_LOAD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&ctx->aw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_ARM64_LOAD_ADDRESS_OF(reg, field) \
    gum_arm64_writer_put_add_reg_reg_imm (&ctx->aw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_ARM64_LOAD_U64(reg, val) \
    gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_##reg, val)
#define EMIT_ARM64_STORE(field, reg) \
    gum_arm64_writer_put_str_reg_reg_offset (&ctx->aw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaAgentContext, field))
#define EMIT_ARM64_MOVE(dstreg, srcreg) \
    gum_arm64_writer_put_mov_reg_reg (&ctx->aw, ARM64_REG_##dstreg, ARM64_REG_##srcreg)
#define EMIT_ARM64_CALL(reg) \
    gum_arm64_writer_put_blr_reg (&ctx->aw, ARM64_REG_##reg)

static void
frida_agent_context_emit_arm64_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * again = "again";

  EMIT_ARM64_LOAD (X8, mach_task_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_STORE (task, W0);

  EMIT_ARM64_LOAD (X8, mach_thread_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_STORE (mach_thread, W0);

  EMIT_ARM64_LOAD (W0, task);
  EMIT_ARM64_LOAD (W1, mach_port_allocate_right);
  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_MOVE (X2, SP);
  EMIT_ARM64_LOAD (X8, mach_port_allocate_impl);
  EMIT_ARM64_CALL (X8);
  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_STORE (receive_port, W0);
  EMIT_ARM64_LOAD (X1, message_that_never_arrives);
  gum_arm64_writer_put_str_reg_reg_offset (&ctx->aw, ARM64_REG_W0, ARM64_REG_X1, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port));

  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_MOVE (X0, SP);
  EMIT_ARM64_LOAD_U64 (X1, 0);
  EMIT_ARM64_LOAD (X2, pthread_create_start_routine);
  EMIT_ARM64_LOAD (X3, pthread_create_arg);
  EMIT_ARM64_LOAD (X8, pthread_create_impl);
  EMIT_ARM64_CALL (X8);
  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);

  gum_arm64_writer_put_label (&ctx->aw, again);

  EMIT_ARM64_LOAD (X0, message_that_never_arrives);
  EMIT_ARM64_LOAD (X8, mach_msg_receive_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_b_label (&ctx->aw, again);
}

static void
frida_agent_context_emit_arm64_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * skip_construction = "skip_construction";
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_destruction = "skip_destruction";
  const gchar * skip_detach = "skip_detach";

  EMIT_ARM64_LOAD (X8, mach_thread_self_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_STORE (posix_thread, W0);

  EMIT_ARM64_LOAD (W0, task);
  EMIT_ARM64_LOAD (W1, receive_port);
  EMIT_ARM64_LOAD (X8, mach_port_destroy_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (W0, mach_thread);
  EMIT_ARM64_LOAD (X8, thread_terminate_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (X0, mapped_range);
  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1); /* DarwinInjectorState */

  if (ctx->mapper != NULL)
  {
    EMIT_ARM64_LOAD (W0, constructed);
    gum_arm64_writer_put_cbnz_reg_label (&ctx->aw, ARM64_REG_W0, skip_construction);

    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM64_CALL (X8);
    gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_X1, TRUE);
    EMIT_ARM64_STORE (constructed, W1);

    gum_arm64_writer_put_label (&ctx->aw, skip_construction);

    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, unload_policy);
    EMIT_ARM64_MOVE (X2, SP);
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_ARM64_CALL (X8);
  }
  else
  {
    EMIT_ARM64_LOAD (X19, module_handle);
    gum_arm64_writer_put_cbnz_reg_label (&ctx->aw, ARM64_REG_X19, skip_dlopen);

    EMIT_ARM64_LOAD (X0, dylib_path);
    EMIT_ARM64_LOAD (X1, dlopen_mode);
    EMIT_ARM64_LOAD (X8, dlopen_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X19, X0);
    EMIT_ARM64_STORE (module_handle, X19);

    gum_arm64_writer_put_label (&ctx->aw, skip_dlopen);

    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X1, entrypoint_name);
    EMIT_ARM64_LOAD (X8, dlsym_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X8, X0);

    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, unload_policy);
    EMIT_ARM64_MOVE (X2, SP);
    EMIT_ARM64_CALL (X8);
  }

  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);

  EMIT_ARM64_LOAD (W0, unload_policy);
  gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_X1, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  gum_arm64_writer_put_cmp_reg_reg (&ctx->aw, ARM64_REG_W0, ARM64_REG_W1);
  gum_arm64_writer_put_b_cond_label (&ctx->aw, ARM64_CC_NE, skip_destruction);

  if (ctx->mapper != NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8, gum_darwin_mapper_destructor (ctx->mapper));
    EMIT_ARM64_CALL (X8);
  }
  else
  {
    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X8, dlclose_impl);
    EMIT_ARM64_CALL (X8);
  }

  gum_arm64_writer_put_label (&ctx->aw, skip_destruction);

  EMIT_ARM64_LOAD (W0, unload_policy);
  gum_arm64_writer_put_ldr_reg_u64 (&ctx->aw, ARM64_REG_X1, FRIDA_UNLOAD_POLICY_DEFERRED);
  gum_arm64_writer_put_cmp_reg_reg (&ctx->aw, ARM64_REG_W0, ARM64_REG_W1);
  gum_arm64_writer_put_b_cond_label (&ctx->aw, ARM64_CC_EQ, skip_detach);

  EMIT_ARM64_LOAD (X8, pthread_self_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (X8, pthread_detach_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_label (&ctx->aw, skip_detach);
}

#endif

static kern_return_t
frida_get_debug_state (mach_port_t thread, gpointer state, GumCpuType cpu_type)
{
  mach_msg_type_number_t state_count;
  kern_return_t kr;

#ifdef HAVE_I386
  state_count = x86_DEBUG_STATE_COUNT;
  kr = thread_get_state (thread, x86_DEBUG_STATE, state, &state_count);
#else
  if (cpu_type == GUM_CPU_ARM64)
  {
    state_count = ARM_DEBUG_STATE64_COUNT;
    kr = thread_get_state (thread, ARM_DEBUG_STATE64, state, &state_count);
  }
  else
  {
    state_count = ARM_DEBUG_STATE_COUNT;
    kr = thread_get_state (thread, ARM_DEBUG_STATE, state, &state_count);
  }
#endif

  return kr;
}

static kern_return_t
frida_set_debug_state (mach_port_t thread, gconstpointer state, GumCpuType cpu_type)
{
  mach_msg_type_number_t state_count;
  kern_return_t kr;

#ifdef HAVE_I386
  state_count = x86_DEBUG_STATE_COUNT;
  kr = thread_set_state (thread, x86_DEBUG_STATE, (thread_state_t) state, state_count);
#else
  if (cpu_type == GUM_CPU_ARM64)
  {
    state_count = ARM_DEBUG_STATE64_COUNT;
    kr = thread_set_state (thread, ARM_DEBUG_STATE64, (thread_state_t) state, state_count);
  }
  else
  {
    state_count = ARM_DEBUG_STATE_COUNT;
    kr = thread_set_state (thread, ARM_DEBUG_STATE, (thread_state_t) state, state_count);
  }
#endif

  return kr;
}

static void
frida_set_nth_hardware_breakpoint (gpointer state, guint n, GumAddress break_at, GumCpuType cpu_type)
{
#ifdef HAVE_I386
  x86_debug_state_t * s = state;

  if (cpu_type == GUM_CPU_AMD64)
  {
    x86_debug_state64_t * ds = &s->uds.ds64;

    ((guint64 *) &ds->__dr0)[n] = break_at;
    ds->__dr7 |= 1 << (n * 2);
  }
  else
  {
    x86_debug_state32_t * ds = &s->uds.ds32;

    ((guint32 *) &ds->__dr0)[n] = break_at;
    ds->__dr7 |= 1 << (n * 2);
  }
#else
# define FRIDA_S_USER ((uint32_t) (2u << 1))
# define FRIDA_BAS_ANY ((uint32_t) 15u)
# define FRIDA_BCR_ENABLE ((uint32_t) 1u)

  if (cpu_type == GUM_CPU_ARM64)
  {
    arm_debug_state64_t * s = state;

    s->__bvr[n] = break_at;
    s->__bcr[n] = (FRIDA_BAS_ANY << 5) | FRIDA_S_USER | FRIDA_BCR_ENABLE;
  }
  else
  {
    arm_debug_state_t * s = state;

    s->__bvr[n] = break_at;
    s->__bcr[n] = (FRIDA_BAS_ANY << 5) | FRIDA_S_USER | FRIDA_BCR_ENABLE;
  }
#endif
}

static GumAddress
frida_find_run_initializers_call (mach_port_t task, GumCpuType cpu_type, GumAddress start)
{
  GumAddress found = 0;
  const size_t max_size = 2048;
  uint64_t address = start & ~G_GUINT64_CONSTANT (1);
  csh capstone;
  cs_err err;
  gpointer image;
  cs_insn * insn;
  const uint8_t * code;
  size_t size;

  capstone = frida_create_capstone (cpu_type, start);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  image = gum_darwin_read (task, address, max_size, NULL);

  insn = cs_malloc (capstone);
  code = image;
  size = max_size;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_MOV)
        {
          const cs_x86_op * src = &insn->detail->x86.operands[1];
          if (src->type == X86_OP_MEM && src->mem.base != X86_REG_EBP && src->mem.disp == 0x18)
          {
            found = insn->address;
            break;
          }
        }
      }
      break;

    case GUM_CPU_AMD64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_CALL)
        {
          const cs_x86_op * op = &insn->detail->x86.operands[0];
          if (op->type == X86_OP_MEM && op->mem.disp == 0x28)
          {
            found = insn->address;
            break;
          }
        }
      }
      break;

    case GUM_CPU_ARM64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM64_INS_LDR && insn->detail->arm64.operands[1].mem.disp == 0x28)
        {
          found = insn->address;
          break;
        }
      }
      break;

    default:
      g_assert_not_reached ();
  }

  cs_free (insn, 1);
  cs_close (&capstone);
  g_free (image);

  return found;
}

static GumAddress
frida_find_function_end (mach_port_t task, GumCpuType cpu_type, GumAddress start, gsize max_size)
{
  GumAddress found = 0;
  uint64_t address = start & ~G_GUINT64_CONSTANT (1);
  csh capstone;
  cs_err err;
  gpointer image;
  cs_insn * insn;
  const uint8_t * code;
  size_t size;

  capstone = frida_create_capstone (cpu_type, start);

  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  image = gum_darwin_read (task, address, max_size, NULL);

  insn = cs_malloc (capstone);
  code = image;
  size = max_size;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_AMD64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == X86_INS_RET ||
            insn->id == X86_INS_RETF ||
            insn->id == X86_INS_RETFQ)
        {
          found = insn->address;
          break;
        }
      }
      break;

    case GUM_CPU_ARM:
    {
      int i, pop_lr = -1;

      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM_INS_PUSH &&
            insn->address == (start & ~1))
        {
          for (i = 0; i != insn->detail->arm.op_count; i++)
          {
            if (insn->detail->arm.operands[i].reg == ARM_REG_LR)
            {
              pop_lr = i;
              break;
            }
          }
        }

        if ((insn->id == ARM_INS_BX || insn->id == ARM_INS_BXJ) &&
            insn->detail->arm.operands[0].type == ARM_OP_REG &&
            insn->detail->arm.operands[0].reg == ARM_REG_LR)
        {
          found = insn->address;
          break;
        }

        if (insn->id == ARM_INS_POP &&
            pop_lr >= 0 &&
            pop_lr < insn->detail->arm.op_count)
        {
          if (insn->detail->arm.operands[pop_lr].reg == ARM_REG_PC)
          {
            found = insn->address;
            break;
          }
        }
      }

      break;
    }

    case GUM_CPU_ARM64:
      while (cs_disasm_iter (capstone, &code, &size, &address, insn))
      {
        if (insn->id == ARM64_INS_RET)
        {
          found = insn->address;
          break;
        }
      }
      break;

    default:
      g_assert_not_reached ();
  }

  cs_free (insn, 1);
  cs_close (&capstone);
  g_free (image);

  return found;
}

static csh
frida_create_capstone (GumCpuType cpu_type, GumAddress start)
{
  csh capstone;
  cs_err err;

  switch (cpu_type)
  {
    case GUM_CPU_ARM64:
      err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
      break;

    case GUM_CPU_ARM:
      if (start & 1)
        err = cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &capstone);
      else
        err = cs_open (CS_ARCH_ARM, CS_MODE_ARM, &capstone);
      break;

    case GUM_CPU_IA32:
      err = cs_open (CS_ARCH_X86, CS_MODE_32, &capstone);
      break;

    case GUM_CPU_AMD64:
      err = cs_open (CS_ARCH_X86, CS_MODE_64, &capstone);
      break;

    default:
      g_assert_not_reached ();
  }

  g_assert_cmpint (err, ==, CS_ERR_OK);

  return capstone;
}

static void
frida_mapper_library_blob_deallocate (FridaMappedLibraryBlob * self)
{
  mach_vm_deallocate (mach_task_self (), self->_address, self->_allocated_size);

  frida_mapped_library_blob_free (self);
}

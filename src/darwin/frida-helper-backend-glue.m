#include "frida-helper-backend.h"

#include <capstone.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#import <Foundation/Foundation.h>
#include <glib-unix.h>
#include <spawn.h>
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

typedef struct _FridaHelperContext FridaHelperContext;
typedef struct _FridaSpawnInstance FridaSpawnInstance;
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
  arm_debug_state32_t s32;
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

  mach_port_t server_port;
  dispatch_source_t server_recv_source;
  FridaExceptionPortSet previous_ports;

  __Request__exception_raise_state_identity_t pending_request;

  gboolean ready;
};

struct _FridaInjectInstance
{
  FridaDarwinHelperBackend * backend;
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
  gboolean stay_resident;
  mach_port_t task;
  mach_port_t mach_thread;
  mach_port_t posix_thread;

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

static void frida_spawn_instance_on_server_recv (void * context);

static void frida_make_pipe (int fds[2]);

static FridaInjectInstance * frida_inject_instance_new (FridaDarwinHelperBackend * backend, guint id);
static void frida_inject_instance_free (FridaInjectInstance * instance);
static gboolean frida_inject_instance_task_did_not_exec (FridaInjectInstance * instance);
static gboolean frida_inject_instance_is_resident (FridaInjectInstance * instance);

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
static void frida_set_hardware_breakpoint (gpointer state, GumAddress break_at, GumCpuType cpu_type);

static gboolean frida_store_base_address_if_libc (const GumModuleDetails * details, gpointer user_data);
static GumAddress frida_find_libc_initializer (guint task, GumAddress base);
static GumAddress frida_find_libc_initializer_end (guint task, GumCpuType cpu_type, GumAddress start, gsize max_size);
static csh frida_create_capstone (GumCpuType cpu_type, GumAddress start);
static GumAddress frida_get_module_slide (gconstpointer command, gsize ncmds, GumAddress base);

static void frida_mapper_library_blob_deallocate (FridaMappedLibraryBlob * self);

void
frida_darwin_helper_backend_make_pipe_endpoints (guint local_task, guint remote_pid, guint remote_task, FridaPipeEndpoints * result, GError ** error)
{
  mach_port_t self_task;
  mach_port_t local_rx = MACH_PORT_NULL;
  mach_port_t local_tx = MACH_PORT_NULL;
  mach_port_t remote_rx = MACH_PORT_NULL;
  mach_port_t remote_tx = MACH_PORT_NULL;
  mach_msg_type_name_t acquired_type;
  mach_msg_header_t init;
  gchar * local_address, * remote_address;
  kern_return_t ret;
  const gchar * failed_operation;

  self_task = mach_task_self ();

  if (local_task == MACH_PORT_NULL)
    local_task = self_task;

  ret = mach_port_allocate (local_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_allocate local_rx");

  ret = mach_port_allocate (remote_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_allocate remote_rx");

  ret = mach_port_extract_right (local_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &local_tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_extract_right local_rx");

  ret = mach_port_extract_right (remote_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &remote_tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_extract_right remote_rx");

  init.msgh_size = sizeof (init);
  init.msgh_reserved = 0;
  init.msgh_id = 3;

  if (local_task != self_task)
  {
    init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND);
    init.msgh_remote_port = local_tx;
    init.msgh_local_port = remote_tx;
    ret = mach_msg_send (&init);
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_msg_send local_tx");

    init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
  }
  else
  {
    init.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MOVE_SEND);
  }

  init.msgh_remote_port = remote_tx;
  init.msgh_local_port = local_tx;
  ret = mach_msg_send (&init);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_msg_send remote_tx");

  if (local_task != self_task)
    local_address = g_strdup_printf ("pipe:rx=%d", local_rx);
  else
    local_address = g_strdup_printf ("pipe:rx=%d,tx=%d", local_rx, remote_tx);
  remote_address = g_strdup_printf ("pipe:rx=%d", remote_rx);
  frida_pipe_endpoints_init (result, local_address, remote_address);
  g_free (remote_address);
  g_free (local_address);

  return;

handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing pipe endpoints for process with pid %u (%s returned '%s')",
        remote_pid, failed_operation, mach_error_string (ret));

    if (remote_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, remote_tx);
    if (local_tx != MACH_PORT_NULL)
      mach_port_deallocate (self_task, local_tx);
    if (remote_rx != MACH_PORT_NULL)
      mach_port_mod_refs (remote_task, remote_rx, MACH_PORT_RIGHT_RECEIVE, -1);
    if (local_rx != MACH_PORT_NULL)
      mach_port_mod_refs (local_task, local_rx, MACH_PORT_RIGHT_RECEIVE, -1);

    return;
  }
}

guint
frida_darwin_helper_backend_task_for_pid (guint pid, GError ** error)
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
  kern_return_t ret;

  ret = task_info (task, MACH_TASK_BASIC_INFO, (task_info_t) &info, &info_count);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_info");

  return info.suspend_count >= 1;

handle_mach_error:
  {
    if (ret == MACH_SEND_INVALID_DEST)
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
          failed_operation, mach_error_string (ret));
    }
    return FALSE;
  }
}

void
_frida_darwin_helper_backend_resume_process (FridaDarwinHelperBackend * self, guint pid, guint task, GError ** error)
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
  kern_return_t ret;
  mach_port_t self_task, child_thread;
  guint page_size;
  thread_act_array_t threads;
  guint thread_index;
  mach_msg_type_number_t thread_count = 0;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  GumAddress libc_header, probe_address;
  FridaDebugState breakpoint_debug_state;
  FridaExceptionPortSet * previous_ports;
  dispatch_source_t source;
  static GumAddress cached_address_for_breakpoint[6] = { 0, };

  /*
   * We POSIX_SPAWN_START_SUSPENDED which means that the kernel will create
   * the task and its main thread, with the main thread's instruction pointer
   * pointed at __dyld_start. At this point neither dyld nor libc have been
   * initialized, so we won't be able to inject frida-agent at this point.
   *
   * So here's what we'll do before we consider spawn() done:
   * - Get the address of the libSystem.B.dylib module in memory.
   * - Walk its header and find the initializer address (into __mod_init_func),
   *   this function in turn will call all the initializers of libSystem's
   *   sub-libraries.
   * - Disassemble the function to find its only exit point (the RET instruction,
   *   or equivalent).
   * - Set a hardware breakpoint there - at that point things are sufficiently
   *   initialized to allow instrumentation.
   * - Swap out the thread's exception ports with our own.
   * - Resume the task.
   * - Wait until we get a message on our exception port, meaning our breakpoint
   *   was hit.
   * - Swap back the thread's orginal exception ports.
   * - Clear the hardware breakpoint by restoring the thread's debug registers.
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

  ret = task_threads (task, &threads, &thread_count);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_threads");

  child_thread = threads[0];
  instance->thread = child_thread;

  for (thread_index = 1; thread_index < thread_count; thread_index++)
    mach_port_deallocate (self_task, threads[thread_index]);
  vm_deallocate (self_task, (vm_address_t) threads, thread_count * sizeof (thread_t));
  threads = NULL;

  if (cached_address_for_breakpoint[instance->cpu_type] == 0)
  {
    GumAddress initializer, ret_address;

    libc_header = 0;
    gum_darwin_enumerate_modules (task, frida_store_base_address_if_libc, &libc_header);
    if (libc_header == 0)
      goto handle_probe_libc_error;

    initializer = frida_find_libc_initializer (task, libc_header);
    if (initializer == 0)
      goto handle_probe_libc_error;

    ret_address = frida_find_libc_initializer_end (task, instance->cpu_type, initializer, 512);

    cached_address_for_breakpoint[instance->cpu_type] = ret_address;
  }

  probe_address = cached_address_for_breakpoint[instance->cpu_type];

  if (probe_address == 0)
    goto handle_probe_libc_error;

  ret = frida_get_debug_state (child_thread, &instance->previous_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "frida_get_debug_state");

  memcpy (&breakpoint_debug_state, &instance->previous_debug_state, sizeof (breakpoint_debug_state));
  frida_set_hardware_breakpoint (&breakpoint_debug_state, probe_address, instance->cpu_type);

  ret = frida_set_debug_state (child_thread, &breakpoint_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "frida_set_debug_state");

  ret = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &instance->server_port);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_allocate server");

  ret = mach_port_insert_right (self_task, instance->server_port, instance->server_port, MACH_MSG_TYPE_MAKE_SEND);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_insert_right server");

  previous_ports = &instance->previous_ports;
  ret = thread_swap_exception_ports (child_thread,
      EXC_MASK_BREAKPOINT,
      instance->server_port,
      EXCEPTION_DEFAULT,
      state_flavor,
      previous_ports->masks,
      &previous_ports->count,
      previous_ports->ports,
      previous_ports->behaviors,
      previous_ports->flavors);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "thread_swap_exception_ports");

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV, instance->server_port, 0, ctx->dispatch_queue);
  instance->server_recv_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_spawn_instance_on_server_recv);
  dispatch_resume (source);

  ret = task_resume (task);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_resume");

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
handle_probe_libc_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing libSystem initializer of target process");
    goto error_epilogue;
  }
handle_mach_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while preparing target process for injection (%s returned '%s')",
        failed_operation, mach_error_string (ret));
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
  FridaHelperContext * ctx = self->context;
  mach_port_t self_task;
  FridaInjectInstance * instance;
  GumDarwinModuleResolver * resolver = NULL;
  GumDarwinMapper * mapper = NULL;
  FridaAgentDetails details = { 0, };
  guint page_size;
  FridaInjectPayloadLayout layout;
  const gchar * failed_operation;
  kern_return_t ret;
  guint base_payload_size;
  mach_vm_address_t payload_address = 0;
  mach_vm_address_t agent_context_address = 0;
  mach_vm_address_t data_address;
  vm_prot_t cur_protection, max_protection;
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

  self_task = mach_task_self ();

  instance = frida_inject_instance_new (self, self->last_id++);
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

  ret = mach_vm_allocate (task, &payload_address, instance->payload_size, VM_FLAGS_ANYWHERE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_allocate(payload)");
  instance->payload_address = payload_address;

  ret = mach_vm_allocate (self_task, &agent_context_address, layout.data_size, VM_FLAGS_ANYWHERE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_allocate(agent_context)");
  instance->agent_context = (FridaAgentContext *) agent_context_address;
  instance->agent_context_size = layout.data_size;

  data_address = payload_address + layout.data_offset;
  ret = mach_vm_remap (task, &data_address, layout.data_size, 0, VM_FLAGS_OVERWRITE, self_task, agent_context_address,
      FALSE, &cur_protection, &max_protection, VM_INHERIT_SHARE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_remap(data)");
  instance->remote_agent_context = data_address;

  if (mapper != NULL)
  {
    gum_darwin_mapper_map (mapper, payload_address + base_payload_size);

    instance->is_mapped = TRUE;
  }

  ret = mach_vm_protect (task, payload_address + layout.stack_guard_offset, layout.stack_guard_size, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_protect");

  if (!frida_agent_context_init (&agent_ctx, &details, &layout, payload_address, instance->payload_size, resolver, mapper, error))
    goto error_epilogue;

  frida_agent_context_emit_mach_stub_code (&agent_ctx, mach_stub_code, details.cpu_type, mapper);

  frida_agent_context_emit_pthread_stub_code (&agent_ctx, pthread_stub_code, details.cpu_type, mapper);

  if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
  {
    ret = mach_vm_write (task, payload_address + layout.mach_code_offset,
        (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_write(mach_stub_code)");

    ret = mach_vm_write (task, payload_address + layout.pthread_code_offset,
        (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_write(pthread_stub_code)");

    ret = mach_vm_protect (task, payload_address + layout.code_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_protect");
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
    ret = mach_vm_remap (task, &code_address, page_size, 0, VM_FLAGS_OVERWRITE, self_task, (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);

    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_remap(code)");
  }

  ret = mach_vm_write (task, payload_address + layout.data_offset, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_write(data)");

  ret = mach_vm_protect (task, payload_address + layout.data_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_protect");

#ifdef HAVE_I386
  bzero (&state, sizeof (state));

  if (details.cpu_type == GUM_CPU_AMD64)
  {
    x86_thread_state64_t * ts;

    state.tsh.flavor = x86_THREAD_STATE64;
    state.tsh.count = x86_THREAD_STATE64_COUNT;

    ts = &state.uts.ts64;

    ts->__rbx = payload_address + layout.data_offset;

    ts->__rsp = payload_address + layout.stack_top_offset;
    ts->__rip = payload_address + layout.mach_code_offset;
  }
  else
  {
    x86_thread_state32_t * ts;

    state.tsh.flavor = x86_THREAD_STATE32;
    state.tsh.count = x86_THREAD_STATE32_COUNT;

    ts = &state.uts.ts32;

    ts->__ebx = payload_address + layout.data_offset;

    ts->__esp = payload_address + layout.stack_top_offset;
    ts->__eip = payload_address + layout.mach_code_offset;
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

    ts->__x[20] = payload_address + layout.data_offset;

    ts->__sp = payload_address + layout.stack_top_offset;
    ts->__lr = 0xcafebabe;
    ts->__pc = payload_address + layout.mach_code_offset;

    state_data = (thread_state_t) &state64;
    state_count = ARM_UNIFIED_THREAD_STATE_COUNT;
    state_flavor = ARM_UNIFIED_THREAD_STATE;
  }
  else
  {
    bzero (&state32, sizeof (state32));

    state32.__r[7] = payload_address + layout.data_offset;

    state32.__sp = payload_address + layout.stack_top_offset;
    state32.__lr = 0xcafebabe;
    state32.__pc = payload_address + layout.mach_code_offset;
    state32.__cpsr = FRIDA_PSR_THUMB;

    state_data = (thread_state_t) &state32;
    state_count = ARM_THREAD_STATE_COUNT;
    state_flavor = ARM_THREAD_STATE;
  }
#endif

  ret = thread_create (task, &instance->thread);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "thread_create");

  ret = act_set_state (instance->thread, state_flavor, state_data, state_count);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "act_set_state");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, instance->thread, DISPATCH_MACH_SEND_DEAD,
      ctx->dispatch_queue);
  instance->thread_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_inject_instance_on_mach_thread_dead);
  dispatch_resume (source);

  ret = thread_resume (instance->thread);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "thread_resume");

  result = instance->id;
  goto beach;

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
    g_clear_object (&mapper);
    g_clear_object (&resolver);

    return result;
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

  instance->ready = FALSE;

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
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  __Reply__exception_raise_t response;
  mach_msg_header_t * header;
  kern_return_t ret;

  if (!self->ready)
  {
    guint task;
    GError * error = NULL;

    task = frida_darwin_helper_backend_steal_task_for_remote_pid (self->backend, self->pid, &error);
    if (error == NULL)
    {
      _frida_darwin_helper_backend_resume_process (self->backend, self->pid, task, &error);
    }

    g_clear_error (&error);

    return;
  }

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
  ret = mach_msg_send (header);
  if (ret == KERN_SUCCESS)
    request->Head.msgh_remote_port = MACH_PORT_NULL;
}

static void
frida_spawn_instance_on_server_recv (void * context)
{
  FridaSpawnInstance * self = context;
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  mach_msg_header_t * header;
  kern_return_t ret;
  task_t self_task;
  FridaExceptionPortSet * previous_ports;
  mach_msg_type_number_t port_index;

  bzero (request, sizeof (*request));
  header = &request->Head;
  header->msgh_size = sizeof (*request);
  header->msgh_local_port = self->server_port;
  ret = mach_msg_receive (header);
  g_assert_cmpint (ret, ==, 0);

  self_task = mach_task_self ();

  previous_ports = &self->previous_ports;
  for (port_index = 0; port_index != previous_ports->count; port_index++)
  {
    ret = thread_set_exception_ports (self->thread,
        previous_ports->masks[port_index],
        previous_ports->ports[port_index],
        previous_ports->behaviors[port_index],
        previous_ports->flavors[port_index]);
    if (ret != KERN_SUCCESS)
    {
      mach_port_deallocate (self_task, previous_ports->ports[port_index]);
    }
  }
  previous_ports->count = 0;

  frida_set_debug_state (self->thread, &self->previous_debug_state, self->cpu_type);

  self->ready = TRUE;

  _frida_darwin_helper_backend_on_spawn_instance_ready (self->backend, self->pid);
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
  instance->backend = g_object_ref (backend);
  instance->id = id;

  instance->task = MACH_PORT_NULL;

  instance->payload_address = 0;
  instance->payload_size = 0;
  instance->agent_context = NULL;
  instance->agent_context_size = 0;
  instance->is_mapped = FALSE;

  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  return instance;
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

  can_deallocate_payload = !(agent_context != NULL && agent_context->stay_resident && instance->is_mapped);
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
  return instance->agent_context->stay_resident;
}

static gboolean
frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details, const FridaInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinModuleResolver * resolver, GumDarwinMapper * mapper, GError ** error)
{
  bzero (self, sizeof (FridaAgentContext));

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
  self->mapped_range = payload_base + layout->data_offset +
      G_STRUCT_OFFSET (FridaAgentContext, mapped_range_storage);
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

  gum_x86_writer_free (&ctx.cw);
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

  gum_x86_writer_free (&ctx.cw);
}

#define FRIDA_EMIT_LOAD(reg, field) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_##reg, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, field))
#define FRIDA_EMIT_LOAD_ADDRESS_OF(reg, field) \
    gum_x86_writer_put_lea_reg_reg_offset (&ctx->cw, GUM_REG_##reg, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, field))
#define FRIDA_EMIT_STORE(field, reg) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, field), GUM_REG_##reg)
#define FRIDA_EMIT_MOVE(dstreg, srcreg) \
    gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_##dstreg, GUM_REG_##srcreg)
#define FRIDA_EMIT_CALL(fun, ...) \
    gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XBX, G_STRUCT_OFFSET (FridaAgentContext, fun), __VA_ARGS__)

static void
frida_agent_context_emit_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * again_label = "again";

  FRIDA_EMIT_CALL (mach_task_self_impl, 0);
  FRIDA_EMIT_STORE (task, EAX);

  FRIDA_EMIT_CALL (mach_thread_self_impl, 0);
  FRIDA_EMIT_STORE (mach_thread, EAX);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 4);
  else
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 16);

  FRIDA_EMIT_LOAD (EDI, task);
  FRIDA_EMIT_LOAD (ESI, mach_port_allocate_right);
  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XDX, GUM_REG_XSP);
  FRIDA_EMIT_CALL (mach_port_allocate_impl, 3,
      GUM_ARG_REGISTER, GUM_REG_EDI,
      GUM_ARG_REGISTER, GUM_REG_ESI,
      GUM_ARG_REGISTER, GUM_REG_XDX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_EAX, GUM_REG_XSP, 0);
  FRIDA_EMIT_STORE (receive_port, EAX);
  FRIDA_EMIT_LOAD (XDI, message_that_never_arrives);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_REG_XDI, G_STRUCT_OFFSET (mach_msg_header_t, msgh_local_port), GUM_REG_EAX);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 12);

  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XDI, GUM_REG_XSP);
  FRIDA_EMIT_LOAD (XDX, pthread_create_start_routine);
  FRIDA_EMIT_LOAD (XCX, pthread_create_arg);
  FRIDA_EMIT_CALL (pthread_create_impl, 4,
      GUM_ARG_REGISTER, GUM_REG_XDI,
      GUM_ARG_POINTER, NULL,
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 4);
  else
    gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 16);

  gum_x86_writer_put_label (&ctx->cw, again_label);

  FRIDA_EMIT_LOAD (XAX, message_that_never_arrives);
  FRIDA_EMIT_CALL (mach_msg_receive_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XAX);

  gum_x86_writer_put_jmp_short_label (&ctx->cw, again_label);
}

static void
frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * skip_unload_label = "skip_unload";

  FRIDA_EMIT_CALL (mach_thread_self_impl, 0);
  FRIDA_EMIT_STORE (posix_thread, EAX);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 8);

  FRIDA_EMIT_LOAD (EDI, task);
  FRIDA_EMIT_LOAD (ESI, receive_port);
  FRIDA_EMIT_CALL (mach_port_destroy_impl, 2,
      GUM_ARG_REGISTER, GUM_REG_EDI,
      GUM_ARG_REGISTER, GUM_REG_ESI);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

  FRIDA_EMIT_LOAD (EDI, mach_thread);
  FRIDA_EMIT_CALL (thread_terminate_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_EDI);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 12);

  if (ctx->mapper != NULL)
  {
    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, gum_darwin_mapper_constructor (ctx->mapper));
    gum_x86_writer_put_call_reg (&ctx->cw, GUM_REG_XAX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    FRIDA_EMIT_LOAD (XDI, entrypoint_data);
    FRIDA_EMIT_LOAD_ADDRESS_OF (XSI, stay_resident);
    FRIDA_EMIT_LOAD (XDX, mapped_range);
    gum_x86_writer_put_call_reg_with_arguments (&ctx->cw,
        GUM_CALL_CAPI, GUM_REG_XAX, 3,
        GUM_ARG_REGISTER, GUM_REG_XDI,
        GUM_ARG_REGISTER, GUM_REG_XSI,
        GUM_ARG_REGISTER, GUM_REG_XDX);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

    FRIDA_EMIT_LOAD (EAX, stay_resident);
    gum_x86_writer_put_test_reg_reg (&ctx->cw, GUM_REG_EAX, GUM_REG_EAX);
    gum_x86_writer_put_jcc_short_label (&ctx->cw, GUM_X86_JNZ, skip_unload_label, GUM_NO_HINT);

    gum_x86_writer_put_mov_reg_address (&ctx->cw, GUM_REG_XAX, gum_darwin_mapper_destructor (ctx->mapper));
    gum_x86_writer_put_call_reg (&ctx->cw, GUM_REG_XAX);

    gum_x86_writer_put_label (&ctx->cw, skip_unload_label);
  }
  else
  {
    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 8);

    FRIDA_EMIT_LOAD (XDI, dylib_path);
    FRIDA_EMIT_LOAD (ESI, dlopen_mode);
    FRIDA_EMIT_CALL (dlopen_impl, 2,
        GUM_ARG_REGISTER, GUM_REG_XDI,
        GUM_ARG_REGISTER, GUM_REG_ESI);

    gum_x86_writer_put_mov_reg_offset_ptr_reg (&ctx->cw, GUM_REG_XSP, (ctx->cw.target_cpu == GUM_CPU_IA32) ? 8 : 0, GUM_REG_XAX);

    FRIDA_EMIT_LOAD (XSI, entrypoint_name);
    FRIDA_EMIT_CALL (dlsym_impl, 2,
        GUM_ARG_REGISTER, GUM_REG_XAX,
        GUM_ARG_REGISTER, GUM_REG_XSI);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

    FRIDA_EMIT_LOAD (XDI, entrypoint_data);
    FRIDA_EMIT_LOAD_ADDRESS_OF (XSI, stay_resident);
    gum_x86_writer_put_call_reg_with_arguments (&ctx->cw,
        GUM_CALL_CAPI, GUM_REG_XAX, 3,
        GUM_ARG_REGISTER, GUM_REG_XDI,
        GUM_ARG_REGISTER, GUM_REG_XSI,
        GUM_ARG_POINTER, NULL);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 8);

    FRIDA_EMIT_LOAD (EAX, stay_resident);
    gum_x86_writer_put_test_reg_reg (&ctx->cw, GUM_REG_EAX, GUM_REG_EAX);
    gum_x86_writer_put_jcc_short_label (&ctx->cw, GUM_X86_JNZ, skip_unload_label, GUM_NO_HINT);

    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_XDI, GUM_REG_XSP, (ctx->cw.target_cpu == GUM_CPU_IA32) ? 12 : 0);
    FRIDA_EMIT_CALL (dlclose_impl, 1,
        GUM_ARG_REGISTER, GUM_REG_XDI);

    gum_x86_writer_put_label (&ctx->cw, skip_unload_label);

    if (ctx->cw.target_cpu == GUM_CPU_IA32)
      gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 12);
  }

  FRIDA_EMIT_CALL (pthread_self_impl, 0);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 12);

  FRIDA_EMIT_CALL (pthread_detach_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XAX);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 12);
}

#undef FRIDA_EMIT_LOAD
#undef FRIDA_EMIT_STORE
#undef FRIDA_EMIT_MOVE
#undef FRIDA_EMIT_CALL

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

  gum_thumb_writer_free (&ctx.tw);
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

  gum_thumb_writer_free (&ctx.tw);
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

static void
frida_agent_context_emit_arm_mach_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * again_label = "again";

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

  gum_thumb_writer_put_label (&ctx->tw, again_label);

  EMIT_ARM_LOAD (R0, message_that_never_arrives);
  EMIT_ARM_LOAD (R4, mach_msg_receive_impl);
  EMIT_ARM_CALL (R4);

  gum_thumb_writer_put_b_label (&ctx->tw, again_label);
}

static void
frida_agent_context_emit_arm_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * skip_unload_label = "skip_unload";

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

  if (ctx->mapper != NULL)
  {
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM_CALL (R4);

    EMIT_ARM_LOAD (R0, entrypoint_data);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, stay_resident);
    EMIT_ARM_LOAD (R2, mapped_range);
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R4, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_ARM_CALL (R4);
  }
  else
  {
    EMIT_ARM_LOAD (R0, dylib_path);
    EMIT_ARM_LOAD (R1, dlopen_mode);
    EMIT_ARM_LOAD (R4, dlopen_impl);
    EMIT_ARM_CALL (R4);
    EMIT_ARM_MOVE (R5, R0);

    EMIT_ARM_MOVE (R0, R5);
    EMIT_ARM_LOAD (R1, entrypoint_name);
    EMIT_ARM_LOAD (R4, dlsym_impl);
    EMIT_ARM_CALL (R4);
    EMIT_ARM_MOVE (R4, R0);

    EMIT_ARM_LOAD (R0, entrypoint_data);
    EMIT_ARM_LOAD_ADDRESS_OF (R1, stay_resident);
    EMIT_ARM_LOAD_U32 (R2, 0);
    EMIT_ARM_CALL (R4);
  }

  EMIT_ARM_LOAD (R0, stay_resident);
  gum_thumb_writer_put_cbnz_reg_label (&ctx->tw, ARM_REG_R0, skip_unload_label);

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

  gum_thumb_writer_put_label (&ctx->tw, skip_unload_label);

  EMIT_ARM_LOAD (R4, pthread_self_impl);
  EMIT_ARM_CALL (R4);

  EMIT_ARM_LOAD (R4, pthread_detach_impl);
  EMIT_ARM_CALL (R4);
}

#undef EMIT_ARM_LOAD
#undef EMIT_ARM_STORE
#undef EMIT_ARM_MOVE
#undef EMIT_ARM_CALL

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

  gum_arm64_writer_free (&ctx.aw);
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
  gum_arm64_writer_free (&ctx.aw);
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
  const gchar * again_label = "again";

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

  gum_arm64_writer_put_label (&ctx->aw, again_label);

  EMIT_ARM64_LOAD (X0, message_that_never_arrives);
  EMIT_ARM64_LOAD (X8, mach_msg_receive_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_b_label (&ctx->aw, again_label);
}

static void
frida_agent_context_emit_arm64_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
  const gchar * skip_unload_label = "skip_unload";

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

  if (ctx->mapper != NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM64_CALL (X8);

    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, stay_resident);
    EMIT_ARM64_LOAD (X2, mapped_range);
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_ARM64_CALL (X8);
  }
  else
  {
    EMIT_ARM64_LOAD (X0, dylib_path);
    EMIT_ARM64_LOAD (X1, dlopen_mode);
    EMIT_ARM64_LOAD (X8, dlopen_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X19, X0);

    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X1, entrypoint_name);
    EMIT_ARM64_LOAD (X8, dlsym_impl);
    EMIT_ARM64_CALL (X8);
    EMIT_ARM64_MOVE (X8, X0);

    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_LOAD_ADDRESS_OF (X1, stay_resident);
    EMIT_ARM64_LOAD_U64 (X2, 0);
    EMIT_ARM64_CALL (X8);
  }

  EMIT_ARM64_LOAD (W0, stay_resident);
  gum_arm64_writer_put_cbnz_reg_label (&ctx->aw, ARM64_REG_W0, skip_unload_label);

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

  gum_arm64_writer_put_label (&ctx->aw, skip_unload_label);

  EMIT_ARM64_LOAD (X8, pthread_self_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD (X8, pthread_detach_impl);
  EMIT_ARM64_CALL (X8);
}

#undef EMIT_ARM64_LOAD
#undef EMIT_ARM64_STORE
#undef EMIT_ARM64_MOVE
#undef EMIT_ARM64_CALL

#endif

static kern_return_t
frida_get_debug_state (mach_port_t thread, gpointer state, GumCpuType cpu_type)
{
  mach_msg_type_number_t state_count;
  kern_return_t ret;

#ifdef HAVE_I386
  state_count = x86_DEBUG_STATE_COUNT;
  ret = thread_get_state (thread, x86_DEBUG_STATE, state, &state_count);
#else
  if (cpu_type == GUM_CPU_ARM64)
  {
    state_count = ARM_DEBUG_STATE64_COUNT;
    ret = thread_get_state (thread, ARM_DEBUG_STATE64, state, &state_count);
  }
  else
  {
    state_count = ARM_DEBUG_STATE32_COUNT;
    ret = thread_get_state (thread, ARM_DEBUG_STATE32, state, &state_count);
  }
#endif

  return ret;
}

static kern_return_t
frida_set_debug_state (mach_port_t thread, gconstpointer state, GumCpuType cpu_type)
{
  mach_msg_type_number_t state_count;
  kern_return_t ret;

#ifdef HAVE_I386
  state_count = x86_DEBUG_STATE_COUNT;
  ret = thread_set_state (thread, x86_DEBUG_STATE, (thread_state_t) state, state_count);
#else
  if (cpu_type == GUM_CPU_ARM64)
  {
    state_count = ARM_DEBUG_STATE64_COUNT;
    ret = thread_set_state (thread, ARM_DEBUG_STATE64, (thread_state_t) state, state_count);
  }
  else
  {
    state_count = ARM_DEBUG_STATE32_COUNT;
    ret = thread_set_state (thread, ARM_DEBUG_STATE32, (thread_state_t) state, state_count);
  }
#endif

  return ret;
}

static void
frida_set_hardware_breakpoint (gpointer state, GumAddress break_at, GumCpuType cpu_type)
{
#ifdef HAVE_I386
  x86_debug_state_t * s = state;

  if (cpu_type == GUM_CPU_AMD64)
  {
    x86_debug_state64_t * ds = &s->uds.ds64;

    ds->__dr0 = break_at;
    ds->__dr7 = 1;
  }
  else
  {
    x86_debug_state32_t * ds = &s->uds.ds32;

    ds->__dr0 = break_at;
    ds->__dr7 = 1;
  }
#else
# define FRIDA_S_USER ((uint32_t) (2u << 1))
# define FRIDA_BAS_ANY ((uint32_t) 15u)
# define FRIDA_BCR_ENABLE ((uint32_t) 1u)

  if (cpu_type == GUM_CPU_ARM64)
  {
    arm_debug_state64_t * s = state;

    s->__bvr[0] = break_at;
    s->__bcr[0] = (FRIDA_BAS_ANY << 5) | FRIDA_S_USER | FRIDA_BCR_ENABLE;
  }
  else
  {
    arm_debug_state32_t * s = state;

    s->__bvr[0] = break_at;
    s->__bcr[0] = (FRIDA_BAS_ANY << 5) | FRIDA_S_USER | FRIDA_BCR_ENABLE;
  }
#endif
}

static gboolean
frida_store_base_address_if_libc (const GumModuleDetails * details, gpointer user_data)
{
  GumAddress * address = user_data;

  if (g_str_has_suffix (details->path, "libSystem.B.dylib"))
  {
    *address = details->range->base_address;
    return FALSE;
  }

  return TRUE;
}

static GumAddress
frida_find_libc_initializer (guint task, GumAddress base)
{
  GumAddress initializer = 0;
  gpointer image;
  const struct mach_header * header;
  gconstpointer command;
  gsize command_index;
  gsize slide = 0;

  image = gum_darwin_read (task, base, 4096, NULL);
  header = image;

  if (header->magic == MH_MAGIC)
    command = image + sizeof (struct mach_header);
  else
    command = image + sizeof (struct mach_header_64);

  slide = frida_get_module_slide (command, header->ncmds, base);

  for (command_index = 0;
       command_index != header->ncmds && initializer == 0;
       command_index++)
  {
    const struct load_command * lc = command;
    gconstpointer sections;
    gsize section_count, section_index;

    if (lc->cmd != LC_SEGMENT && lc->cmd != LC_SEGMENT_64)
      goto skip_command;

    if (lc->cmd == LC_SEGMENT)
    {
        const struct segment_command * sc = command;

        sections = sc + 1;
        section_count = sc->nsects;

        if (strcmp (sc->segname, "__DATA_CONST") != 0 &&
            strcmp (sc->segname, "__DATA") != 0)
          goto skip_command;
    }
    else
    {
        const struct segment_command_64 * sc = command;

        sections = sc + 1;
        section_count = sc->nsects;

        if (strcmp (sc->segname, "__DATA_CONST") != 0 &&
            strcmp (sc->segname, "__DATA") != 0)
          goto skip_command;
    }

    for (section_index = 0;
        section_index != section_count && initializer == 0;
        section_index++)
    {
      GumAddress addr;
      const char * sectname;
      gsize sectsize;

      if (lc->cmd == LC_SEGMENT)
      {
        const struct section * s = sections + (section_index * sizeof (struct section));

        sectname = s->sectname;
        addr = s->addr + (guint32) slide;
        sectsize = s->size;
      }
      else
      {
        const struct section_64 * s = sections + (section_index * sizeof (struct section_64));

        sectname = s->sectname;
        addr = s->addr + (guint64) slide;
        sectsize = s->size;
      }

      if (strcmp (sectname, "__mod_init_func") == 0)
      {
        if (lc->cmd == LC_SEGMENT)
        {
          guint32 * init_func;

          g_assert_cmpint (sectsize, ==, 4);

          init_func = (guint32 *) gum_darwin_read (task, addr, sizeof (guint32), NULL);
          initializer = *init_func;
          g_free (init_func);
        }
        else
        {
          guint64 * init_func;

          g_assert_cmpint (sectsize, ==, 8);

          init_func = (guint64 *) gum_darwin_read (task, addr, sizeof (guint64), NULL);
          initializer = *init_func;
          g_free (init_func);
        }
      }
    }

skip_command:
    command += lc->cmdsize;
  }

  g_free (image);

  return initializer;
}

static GumAddress
frida_find_libc_initializer_end (guint task, GumCpuType cpu_type, GumAddress start, gsize max_size)
{
  GumAddress found = 0;
  uint64_t address = start & ~1;
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

static GumAddress
frida_get_module_slide (gconstpointer command, gsize ncmds, GumAddress base)
{
  gsize slide = 0;
  gsize command_index;

  for (command_index = 0; command_index != ncmds && slide == 0; command_index++)
  {
    const struct load_command * lc = command;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      if (lc->cmd == LC_SEGMENT)
      {
        const struct segment_command * sc = command;
        if (strcmp (sc->segname, "__TEXT") == 0)
          slide = base - sc->vmaddr;
      }
      else
      {
        const struct segment_command_64 * sc = command;
        if (strcmp (sc->segname, "__TEXT") == 0)
          slide = base - sc->vmaddr;
      }
    }

    command += lc->cmdsize;
  }

  return slide;
}

static void
frida_mapper_library_blob_deallocate (FridaMappedLibraryBlob * self)
{
  mach_vm_deallocate (mach_task_self (), self->_address, self->_allocated_size);

  frida_mapped_library_blob_free (self);
}

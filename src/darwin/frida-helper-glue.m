#include "frida-helper.h"

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
  FridaHelperService * service;
  guint pid;
  GumCpuType cpu_type;
  mach_port_t task;
  mach_port_t thread;
  FridaDebugState previous_debug_state;

  mach_port_t server_port;
  dispatch_source_t server_recv_source;
  FridaExceptionPortSet previous_ports;

  __Request__exception_raise_state_identity_t pending_request;
};

struct _FridaInjectInstance
{
  FridaHelperService * service;
  guint id;

  mach_port_t task;

  mach_vm_address_t payload_address;
  mach_vm_address_t data_address;
  mach_vm_size_t payload_size;
  gboolean is_resident;
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
  mach_port_t task;
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

static FridaSpawnInstance * frida_spawn_instance_new (FridaHelperService * service);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static void frida_spawn_instance_on_server_recv (void * context);

static void frida_make_pipe (int fds[2]);

static FridaInjectInstance * frida_inject_instance_new (FridaHelperService * service, guint id);
static void frida_inject_instance_free (FridaInjectInstance * instance);
static gboolean frida_inject_instance_is_resident (FridaInjectInstance * instance);

static void frida_inject_instance_on_mach_thread_dead (void * context);
static void frida_inject_instance_join_posix_thread (FridaInjectInstance * self, mach_port_t posix_thread);
static void frida_inject_instance_on_posix_thread_dead (void * context);

static gboolean frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details, const FridaInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinMapper * mapper, GError ** error);
static gboolean frida_agent_context_init_functions (FridaAgentContext * self, const FridaAgentDetails * details, GumDarwinMapper * mapper,
    GError ** error);

static void frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper);
static void frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type, GumDarwinMapper * mapper);

static kern_return_t frida_get_debug_state (mach_port_t thread, gpointer state, GumCpuType cpu_type);
static kern_return_t frida_set_debug_state (mach_port_t thread, gconstpointer state, GumCpuType cpu_type);
static void frida_set_hardware_breakpoint (gpointer state, GumAddress break_at, GumCpuType cpu_type);

static volatile BOOL _frida_run_loop_running = NO;

void
_frida_start_run_loop (void)
{
  NSRunLoop * loop = [NSRunLoop mainRunLoop];

  _frida_run_loop_running = YES;
  while (_frida_run_loop_running && [loop runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]])
    ;
}

void
_frida_stop_run_loop (void)
{
  _frida_run_loop_running = NO;
  CFRunLoopStop ([[NSRunLoop mainRunLoop] getCFRunLoop]);
}

void
_frida_helper_service_create_context (FridaHelperService * self)
{
  FridaHelperContext * ctx;

  ctx = g_slice_new (FridaHelperContext);
  ctx->dispatch_queue = dispatch_queue_create ("re.frida.helper.queue", DISPATCH_QUEUE_SERIAL);

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
_frida_helper_service_do_spawn (FridaHelperService * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, FridaStdioPipes ** pipes, GError ** error)
{
  FridaHelperContext * ctx = self->context;
  FridaSpawnInstance * instance = NULL;
  int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
  pid_t pid = 0;
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attributes;
  sigset_t signal_mask_set;
  int spawn_errno, result;
  const gchar * failed_operation;
  kern_return_t ret;
  mach_port_t self_task, child_task, child_thread;
  guint page_size;
  thread_act_array_t threads;
  guint thread_index;
  mach_msg_type_number_t thread_count = 0;
  GumDarwinUnifiedThreadState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  GumAddress dyld_start, dyld_granularity, dyld_chunk, dyld_header;
  GumDarwinModule * dyld;
  GumAddress dyld_init_address;
  FridaDebugState breakpoint_debug_state;
  FridaExceptionPortSet * previous_ports;
  dispatch_source_t source;

  *pipes = NULL;

  if (!g_file_test (path, G_FILE_TEST_EXISTS))
    goto handle_path_error;

  /*
   * We POSIX_SPAWN_START_SUSPENDED which means that the kernel will create
   * the task and its main thread, with the main thread's instruction pointer
   * pointed at __dyld_start. At this point neither dyld nor libc have been
   * initialized, so we won't be able to inject frida-agent at this point.
   *
   * So here's what we'll do before we consider spawn() done:
   * - Get hold of the main thread to read its instruction pointer, which will
   *   tell us where dyld is in memory.
   * - Walk backwards to find dyld's Mach-O header.
   * - Walk its symbols and find a function that's called at a point where the
   *   process is sufficiently initialized to load frida-agent. For now this is
   *   the point right before the entrypoint is called, but eventually we should
   *   be able to move this earlier so the app's constructor functions don't get
   *   a chance to run.
   * - Set a hardware breakpoint on this function.
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

  if (!gum_darwin_cpu_type_from_pid (instance->pid, &instance->cpu_type))
    goto handle_cpu_type_error;

  self_task = mach_task_self ();

  ret = task_for_pid (self_task, pid, &child_task);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_for_pid");
  instance->task = child_task;

  if (!gum_darwin_query_page_size (instance->task, &page_size))
    goto handle_page_size_error;

  ret = task_threads (child_task, &threads, &thread_count);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_threads");

  child_thread = threads[0];
  instance->thread = child_thread;

  for (thread_index = 1; thread_index < thread_count; thread_index++)
    mach_port_deallocate (self_task, threads[thread_index]);
  vm_deallocate (self_task, (vm_address_t) threads, thread_count * sizeof (thread_t));
  threads = NULL;

  ret = thread_get_state (child_thread, state_flavor, (thread_state_t) &state, &state_count);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "thread_get_state");

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

    magic = (guint32 *) gum_darwin_read (child_task, dyld_chunk, sizeof (magic), NULL);
    if (magic == NULL)
      goto handle_probe_dyld_error;

    if (*magic == MH_MAGIC || *magic == MH_MAGIC_64)
      dyld_header = dyld_chunk;

    g_free (magic);
  }

  dyld = gum_darwin_module_new_from_memory ("/usr/lib/dyld", child_task, instance->cpu_type, dyld_header);

  /*
   * Ideally we'd only run until __ZN4dyld24initializeMainExecutableEv, but for
   * now we require libc to be initialized.
   */
  dyld_init_address = gum_darwin_module_resolve_symbol_address (dyld, "__ZNK16ImageLoaderMachO11getThreadPCEv");

  gum_darwin_module_unref (dyld);

  if (dyld_init_address == 0)
    goto handle_probe_dyld_error;

  ret = frida_get_debug_state (child_thread, &instance->previous_debug_state, instance->cpu_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "frida_get_debug_state");

  memcpy (&breakpoint_debug_state, &instance->previous_debug_state, sizeof (breakpoint_debug_state));
  frida_set_hardware_breakpoint (&breakpoint_debug_state, dyld_init_address, instance->cpu_type);

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

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instance_by_pid), GUINT_TO_POINTER (pid), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV, instance->server_port, 0, ctx->dispatch_queue);
  instance->server_recv_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_spawn_instance_on_server_recv);
  dispatch_resume (source);

  ret = task_resume (child_task);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_resume");

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
handle_page_size_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing page size of child process '%s'",
        path);
    goto error_epilogue;
  }
handle_probe_dyld_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing dyld of child process '%s'",
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

static void frida_kill_application (NSString * identifier);

void
_frida_helper_service_do_launch (FridaHelperService * self, const gchar * identifier, const gchar * url, GError ** error)
{
  NSAutoreleasePool * pool;
  FridaSpringboardApi * api;
  NSDictionary * params, * options;
  UInt32 res;

  pool = [[NSAutoreleasePool alloc] init];

  api = _frida_get_springboard_api ();

  params = [NSDictionary dictionary];

  options = [NSDictionary dictionaryWithObject:@YES forKey:api->SBSApplicationLaunchOptionUnlockDeviceKey];

  if (url != NULL)
  {
    res = api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions (
        [NSString stringWithUTF8String:identifier],
        [NSURL URLWithString:[NSString stringWithUTF8String:url]],
        params,
        options,
        NO);
  }
  else
  {
    res = api->SBSLaunchApplicationWithIdentifierAndLaunchOptions (
        [NSString stringWithUTF8String:identifier],
        options,
        NO);
  }

  if (res != 0)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to launch iOS app: %s",
        [api->SBSApplicationLaunchingErrorString (res) UTF8String]);
  }

  [pool release];
}

void
_frida_helper_service_do_kill_process (FridaHelperService * self, guint pid)
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
_frida_helper_service_do_kill_application (FridaHelperService * self, const gchar * identifier)
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
_frida_helper_service_do_launch (FridaHelperService * self, const gchar * identifier, const gchar * url, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not yet able to launch apps on Mac");
}

void
_frida_helper_service_do_kill_process (FridaHelperService * self, guint pid)
{
  kill (pid, SIGKILL);
}

void
_frida_helper_service_do_kill_application (FridaHelperService * self, const gchar * identifier)
{
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
_frida_helper_service_do_inject (FridaHelperService * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, GError ** error)
{
  guint result = 0;
  FridaHelperContext * ctx = self->context;
  mach_port_t self_task;
  FridaInjectInstance * instance;
  FridaAgentDetails details = { 0, };
  const gchar * failed_operation;
  kern_return_t ret;
  GumDarwinMapper * mapper = NULL;
  guint page_size;
  FridaInjectPayloadLayout layout;
  guint base_payload_size;
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

  self_task = mach_task_self ();

  instance = frida_inject_instance_new (self, self->last_id++);

  details.pid = pid;
  details.dylib_path = path;
  details.entrypoint_name = entrypoint;
  details.entrypoint_data = data;

  if (!gum_darwin_cpu_type_from_pid (pid, &details.cpu_type))
    goto handle_cpu_type_error;

  ret = task_for_pid (self_task, pid, &details.task);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_for_pid");
  instance->task = details.task;

#ifdef HAVE_MAPPER
  mapper = gum_darwin_mapper_new (path, details.task, details.cpu_type);
#endif

  if (!gum_darwin_query_page_size (instance->task, &page_size))
    goto handle_page_size_error;
  layout.stack_guard_size = page_size;
  layout.stack_size = 32 * 1024;

  layout.code_offset = 0;
  layout.mach_code_offset = 0;
  layout.pthread_code_offset = 512;
  layout.data_offset = page_size;
  layout.stack_guard_offset = layout.data_offset + page_size;
  layout.stack_bottom_offset = layout.stack_guard_offset + layout.stack_guard_size;
  layout.stack_top_offset = layout.stack_bottom_offset + layout.stack_size;

  base_payload_size = layout.stack_top_offset;

  instance->payload_size = base_payload_size;
  if (mapper != NULL)
    instance->payload_size += gum_darwin_mapper_size (mapper);

  ret = mach_vm_allocate (details.task, &payload_address, instance->payload_size, TRUE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_allocate");
  instance->payload_address = payload_address;
  instance->data_address = payload_address + layout.data_offset;

  if (mapper != NULL)
  {
    gum_darwin_mapper_map (mapper, payload_address + base_payload_size);

    instance->is_mapped = TRUE;
  }

  ret = mach_vm_protect (details.task, payload_address + layout.stack_guard_offset, layout.stack_guard_size, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_protect");

  if (!frida_agent_context_init (&agent_ctx, &details, &layout, payload_address, instance->payload_size, mapper, error))
    goto error_epilogue;

  frida_agent_context_emit_mach_stub_code (&agent_ctx, mach_stub_code, details.cpu_type, mapper);

  frida_agent_context_emit_pthread_stub_code (&agent_ctx, pthread_stub_code, details.cpu_type, mapper);

  if (gum_query_is_rwx_supported ())
  {
    ret = mach_vm_write (details.task, payload_address + layout.mach_code_offset,
        (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_write (mach_stub_code)");

    ret = mach_vm_write (details.task, payload_address + layout.pthread_code_offset,
        (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_write(pthread_stub_code)");

    ret = mach_vm_protect (details.task, payload_address + layout.code_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_protect");
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;
    mach_vm_address_t code_address;
    vm_prot_t cur_protection, max_protection;

    segment = gum_code_segment_new (page_size, NULL);

    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page + layout.mach_code_offset, mach_stub_code, sizeof (mach_stub_code));
    memcpy (scratch_page + layout.pthread_code_offset, pthread_stub_code, sizeof (pthread_stub_code));

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, page_size, scratch_page);

    code_address = payload_address + layout.code_offset;
    ret = mach_vm_remap (details.task, &code_address, page_size, 0, VM_FLAGS_OVERWRITE, self_task, (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);

    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_remap");
  }

  ret = mach_vm_write (details.task, payload_address + layout.data_offset, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_vm_write(data)");

  ret = mach_vm_protect (details.task, payload_address + layout.data_offset, page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
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

  ret = thread_create_running (details.task, state_flavor, state_data, state_count, &instance->thread);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "thread_create_running");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, instance->thread, DISPATCH_MACH_SEND_DEAD,
      ctx->dispatch_queue);
  instance->thread_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, frida_inject_instance_on_mach_thread_dead);
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
handle_page_size_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while probing page size of process with pid %u",
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
      gum_darwin_mapper_free (mapper);

    return result;
  }
}

static void
frida_inject_instance_on_mach_thread_dead (void * context)
{
  FridaInjectInstance * self = context;
  mach_port_t * posix_thread;
  gpointer posix_thread_value = NULL;

  posix_thread = (mach_port_t *) gum_darwin_read (self->task, self->data_address + G_STRUCT_OFFSET (FridaAgentContext, posix_thread),
      sizeof (mach_port_t), NULL);
  if (posix_thread != NULL)
  {
    mach_port_t posix_thread_in_this_task;
    mach_msg_type_name_t acquired_type;
    kern_return_t kr;

    if (*posix_thread != MACH_PORT_NULL)
    {
      kr = mach_port_extract_right (self->task, *posix_thread, MACH_MSG_TYPE_MOVE_SEND, &posix_thread_in_this_task, &acquired_type);
      if (kr == KERN_SUCCESS)
        posix_thread_value = GSIZE_TO_POINTER (posix_thread_in_this_task);
    }

    g_free (posix_thread);
  }

  _frida_helper_service_on_mach_thread_dead (self->service, self->id, posix_thread_value);
}

void
_frida_helper_service_join_inject_instance_posix_thread (FridaHelperService * self, void * instance, void * posix_thread)
{
  frida_inject_instance_join_posix_thread (instance, GPOINTER_TO_SIZE (posix_thread));
}

static void
frida_inject_instance_join_posix_thread (FridaInjectInstance * self, mach_port_t posix_thread)
{
  FridaHelperContext * ctx = self->service->context;
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
  gboolean * stay_resident;

  stay_resident = (gboolean *) gum_darwin_read (self->task, self->data_address + G_STRUCT_OFFSET (FridaAgentContext, stay_resident),
      sizeof (gboolean), NULL);
  if (stay_resident != NULL)
  {
    self->is_resident = *stay_resident;
    g_free (stay_resident);
  }

  _frida_helper_service_on_posix_thread_dead (self->service, self->id);
}

gboolean
_frida_helper_service_is_instance_resident (FridaHelperService * self, void * instance)
{
  return frida_inject_instance_is_resident (instance);
}

void
_frida_helper_service_free_inject_instance (FridaHelperService * self, void * instance)
{
  frida_inject_instance_free (instance);
}

void
_frida_helper_service_do_make_pipe_endpoints (guint local_pid, guint remote_pid, gboolean * need_proxy, FridaPipeEndpoints * result, GError ** error)
{
  gboolean remote_pid_exists;
  mach_port_t self_task;
  mach_port_t local_task = MACH_PORT_NULL;
  mach_port_t remote_task = MACH_PORT_NULL;
  mach_port_t local_rx = MACH_PORT_NULL;
  mach_port_t local_tx = MACH_PORT_NULL;
  mach_port_t remote_rx = MACH_PORT_NULL;
  mach_port_t remote_tx = MACH_PORT_NULL;
  mach_port_t tx = MACH_PORT_NULL;
  kern_return_t ret;
  const gchar * failed_operation;
  mach_msg_type_name_t acquired_type;
  guint offset;
  gchar * local_address, * remote_address;

  remote_pid_exists = kill (remote_pid, 0) == 0 || errno == EPERM;
  if (!remote_pid_exists)
    goto handle_pid_error;

  self_task = mach_task_self ();

  ret = task_for_pid (self_task, local_pid, &local_task);
  if (ret == 0)
  {
    *need_proxy = FALSE;
  }
  else
  {
    *need_proxy = TRUE;
    local_task = self_task;
  }

  ret = task_for_pid (self_task, remote_pid, &remote_task);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "task_for_pid() for remote pid");

  ret = mach_port_allocate (local_task, MACH_PORT_RIGHT_RECEIVE, &local_rx);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_allocate local_rx");

  ret = mach_port_allocate (remote_task, MACH_PORT_RIGHT_RECEIVE, &remote_rx);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_allocate remote_rx");

  ret = mach_port_extract_right (remote_task, remote_rx, MACH_MSG_TYPE_MAKE_SEND, &tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_extract_right local_tx");
  if (local_task != self_task)
  {
    offset = 1;
    do
    {
      local_tx = MACH_PORT_MAKE (MACH_PORT_INDEX (local_rx) + offset, MACH_PORT_GEN (local_rx));
      ret = mach_port_insert_right (local_task, local_tx, tx, MACH_MSG_TYPE_COPY_SEND);
      offset++;
    }
    while (ret == KERN_NAME_EXISTS || ret == KERN_FAILURE);
    if (ret != KERN_SUCCESS)
      local_tx = MACH_PORT_NULL;
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_insert_right local_tx");
    mach_port_deallocate (self_task, tx);
  }
  else
  {
    local_tx = tx;
  }
  tx = MACH_PORT_NULL;

  ret = mach_port_extract_right (local_task, local_rx, MACH_MSG_TYPE_MAKE_SEND, &tx, &acquired_type);
  CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_extract_right remote_tx");
  if (remote_task != self_task)
  {
    offset = 1;
    do
    {
      remote_tx = MACH_PORT_MAKE (MACH_PORT_INDEX (remote_rx) + offset, MACH_PORT_GEN (remote_rx));
      ret = mach_port_insert_right (remote_task, remote_tx, tx, MACH_MSG_TYPE_COPY_SEND);
      offset++;
    }
    while (ret == KERN_NAME_EXISTS || ret == KERN_FAILURE);
    if (ret != KERN_SUCCESS)
      remote_tx = MACH_PORT_NULL;
    CHECK_MACH_RESULT (ret, ==, KERN_SUCCESS, "mach_port_insert_right remote_tx");
    mach_port_deallocate (self_task, tx);
  }
  else
  {
    remote_tx = tx;
  }
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
      mach_port_deallocate (self_task, tx);
    if (remote_tx != MACH_PORT_NULL)
      mach_port_deallocate (remote_task, remote_tx);
    if (local_tx != MACH_PORT_NULL)
      mach_port_deallocate (local_task, local_tx);
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
    if (local_task != MACH_PORT_NULL && local_task != self_task)
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
  instance->thread = MACH_PORT_NULL;

  instance->server_port = MACH_PORT_NULL;
  instance->server_recv_source = NULL;

  instance->pending_request.thread.name = MACH_PORT_NULL;
  instance->pending_request.task.name = MACH_PORT_NULL;

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
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->service);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  __Request__exception_raise_state_identity_t * request = &self->pending_request;
  __Reply__exception_raise_t response;
  mach_msg_header_t * header;
  kern_return_t ret;

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

  _frida_helper_service_on_spawn_instance_ready (self->service, self->pid);
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
frida_inject_instance_new (FridaHelperService * service, guint id)
{
  FridaInjectInstance * instance;

  instance = g_slice_new (FridaInjectInstance);
  instance->service = g_object_ref (service);
  instance->id = id;

  instance->task = MACH_PORT_NULL;

  instance->payload_address = 0;
  instance->data_address = 0;
  instance->payload_size = 0;
  instance->is_resident = FALSE;
  instance->is_mapped = FALSE;

  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  return instance;
}

static void
frida_inject_instance_free (FridaInjectInstance * instance)
{
  task_t self_task;
  gboolean can_deallocate_payload;

  self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);

  can_deallocate_payload = !(instance->is_resident && instance->is_mapped);
  if (instance->payload_address != 0 && can_deallocate_payload)
    mach_vm_deallocate (instance->task, instance->payload_address, instance->payload_size);

  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);

  g_object_unref (instance->service);

  g_slice_free (FridaInjectInstance, instance);
}

static gboolean
frida_inject_instance_is_resident (FridaInjectInstance * instance)
{
  return instance->is_resident;
}

static gboolean
frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details, const FridaInjectPayloadLayout * layout,
    mach_vm_address_t payload_base, mach_vm_size_t payload_size, GumDarwinMapper * mapper, GError ** error)
{
  bzero (self, sizeof (FridaAgentContext));

  if (!frida_agent_context_init_functions (self, details, mapper, error))
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
  self->field##_impl = gum_darwin_module_resolver_find_export_address (&resolver, module, G_STRINGIFY (field))

static gboolean
frida_agent_context_init_functions (FridaAgentContext * self, const FridaAgentDetails * details, GumDarwinMapper * mapper, GError ** error)
{
  GumDarwinModuleResolver resolver;
  GumDarwinModule * module;

  gum_darwin_module_resolver_open (&resolver, details->task);

  module = gum_darwin_module_resolver_find_module (&resolver, "/usr/lib/system/libsystem_kernel.dylib");
  if (module == NULL)
    goto handle_libc_error;
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_task_self);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_thread_self);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_port_allocate);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_msg_receive);
  FRIDA_AGENT_CONTEXT_RESOLVE (mach_port_destroy);
  FRIDA_AGENT_CONTEXT_RESOLVE (thread_terminate);

  module = gum_darwin_module_resolver_find_module (&resolver, "/usr/lib/system/libsystem_pthread.dylib");
  if (module == NULL)
    module = gum_darwin_module_resolver_find_module (&resolver, "/usr/lib/system/introspection/libsystem_pthread.dylib");
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
    module = gum_darwin_module_resolver_find_module (&resolver, "/usr/lib/system/libdyld.dylib");
    if (module == NULL)
      goto handle_libc_error;
    FRIDA_AGENT_CONTEXT_RESOLVE (dlopen);
    FRIDA_AGENT_CONTEXT_RESOLVE (dlsym);
    FRIDA_AGENT_CONTEXT_RESOLVE (dlclose);
  }

  gum_darwin_module_resolver_close (&resolver);

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
    gum_darwin_module_resolver_close (&resolver);

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
#define EMIT_ARM_STORE(field, reg) \
    frida_agent_context_emit_arm_store_reg_in_ctx_value (G_STRUCT_OFFSET (FridaAgentContext, field), ARM_REG_##reg, &ctx->tw)
#define EMIT_ARM_LOAD_U32(reg, val) \
    gum_thumb_writer_put_ldr_reg_u32 (&ctx->tw, ARM_REG_##reg, val)
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
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R0, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM_CALL (R0);

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
    gum_thumb_writer_put_ldr_reg_address (&ctx->tw, ARM_REG_R0, gum_darwin_mapper_destructor (ctx->mapper));
    EMIT_ARM_CALL (R0);
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
#if 0
  EMIT_ARM64_LOAD (X3, pthread_create_arg);
  EMIT_ARM64_LOAD (X2, pthread_create_start_routine);
  EMIT_ARM64_LOAD_U64 (X1, 0);
  gum_arm64_writer_put_push_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_MOVE (X0, SP);
  EMIT_ARM64_LOAD (X8, pthread_create_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_LOAD_U64 (X1, 0);
  gum_arm64_writer_put_pop_reg_reg (&ctx->aw, ARM64_REG_X0, ARM64_REG_X1);
  EMIT_ARM64_LOAD (X8, pthread_join_impl);
  EMIT_ARM64_CALL (X8);

  EMIT_ARM64_MOVE (X0, X21);
  EMIT_ARM64_LOAD (X8, thread_terminate_impl);
  EMIT_ARM64_CALL (X8);
#endif
}

static void
frida_agent_context_emit_arm64_pthread_stub_body (FridaAgentContext * self, FridaAgentEmitContext * ctx)
{
#if 0
  if (ctx->mapper != NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X0, gum_darwin_mapper_constructor (ctx->mapper));
    EMIT_ARM64_CALL (X0);

    EMIT_ARM64_LOAD (X2, thread_id);
    EMIT_ARM64_LOAD (X1, mapped_range);
    EMIT_ARM64_LOAD (X0, entrypoint_data);
    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X8, gum_darwin_mapper_resolve (ctx->mapper, self->entrypoint_name_storage));
    EMIT_ARM64_CALL (X8);

    gum_arm64_writer_put_ldr_reg_address (&ctx->aw, ARM64_REG_X0, gum_darwin_mapper_destructor (ctx->mapper));
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
    EMIT_ARM64_LOAD (X0, entrypoint_data);
    EMIT_ARM64_CALL (X8);

    EMIT_ARM64_MOVE (X0, X19);
    EMIT_ARM64_LOAD (X8, dlclose_impl);
    EMIT_ARM64_CALL (X8);
  }
#endif
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

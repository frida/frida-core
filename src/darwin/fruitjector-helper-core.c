#include "fruitjector-helper.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#ifdef HAVE_ARM
# include <gum/arch-arm/gumthumbwriter.h>
#else
# include <gum/arch-x86/gumx86writer.h>
#endif
#include <gum/gum.h>
#include <gum/gumdarwin.h>
#include <mach/mach.h>

#define FRIDA_AGENT_ENTRYPOINT_NAME "frida_agent_main"

#define FRIDA_SYSTEM_LIBC         "/usr/lib/libSystem.B.dylib"

#define FRIDA_PAGE_SIZE           (4096)
#define FRIDA_STACK_GUARD_SIZE    FRIDA_PAGE_SIZE
#define FRIDA_STACK_SIZE          (32 * 1024)
#define FRIDA_PTHREAD_DATA_SIZE   (2 * FRIDA_PAGE_SIZE)
#define FRIDA_CODE_OFFSET         (0)
#define FRIDA_MACH_CODE_OFFSET    (0)
#define FRIDA_PTHREAD_CODE_OFFSET (512)
#define FRIDA_DATA_OFFSET         (1024)
#define FRIDA_STACK_GUARD_OFFSET  FRIDA_PAGE_SIZE
#define FRIDA_STACK_BOTTOM_OFFSET (FRIDA_STACK_GUARD_OFFSET + FRIDA_STACK_GUARD_SIZE)
#define FRIDA_STACK_TOP_OFFSET    (FRIDA_STACK_BOTTOM_OFFSET + FRIDA_STACK_SIZE)
#define FRIDA_THREAD_SELF_OFFSET  (FRIDA_STACK_TOP_OFFSET)

#define FRIDA_PAYLOAD_SIZE        (FRIDA_THREAD_SELF_OFFSET + FRIDA_PTHREAD_DATA_SIZE)

#define FRIDA_PSR_THUMB           (0x20)

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _FridaFruitContext FridaFruitContext;
typedef struct _FridaInjectionInstance FridaInjectionInstance;
typedef struct _FridaAgentDetails FridaAgentDetails;
typedef struct _FridaAgentContext FridaAgentContext;

struct _FridaFruitContext
{
  dispatch_queue_t dispatch_queue;
};

struct _FridaInjectionInstance
{
  FruitjectorService * service;
  guint id;
  mach_port_t task;
  vm_address_t payload_address;
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

  GumAddress dlclose_impl;

  GumAddress dylib_path;

  gchar entrypoint_name_data[32];
  gchar data_string_data[256];
  gchar dylib_path_data[256];
};

typedef struct _FridaEmitContext FridaEmitContext;
typedef struct _FridaFillContext FridaFillContext;

struct _FridaEmitContext
{
  guint8 * code;
#ifdef HAVE_ARM
  GumThumbWriter tw;
#else
  GumX86Writer cw;
#endif
};

struct _FridaFillContext
{
  FridaAgentContext * agent;
  guint remaining;
};

static gboolean frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details,
    vm_address_t remote_payload_base, GError ** error);
static gboolean frida_agent_context_init_functions (FridaAgentContext * self, const FridaAgentDetails * details,
    GError ** error);
static gboolean frida_agent_context_init_functions_the_easy_way (FridaAgentContext * self,
    const FridaAgentDetails * details, GError ** error);
static gboolean frida_agent_context_init_functions_the_hard_way (FridaAgentContext * self,
    const FridaAgentDetails * details, GError ** error);
static gboolean frida_fill_function_if_matching (const gchar * name, GumAddress address, gpointer user_data);

static void frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type);
static void frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type);

static void frida_agent_context_emit_pthread_setup (FridaAgentContext * self, FridaEmitContext * ctx);
static void frida_agent_context_emit_pthread_create_and_join (FridaAgentContext * self, FridaEmitContext * ctx);
static void frida_agent_context_emit_thread_terminate (FridaAgentContext * self, FridaEmitContext * ctx);

static void frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaEmitContext * ctx);

void
_fruitjector_service_create_context (FruitjectorService * self)
{
  FridaFruitContext * ctx;

  ctx = g_slice_new (FridaFruitContext);
  ctx->dispatch_queue = dispatch_queue_create (
      "org.boblycat.frida.fruitjector.queue", NULL);

  self->context = ctx;
}

void
_fruitjector_service_destroy_context (FruitjectorService * self)
{
  FridaFruitContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_slice_free (FridaFruitContext, ctx);
}

static FridaInjectionInstance *
frida_injection_instance_new (FruitjectorService * service, guint id)
{
  FridaInjectionInstance * instance;

  instance = g_slice_new (FridaInjectionInstance);
  instance->service = g_object_ref (service);
  instance->id = id;
  instance->task = MACH_PORT_NULL;
  instance->payload_address = 0;
  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  return instance;
}

static void
frida_injection_instance_free (FridaInjectionInstance * instance)
{
  task_t self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);
  if (instance->payload_address != 0)
    vm_deallocate (instance->task, instance->payload_address, FRIDA_PAYLOAD_SIZE);
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->service);
  g_slice_free (FridaInjectionInstance, instance);
}

static void
frida_injection_instance_handle_event (void * context)
{
  FridaInjectionInstance * instance = context;

  _fruitjector_service_on_instance_dead (instance->service, instance->id);
}

void
_fruitjector_service_free_instance (FruitjectorService * self, void * instance)
{
  frida_injection_instance_free (instance);
}

guint
_fruitjector_service_do_inject (FruitjectorService * self, guint pid, const gchar * dylib_path, const char * data_string, GError ** error)
{
  FridaFruitContext * ctx = self->context;
  FridaInjectionInstance * instance;
  FridaAgentDetails details = { 0, };
  const gchar * failed_operation;
  kern_return_t ret;
  vm_address_t payload_address = (vm_address_t) NULL;
  guint8 mach_stub_code[512] = { 0, };
  guint8 pthread_stub_code[512] = { 0, };
  FridaAgentContext agent_ctx;
#ifdef HAVE_ARM
  arm_thread_state_t state;
  mach_msg_type_number_t state_count = ARM_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = ARM_THREAD_STATE;
#else
  x86_thread_state_t state;
  mach_msg_type_number_t state_count = x86_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = x86_THREAD_STATE;
#endif
  dispatch_source_t source;

  instance = frida_injection_instance_new (self, self->last_id++);

  details.pid = pid;
  details.dylib_path = dylib_path;
  details.data_string = data_string;

  if (!gum_darwin_cpu_type_from_pid (pid, &details.cpu_type))
    goto handle_cpu_type_error;

  ret = task_for_pid (mach_task_self (), pid, &details.task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");
  instance->task = details.task;

  ret = vm_allocate (details.task, &payload_address, FRIDA_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");
  instance->payload_address = payload_address;

  ret = vm_protect (details.task, payload_address + FRIDA_STACK_GUARD_OFFSET, FRIDA_STACK_GUARD_SIZE, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  if (!frida_agent_context_init (&agent_ctx, &details, payload_address, error))
    goto error_epilogue;

  frida_agent_context_emit_mach_stub_code (&agent_ctx, mach_stub_code, details.cpu_type);
  ret = vm_write (details.task, payload_address + FRIDA_MACH_CODE_OFFSET,
      (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(mach_stub_code)");

  frida_agent_context_emit_pthread_stub_code (&agent_ctx, pthread_stub_code, details.cpu_type);
  ret = vm_write (details.task, payload_address + FRIDA_PTHREAD_CODE_OFFSET,
      (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(pthread_stub_code)");

  ret = vm_write (details.task, payload_address + FRIDA_DATA_OFFSET, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(data)");

  ret = vm_protect (details.task, payload_address + FRIDA_CODE_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  bzero (&state, sizeof (state));
#if defined(HAVE_ARM)
  state.__r[7] = payload_address + FRIDA_DATA_OFFSET;

  state.__sp = payload_address + FRIDA_STACK_TOP_OFFSET;
  state.__lr = 0xcafebabe;
  state.__pc = payload_address + FRIDA_MACH_CODE_OFFSET;
  state.__cpsr = FRIDA_PSR_THUMB;
#else
  if (details.cpu_type == GUM_CPU_AMD64)
  {
    x86_thread_state64_t * ts;

    state.tsh.flavor = x86_THREAD_STATE64;
    state.tsh.count = x86_THREAD_STATE64_COUNT;

    ts = &state.uts.ts64;

    ts->__rbp = payload_address + FRIDA_DATA_OFFSET;

    ts->__rsp = payload_address + FRIDA_STACK_TOP_OFFSET;
    ts->__rip = payload_address + FRIDA_MACH_CODE_OFFSET;
  }
  else
  {
    x86_thread_state32_t * ts;

    state.tsh.flavor = x86_THREAD_STATE32;
    state.tsh.count = x86_THREAD_STATE32_COUNT;

    ts = &state.uts.ts32;

    ts->__ebp = payload_address + FRIDA_DATA_OFFSET;

    ts->__esp = payload_address + FRIDA_STACK_TOP_OFFSET;
    ts->__eip = payload_address + FRIDA_MACH_CODE_OFFSET;
  }
#endif

  ret = thread_create_running (details.task, state_flavor, (thread_state_t) &state, state_count, &instance->thread);
  CHECK_MACH_RESULT (ret, ==, 0, "thread_create_running");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, instance->thread, DISPATCH_MACH_SEND_DEAD,
      ctx->dispatch_queue);
  instance->thread_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source,
      frida_injection_instance_handle_event);
  dispatch_resume (source);

  return instance->id;

handle_cpu_type_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to probe cpu type");
    goto error_epilogue;
  }

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed while trying to inject: %s (%d)", failed_operation, mach_error_string (ret), ret);
    goto error_epilogue;
  }

error_epilogue:
  {
    frida_injection_instance_free (instance);
    return 0;
  }
}

void
_fruitjector_service_do_make_pipe_endpoints (guint local_pid, guint remote_pid, FridaFruitjectorPipeEndpoints * result, GError ** error)
{
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
  local_tx = tx - 1;
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
  remote_tx = tx - 1;
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
  frida_fruitjector_pipe_endpoints_init (result, local_address, remote_address);
  g_free (remote_address);
  g_free (local_address);

  goto beach;

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed while trying to make pipe endpoints: %s (%d)", failed_operation, mach_error_string (ret), ret);

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

static gboolean
frida_agent_context_init (FridaAgentContext * self, const FridaAgentDetails * details,
    vm_address_t remote_payload_base, GError ** error)
{
  if (!frida_agent_context_init_functions (self, details, error))
    return FALSE;

  self->thread_self_data = remote_payload_base + FRIDA_THREAD_SELF_OFFSET;

#ifdef HAVE_ARM
  self->pthread_create_start_routine = remote_payload_base + FRIDA_PTHREAD_CODE_OFFSET + 1;
#else
  self->pthread_create_start_routine = remote_payload_base + FRIDA_PTHREAD_CODE_OFFSET;
#endif
  self->pthread_create_arg = remote_payload_base + FRIDA_DATA_OFFSET;

  self->dylib_path = remote_payload_base + FRIDA_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, dylib_path_data);
  strcpy (self->dylib_path_data, details->dylib_path);
  self->dlopen_mode = RTLD_LAZY;

  self->entrypoint_name = remote_payload_base + FRIDA_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, entrypoint_name_data);
  strcpy (self->entrypoint_name_data, FRIDA_AGENT_ENTRYPOINT_NAME);
  self->data_string = remote_payload_base + FRIDA_DATA_OFFSET +
      G_STRUCT_OFFSET (FridaAgentContext, data_string_data);
  g_assert_cmpint (strlen (details->data_string), <, sizeof (self->data_string_data));
  strcpy (self->data_string_data, details->data_string);

  return TRUE;
}

static gboolean
frida_agent_context_init_functions (FridaAgentContext * self, const FridaAgentDetails * details, GError ** error)
{
  GumCpuType own_cpu_type;
  if (!gum_darwin_cpu_type_from_pid (getpid (), &own_cpu_type))
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to probe cpu type");
    return FALSE;
  }

  if (details->cpu_type == own_cpu_type)
    return frida_agent_context_init_functions_the_easy_way (self, details, error);
  else
    return frida_agent_context_init_functions_the_hard_way (self, details, error);
}

#define FRIDA_CTX_ASSIGN_FUNCTION(field) \
  self->field##_impl = GUM_ADDRESS (dlsym (syslib_handle, G_STRINGIFY (field))); \
  CHECK_DL_RESULT (self->field##_impl, !=, 0, "dlsym(\"" G_STRINGIFY (field) "\")")
#define FRIDA_CTX_TRY_ASSIGN_FUNCTION(field) \
  self->field##_impl = GUM_ADDRESS (dlsym (syslib_handle, G_STRINGIFY (field)))
#define CHECK_DL_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_dl_error; \
  }

static gboolean
frida_agent_context_init_functions_the_easy_way (FridaAgentContext * self, const FridaAgentDetails * details, GError ** error)
{
  gboolean result = FALSE;
  void * syslib_handle;
  const gchar * failed_operation;

  syslib_handle = dlopen (FRIDA_SYSTEM_LIBC, RTLD_LAZY | RTLD_GLOBAL);
  CHECK_DL_RESULT (syslib_handle, !=, NULL, "dlopen");

  FRIDA_CTX_ASSIGN_FUNCTION (_pthread_set_self);
  FRIDA_CTX_TRY_ASSIGN_FUNCTION (cthread_set_self);
  FRIDA_CTX_ASSIGN_FUNCTION (pthread_create);
  FRIDA_CTX_ASSIGN_FUNCTION (pthread_join);
  FRIDA_CTX_ASSIGN_FUNCTION (thread_terminate);
  FRIDA_CTX_ASSIGN_FUNCTION (mach_thread_self);
  FRIDA_CTX_ASSIGN_FUNCTION (dlopen);
  FRIDA_CTX_ASSIGN_FUNCTION (dlsym);
  FRIDA_CTX_ASSIGN_FUNCTION (dlclose);

  result = TRUE;
  goto beach;

handle_dl_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %s", failed_operation, dlerror ());
    goto beach;
  }

beach:
  {
    if (syslib_handle != NULL)
      dlclose (syslib_handle);
    return result;
  }
}

static gboolean
frida_agent_context_init_functions_the_hard_way (FridaAgentContext * self, const FridaAgentDetails * details, GError ** error)
{
  FridaFillContext fill_ctx;
  gboolean resolved_all;
  gboolean resolved_all_except_cthread_set_self;

  fill_ctx.agent = self;
  fill_ctx.remaining = 9;
  gum_darwin_enumerate_exports (details->task, FRIDA_SYSTEM_LIBC, frida_fill_function_if_matching, &fill_ctx);

  resolved_all = fill_ctx.remaining == 0;
  resolved_all_except_cthread_set_self = fill_ctx.remaining == 1 && self->cthread_set_self_impl == 0;

  if (!resolved_all && !resolved_all_except_cthread_set_self)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "failed to resolve one or more functions");
    return FALSE;
  }

  return TRUE;
}

#define FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING(field) \
  if (strcmp (name, G_STRINGIFY (field)) == 0) \
  { \
    ctx->agent->field##_impl = address; \
    ctx->remaining--; \
    return ctx->remaining != 0; \
  }

static gboolean
frida_fill_function_if_matching (const gchar * name,
                               GumAddress address,
                               gpointer user_data)
{
  FridaFillContext * ctx = user_data;

  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (_pthread_set_self);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (cthread_set_self);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (pthread_create);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (pthread_join);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (thread_terminate);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (mach_thread_self);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (dlopen);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (dlsym);
  FRIDA_CTX_ASSIGN_AND_RETURN_IF_MATCHING (dlclose);

  return TRUE;
}

#ifdef HAVE_ARM

static void frida_agent_context_emit_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw);

static void
frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type)
{
  FridaEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);

  frida_agent_context_emit_pthread_setup (self, &ctx);
  frida_agent_context_emit_pthread_create_and_join (self, &ctx);
  frida_agent_context_emit_thread_terminate (self, &ctx);

  gum_thumb_writer_free (&ctx.tw);
}

static void
frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type)
{
  FridaEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);

  gum_thumb_writer_put_push_regs (&ctx.tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_LR);
  gum_thumb_writer_put_mov_reg_reg (&ctx.tw, GUM_AREG_R7, GUM_AREG_R0);
  frida_agent_context_emit_pthread_stub_body (self, &ctx);
  gum_thumb_writer_put_pop_regs (&ctx.tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_PC);

  gum_thumb_writer_free (&ctx.tw);
}

#define FRIDA_EMIT_LOAD(reg, field) \
    frida_agent_context_emit_load_reg_with_ctx_value (GUM_AREG_##reg, G_STRUCT_OFFSET (FridaAgentContext, field), &ctx->tw)
#define FRIDA_EMIT_LOAD_U32(reg, val) \
    gum_thumb_writer_put_ldr_reg_u32 (&ctx->tw, GUM_AREG_##reg, val)
#define FRIDA_EMIT_MOVE(dstreg, srcreg) \
    gum_thumb_writer_put_mov_reg_reg (&ctx->tw, GUM_AREG_##dstreg, GUM_AREG_##srcreg)
#define FRIDA_EMIT_CALL(reg) \
    gum_thumb_writer_put_blx_reg (&ctx->tw, GUM_AREG_##reg)

static void
frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaEmitContext * ctx)
{
  FRIDA_EMIT_LOAD (R1, dlopen_mode);
  FRIDA_EMIT_LOAD (R0, dylib_path);
  FRIDA_EMIT_LOAD (R3, dlopen_impl);
  FRIDA_EMIT_CALL (R3);
  FRIDA_EMIT_MOVE (R4, R0);

  FRIDA_EMIT_LOAD (R1, entrypoint_name);
  FRIDA_EMIT_MOVE (R0, R4);
  FRIDA_EMIT_LOAD (R3, dlsym_impl);
  FRIDA_EMIT_CALL (R3);
  FRIDA_EMIT_MOVE (R5, R0);

  FRIDA_EMIT_LOAD (R0, data_string);
  FRIDA_EMIT_CALL (R5);

  FRIDA_EMIT_MOVE (R0, R4);
  FRIDA_EMIT_LOAD (R3, dlclose_impl);
  FRIDA_EMIT_CALL (R3);
}

static void
frida_agent_context_emit_pthread_setup (FridaAgentContext * self, FridaEmitContext * ctx)
{
  FRIDA_EMIT_LOAD (R5, thread_self_data);

  FRIDA_EMIT_MOVE (R0, R5);
  FRIDA_EMIT_LOAD (R4, _pthread_set_self_impl);
  FRIDA_EMIT_CALL (R4);

  if (self->cthread_set_self_impl != 0)
  {
    FRIDA_EMIT_MOVE (R0, R5);
    FRIDA_EMIT_LOAD (R4, cthread_set_self_impl);
    FRIDA_EMIT_CALL (R4);
  }
}

static void
frida_agent_context_emit_pthread_create_and_join (FridaAgentContext * self, FridaEmitContext * ctx)
{
  FRIDA_EMIT_LOAD (R3, pthread_create_arg);
  FRIDA_EMIT_LOAD (R2, pthread_create_start_routine);
  FRIDA_EMIT_LOAD_U32 (R1, 0);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, GUM_AREG_R0);
  FRIDA_EMIT_MOVE (R0, SP);
  FRIDA_EMIT_LOAD (R4, pthread_create_impl);
  FRIDA_EMIT_CALL (R4);

  FRIDA_EMIT_LOAD_U32 (R1, 0);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, GUM_AREG_R0);
  FRIDA_EMIT_LOAD (R4, pthread_join_impl);
  FRIDA_EMIT_CALL (R4);
}

static void
frida_agent_context_emit_thread_terminate (FridaAgentContext * self, FridaEmitContext * ctx)
{
  FRIDA_EMIT_LOAD (R4, mach_thread_self_impl);
  FRIDA_EMIT_CALL (R4);
  FRIDA_EMIT_LOAD (R4, thread_terminate_impl);
  FRIDA_EMIT_CALL (R4);
}

#undef FRIDA_EMIT_LOAD
#undef FRIDA_EMIT_MOVE
#undef FRIDA_EMIT_CALL

static void
frida_agent_context_emit_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw)
{
  gum_thumb_writer_put_ldr_reg_u32 (tw, GUM_AREG_R6, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, reg, GUM_AREG_R7, GUM_AREG_R6);
  gum_thumb_writer_put_ldr_reg_reg (tw, reg, reg);
}

#else /* HAVE_ARM */

static void
frida_agent_context_emit_mach_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type)
{
  FridaEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, cpu_type);

  frida_agent_context_emit_pthread_setup (self, &ctx);
  frida_agent_context_emit_pthread_create_and_join (self, &ctx);
  frida_agent_context_emit_thread_terminate (self, &ctx);
  gum_x86_writer_put_int3 (&ctx.cw);

  gum_x86_writer_free (&ctx.cw);
}

static void
frida_agent_context_emit_pthread_stub_code (FridaAgentContext * self, guint8 * code, GumCpuType cpu_type)
{
  FridaEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);
  gum_x86_writer_set_target_cpu (&ctx.cw, cpu_type);

  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBX);

  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XAX); /* padding */

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

  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XAX); /* padding */

  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&ctx.cw);

  gum_x86_writer_free (&ctx.cw);
}

#define FRIDA_EMIT_LOAD(reg, field) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_##reg, GUM_REG_XBP, G_STRUCT_OFFSET (FridaAgentContext, field))
#define FRIDA_EMIT_MOVE(dstreg, srcreg) \
    gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_##dstreg, GUM_REG_##srcreg)
#define FRIDA_EMIT_CALL(fun, ...) \
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XBP, G_STRUCT_OFFSET (FridaAgentContext, fun), __VA_ARGS__)

static void
frida_agent_context_emit_pthread_stub_body (FridaAgentContext * self, FridaEmitContext * ctx)
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
    gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 4);

  FRIDA_EMIT_LOAD (XDX, data_string);
  gum_x86_writer_put_call_reg_with_arguments (&ctx->cw,
      GUM_CALL_CAPI, GUM_REG_XAX, 1,
      GUM_ARG_REGISTER, GUM_REG_XDX);

  FRIDA_EMIT_CALL (dlclose_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XBX);

  if (ctx->cw.target_cpu == GUM_CPU_IA32)
    gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 12);
}

static void
frida_agent_context_emit_pthread_setup (FridaAgentContext * self, FridaEmitContext * ctx)
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
frida_agent_context_emit_pthread_create_and_join (FridaAgentContext * self, FridaEmitContext * ctx)
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
frida_agent_context_emit_thread_terminate (FridaAgentContext * self, FridaEmitContext * ctx)
{
  FRIDA_EMIT_CALL (mach_thread_self_impl, 0);
  FRIDA_EMIT_CALL (thread_terminate_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XAX);
}

#undef FRIDA_EMIT_LOAD
#undef FRIDA_EMIT_MOVE
#undef FRIDA_EMIT_CALL

#endif /* !HAVE_ARM */

#include "zed-core.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#ifdef HAVE_ARM
# include <gum/arch-arm/gumthumbwriter.h>
#else
# include <gum/arch-x86/gumx86writer.h>
#endif
#include <gum/gum.h>
#include <mach/mach.h>

#define ZED_AGENT_ENTRYPOINT_NAME "zed_agent_main"

#define ZED_PAGE_SIZE           (4096)
#define ZED_STACK_GUARD_SIZE    ZED_PAGE_SIZE
#define ZED_STACK_SIZE          (32 * 1024)
#define ZED_PTHREAD_DATA_SIZE   (2 * ZED_PAGE_SIZE)
#define ZED_CODE_OFFSET         (0)
#define ZED_MACH_CODE_OFFSET    (0)
#define ZED_PTHREAD_CODE_OFFSET (512)
#define ZED_DATA_OFFSET         (1024)
#define ZED_STACK_GUARD_OFFSET  ZED_PAGE_SIZE
#define ZED_STACK_BOTTOM_OFFSET (ZED_STACK_GUARD_OFFSET + ZED_STACK_GUARD_SIZE)
#define ZED_STACK_TOP_OFFSET    (ZED_STACK_BOTTOM_OFFSET + ZED_STACK_SIZE)
#define ZED_THREAD_SELF_OFFSET  (ZED_STACK_TOP_OFFSET)

#define ZED_PAYLOAD_SIZE        (ZED_THREAD_SELF_OFFSET + ZED_PTHREAD_DATA_SIZE)

#define ZED_PSR_THUMB           (0x20)

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }
#define CHECK_DL_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_dl_error; \
  }

typedef struct _ZedFruitContext ZedFruitContext;
typedef struct _ZedInjectionInstance ZedInjectionInstance;
typedef struct _ZedAgentContext ZedAgentContext;

struct _ZedFruitContext
{
  dispatch_queue_t dispatch_queue;
};

struct _ZedInjectionInstance
{
  ZedFruitjector * fruitjector;
  guint id;
  mach_port_t task;
  vm_address_t payload_address;
  mach_port_t thread;
  dispatch_source_t thread_monitor_source;
};

struct _ZedAgentContext
{
  gpointer _pthread_set_self_impl;
  gpointer cthread_set_self_impl;
  gpointer thread_self_data;

  gpointer pthread_create_impl;
  gpointer pthread_create_start_routine;
  gpointer pthread_create_arg;

  gpointer pthread_join_impl;

  gpointer thread_terminate_impl;

  gpointer mach_thread_self_impl;

  gpointer dlopen_impl;
  int dlopen_mode;

  gpointer dlsym_impl;
  gchar * entrypoint_name;
  gchar * data_string;

  gpointer dlclose_impl;

  gchar * dylib_path;

  gchar entrypoint_name_data[32];
  gchar data_string_data[256];
  gchar dylib_path_data[256];
};

typedef struct _ZedEmitContext ZedEmitContext;

struct _ZedEmitContext
{
  guint8 * code;
#ifdef HAVE_ARM
  GumThumbWriter tw;
#else
  GumX86Writer cw;
#endif
};

static void zed_emit_mach_stub_code (guint8 * code);
static void zed_emit_pthread_stub_code (guint8 * code);

static void zed_emit_pthread_setup (ZedEmitContext * ctx);
static void zed_emit_pthread_create_and_join (ZedEmitContext * ctx);
static void zed_emit_thread_terminate (ZedEmitContext * ctx);

static void zed_emit_pthread_stub_body (ZedEmitContext * ctx);

static gboolean zed_fill_agent_context (ZedAgentContext * ctx, const char * dylib_path, const char * data_string,
    vm_address_t remote_payload_base, GError ** error);

void
_zed_fruitjector_create_context (ZedFruitjector * self)
{
  ZedFruitContext * ctx;

  ctx = g_new0 (ZedFruitContext, 1);
  ctx->dispatch_queue = dispatch_queue_create (
      "org.boblycat.frida.fruitjector.queue", NULL);

  self->context = ctx;
}

void
_zed_fruitjector_destroy_context (ZedFruitjector * self)
{
  ZedFruitContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_free (ctx);
}

static ZedInjectionInstance *
zed_injection_instance_new (ZedFruitjector * fruitjector, guint id)
{
  ZedInjectionInstance * instance;

  instance = g_new (ZedInjectionInstance, 1);
  instance->fruitjector = g_object_ref (fruitjector);
  instance->id = id;
  instance->task = MACH_PORT_NULL;
  instance->payload_address = 0;
  instance->thread = MACH_PORT_NULL;
  instance->thread_monitor_source = NULL;

  return instance;
}

static void
zed_injection_instance_free (ZedInjectionInstance * instance)
{
  task_t self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);
  if (instance->payload_address != 0)
    vm_deallocate (instance->task, instance->payload_address, ZED_PAYLOAD_SIZE);
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->fruitjector);
  g_free (instance);
}

static void
zed_injection_instance_handle_event (void * context)
{
  ZedInjectionInstance * instance = context;

  _zed_fruitjector_on_instance_dead (instance->fruitjector, instance->id);
}

void
_zed_fruitjector_free_instance (ZedFruitjector * self, void * instance)
{
  zed_injection_instance_free (instance);
}

guint
_zed_fruitjector_do_inject (ZedFruitjector * self, gulong pid,
    const char * dylib_path, const char * data_string, GError ** error)
{
  ZedFruitContext * ctx = self->context;
  ZedInjectionInstance * instance;
  const gchar * failed_operation;
  mach_port_name_t task = 0;
  kern_return_t ret;
  vm_address_t payload_address = (vm_address_t) NULL;
  guint8 mach_stub_code[512] = { 0, };
  guint8 pthread_stub_code[512] = { 0, };
  ZedAgentContext agent_ctx;
#ifdef HAVE_ARM
  arm_thread_state_t state;
  mach_msg_type_number_t state_count = ARM_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = ARM_THREAD_STATE;
#else
  x86_thread_state_t state;
  mach_msg_type_number_t state_count = x86_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = x86_THREAD_STATE;
#if GLIB_SIZEOF_VOID_P == 8
  x86_thread_state64_t * ts;
#endif
#endif
  dispatch_source_t source;

  instance = zed_injection_instance_new (self, self->last_id++);

  ret = task_for_pid (mach_task_self (), pid, &task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");
  instance->task = task;

  ret = vm_allocate (task, &payload_address, ZED_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");
  instance->payload_address = payload_address;

  ret = vm_protect (task, payload_address + ZED_STACK_GUARD_OFFSET, ZED_STACK_GUARD_SIZE, FALSE, VM_PROT_NONE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  zed_emit_mach_stub_code (mach_stub_code);
  ret = vm_write (task, payload_address + ZED_MACH_CODE_OFFSET,
      (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(mach_stub_code)");

  zed_emit_pthread_stub_code (pthread_stub_code);
  ret = vm_write (task, payload_address + ZED_PTHREAD_CODE_OFFSET,
      (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(pthread_stub_code)");

  if (!zed_fill_agent_context (&agent_ctx, dylib_path, data_string, payload_address, error))
    goto error_epilogue;
  ret = vm_write (task, payload_address + ZED_DATA_OFFSET, (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(data)");

  ret = vm_protect (task, payload_address + ZED_CODE_OFFSET, ZED_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  bzero (&state, sizeof (state));
#if defined(HAVE_ARM)
  state.__r[7] = payload_address + ZED_DATA_OFFSET;

  state.__sp = payload_address + ZED_STACK_TOP_OFFSET;
  state.__lr = 0xcafebabe;
  state.__pc = payload_address + ZED_MACH_CODE_OFFSET;
  state.__cpsr = ZED_PSR_THUMB;
#elif GLIB_SIZEOF_VOID_P == 8
  state.tsh.flavor = x86_THREAD_STATE64;
  state.tsh.count = x86_THREAD_STATE64_COUNT;
  ts = &state.uts.ts64;

  ts->__rbp = payload_address + ZED_DATA_OFFSET;

  ts->__rsp = payload_address + ZED_STACK_TOP_OFFSET;
  ts->__rip = payload_address + ZED_MACH_CODE_OFFSET;
#endif

  ret = thread_create_running (task, state_flavor, (thread_state_t) &state, state_count, &instance->thread);
  CHECK_MACH_RESULT (ret, ==, 0, "thread_create_running");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_id), GUINT_TO_POINTER (instance->id), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, instance->thread, DISPATCH_MACH_SEND_DEAD,
      ctx->dispatch_queue);
  instance->thread_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source,
      zed_injection_instance_handle_event);
  dispatch_resume (source);

  return instance->id;

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %s (%d)", failed_operation, mach_error_string (errno), errno);
    goto error_epilogue;
  }

error_epilogue:
  {
    zed_injection_instance_free (instance);
    return 0;
  }
}

#define ZED_CTX_ASSIGN_FUNCTION(field) \
  ctx->field##_impl = dlsym (syslib_handle, G_STRINGIFY (field)); \
  CHECK_DL_RESULT (ctx->field##_impl, !=, NULL, "dlsym(\"" G_STRINGIFY (field) "\")")

static gboolean
zed_fill_agent_context (ZedAgentContext * ctx, const char * dylib_path, const char * data_string,
    vm_address_t remote_payload_base, GError ** error)
{
  gboolean result = FALSE;
  void * syslib_handle = NULL;
  const gchar * failed_operation;

  syslib_handle = dlopen ("/usr/lib/libSystem.B.dylib", RTLD_LAZY | RTLD_GLOBAL);
  CHECK_DL_RESULT (syslib_handle, !=, NULL, "dlopen");

  ZED_CTX_ASSIGN_FUNCTION (_pthread_set_self);
  ZED_CTX_ASSIGN_FUNCTION (cthread_set_self);
  ctx->thread_self_data = (gpointer) (remote_payload_base + ZED_THREAD_SELF_OFFSET);

  ZED_CTX_ASSIGN_FUNCTION (pthread_create);
#ifdef HAVE_ARM
  ctx->pthread_create_start_routine = (gpointer) (remote_payload_base + ZED_PTHREAD_CODE_OFFSET + 1);
#else
  ctx->pthread_create_start_routine = (gpointer) (remote_payload_base + ZED_PTHREAD_CODE_OFFSET);
#endif
  ctx->pthread_create_arg = (gpointer) (remote_payload_base + ZED_DATA_OFFSET);

  ZED_CTX_ASSIGN_FUNCTION (pthread_join);

  ZED_CTX_ASSIGN_FUNCTION (thread_terminate);

  ZED_CTX_ASSIGN_FUNCTION (mach_thread_self);

  ZED_CTX_ASSIGN_FUNCTION (dlopen);
  CHECK_DL_RESULT (ctx->dlopen_impl, !=, NULL, "dlsym(\"dlopen\")");
  ctx->dylib_path = (gchar *) (remote_payload_base + ZED_DATA_OFFSET +
      G_STRUCT_OFFSET (ZedAgentContext, dylib_path_data));
  strcpy (ctx->dylib_path_data, dylib_path);
  ctx->dlopen_mode = RTLD_LAZY;

  ZED_CTX_ASSIGN_FUNCTION (dlsym);
  ctx->entrypoint_name = (gchar *) (remote_payload_base + ZED_DATA_OFFSET +
      G_STRUCT_OFFSET (ZedAgentContext, entrypoint_name_data));
  strcpy (ctx->entrypoint_name_data, ZED_AGENT_ENTRYPOINT_NAME);
  ctx->data_string = (gchar *) (remote_payload_base + ZED_DATA_OFFSET +
      G_STRUCT_OFFSET (ZedAgentContext, data_string_data));
  g_assert_cmpint (strlen (data_string), <, sizeof (ctx->data_string_data));
  strcpy (ctx->data_string_data, data_string);

  ZED_CTX_ASSIGN_FUNCTION (dlclose);

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

#ifdef HAVE_ARM

static void zed_emit_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw);

static void
zed_emit_mach_stub_code (guint8 * code)
{
  ZedEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);

  zed_emit_pthread_setup (&ctx);
  zed_emit_pthread_create_and_join (&ctx);
  zed_emit_thread_terminate (&ctx);

  gum_thumb_writer_free (&ctx.tw);
}

static void
zed_emit_pthread_stub_code (guint8 * code)
{
  ZedEmitContext ctx;

  ctx.code = code;
  gum_thumb_writer_init (&ctx.tw, ctx.code);

  gum_thumb_writer_put_push_regs (&ctx.tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_LR);
  gum_thumb_writer_put_mov_reg_reg (&ctx.tw, GUM_AREG_R7, GUM_AREG_R0);
  zed_emit_pthread_stub_body (&ctx);
  gum_thumb_writer_put_pop_regs (&ctx.tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_PC);

  gum_thumb_writer_free (&ctx.tw);
}

#define ZED_EMIT_LOAD(reg, field) \
    zed_emit_load_reg_with_ctx_value (GUM_AREG_##reg, G_STRUCT_OFFSET (ZedAgentContext, field), &ctx->tw)
#define ZED_EMIT_LOAD_U32(reg, val) \
    gum_thumb_writer_put_ldr_reg_u32 (&ctx->tw, GUM_AREG_##reg, val)
#define ZED_EMIT_MOVE(dstreg, srcreg) \
    gum_thumb_writer_put_mov_reg_reg (&ctx->tw, GUM_AREG_##dstreg, GUM_AREG_##srcreg)
#define ZED_EMIT_CALL(reg) \
    gum_thumb_writer_put_blx_reg (&ctx->tw, GUM_AREG_##reg)

static void
zed_emit_pthread_stub_body (ZedEmitContext * ctx)
{
  ZED_EMIT_LOAD (R1, dlopen_mode);
  ZED_EMIT_LOAD (R0, dylib_path);
  ZED_EMIT_LOAD (R3, dlopen_impl);
  ZED_EMIT_CALL (R3);
  ZED_EMIT_MOVE (R4, R0);

  ZED_EMIT_LOAD (R1, entrypoint_name);
  ZED_EMIT_MOVE (R0, R4);
  ZED_EMIT_LOAD (R3, dlsym_impl);
  ZED_EMIT_CALL (R3);
  ZED_EMIT_MOVE (R5, R0);

  ZED_EMIT_LOAD (R0, data_string);
  ZED_EMIT_CALL (R5);

  ZED_EMIT_MOVE (R0, R4);
  ZED_EMIT_LOAD (R3, dlclose_impl);
  ZED_EMIT_CALL (R3);
}

static void
zed_emit_pthread_setup (ZedEmitContext * ctx)
{
  ZED_EMIT_LOAD (R5, thread_self_data);

  ZED_EMIT_MOVE (R0, R5);
  ZED_EMIT_LOAD (R4, _pthread_set_self_impl);
  ZED_EMIT_CALL (R4);

  ZED_EMIT_MOVE (R0, R5);
  ZED_EMIT_LOAD (R4, cthread_set_self_impl);
  ZED_EMIT_CALL (R4);
}

static void
zed_emit_pthread_create_and_join (ZedEmitContext * ctx)
{
  ZED_EMIT_LOAD (R3, pthread_create_arg);
  ZED_EMIT_LOAD (R2, pthread_create_start_routine);
  ZED_EMIT_LOAD_U32 (R1, 0);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, GUM_AREG_R0);
  ZED_EMIT_MOVE (R0, SP);
  ZED_EMIT_LOAD (R4, pthread_create_impl);
  ZED_EMIT_CALL (R4);

  ZED_EMIT_LOAD_U32 (R1, 0);
  gum_thumb_writer_put_pop_regs (&ctx->tw, 1, GUM_AREG_R0);
  ZED_EMIT_LOAD (R4, pthread_join_impl);
  ZED_EMIT_CALL (R4);
}

static void
zed_emit_thread_terminate (ZedEmitContext * ctx)
{
  ZED_EMIT_LOAD (R4, mach_thread_self_impl);
  ZED_EMIT_CALL (R4);
  ZED_EMIT_LOAD (R4, thread_terminate_impl);
  ZED_EMIT_CALL (R4);
}

#undef ZED_EMIT_LOAD
#undef ZED_EMIT_MOVE
#undef ZED_EMIT_CALL

static void
zed_emit_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw)
{
  gum_thumb_writer_put_ldr_reg_u32 (tw, GUM_AREG_R6, field_offset);
  gum_thumb_writer_put_add_reg_reg_reg (tw, reg, GUM_AREG_R7, GUM_AREG_R6);
  gum_thumb_writer_put_ldr_reg_reg (tw, reg, reg);
}

#else /* HAVE_ARM */

static void
zed_emit_mach_stub_code (guint8 * code)
{
  ZedEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);

  zed_emit_pthread_setup (&ctx);
  zed_emit_pthread_create_and_join (&ctx);
  zed_emit_thread_terminate (&ctx);
  gum_x86_writer_put_int3 (&ctx.cw);

  gum_x86_writer_free (&ctx.cw);
}

static void
zed_emit_pthread_stub_code (guint8 * code)
{
  ZedEmitContext ctx;

  ctx.code = code;
  gum_x86_writer_init (&ctx.cw, ctx.code);

  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_push_reg (&ctx.cw, GUM_REG_XAX); /* padding */
  gum_x86_writer_put_mov_reg_reg (&ctx.cw, GUM_REG_XBP, GUM_REG_XDI);
  zed_emit_pthread_stub_body (&ctx);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XAX); /* padding */
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&ctx.cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&ctx.cw);

  gum_x86_writer_free (&ctx.cw);
}

#define ZED_EMIT_LOAD(reg, field) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&ctx->cw, GUM_REG_##reg, GUM_REG_XBP, G_STRUCT_OFFSET (ZedAgentContext, field))
#define ZED_EMIT_MOVE(dstreg, srcreg) \
    gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_##dstreg, GUM_REG_##srcreg)
#define ZED_EMIT_CALL(fun, ...) \
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&ctx->cw, GUM_CALL_CAPI, GUM_REG_XBP, G_STRUCT_OFFSET (ZedAgentContext, fun), __VA_ARGS__)

static void
zed_emit_pthread_stub_body (ZedEmitContext * ctx)
{
  ZED_EMIT_LOAD (XAX, dylib_path);
  ZED_EMIT_LOAD (XDX, dlopen_mode);
  ZED_EMIT_CALL (dlopen_impl, 2,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_REGISTER, GUM_REG_XDX);
  ZED_EMIT_MOVE (XBX, XAX);

  ZED_EMIT_LOAD (XAX, entrypoint_name);
  ZED_EMIT_CALL (dlsym_impl, 2,
      GUM_ARG_REGISTER, GUM_REG_XBX,
      GUM_ARG_REGISTER, GUM_REG_XAX);

  ZED_EMIT_LOAD (XDX, data_string);
  gum_x86_writer_put_call_reg_with_arguments (&ctx->cw,
      GUM_CALL_CAPI, GUM_REG_XAX, 1,
      GUM_ARG_REGISTER, GUM_REG_XDX);

  ZED_EMIT_CALL (dlclose_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XBX);
}

static void
zed_emit_pthread_setup (ZedEmitContext * ctx)
{
  ZED_EMIT_LOAD (XAX, thread_self_data);
  ZED_EMIT_CALL (_pthread_set_self_impl, 1, GUM_ARG_REGISTER, GUM_REG_XAX);

  ZED_EMIT_LOAD (XAX, thread_self_data);
  ZED_EMIT_CALL (cthread_set_self_impl, 1, GUM_ARG_REGISTER, GUM_REG_XAX);
}

static void
zed_emit_pthread_create_and_join (ZedEmitContext * ctx)
{
  gum_x86_writer_put_sub_reg_imm (&ctx->cw, GUM_REG_XSP, 16);
  gum_x86_writer_put_mov_reg_reg (&ctx->cw, GUM_REG_XAX, GUM_REG_XSP);
  ZED_EMIT_LOAD (XDX, pthread_create_start_routine);
  ZED_EMIT_LOAD (XCX, pthread_create_arg);
  ZED_EMIT_CALL (pthread_create_impl, 4,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_POINTER, NULL,
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_x86_writer_put_pop_reg (&ctx->cw, GUM_REG_XAX);
  gum_x86_writer_put_add_reg_imm (&ctx->cw, GUM_REG_XSP, 8);
  ZED_EMIT_CALL (pthread_join_impl, 2,
      GUM_ARG_REGISTER, GUM_REG_XAX,
      GUM_ARG_POINTER, NULL);
}

static void
zed_emit_thread_terminate (ZedEmitContext * ctx)
{
  ZED_EMIT_CALL (mach_thread_self_impl, 0);
  ZED_EMIT_CALL (thread_terminate_impl, 1,
      GUM_ARG_REGISTER, GUM_REG_XAX);
}

#undef ZED_EMIT_LOAD
#undef ZED_EMIT_MOVE
#undef ZED_EMIT_CALL

#endif /* !HAVE_ARM */

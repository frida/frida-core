#include "zed-server-core.h"

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <gum/gum.h>
#include <gum/arch-arm/gumthumbwriter.h>
#include <mach/mach.h>

#define ZID_AGENT_ENTRYPOINT_NAME "zed_agent_main"

#define ZID_CODE_OFFSET         (0)
#define ZID_MACH_CODE_OFFSET    (0)
#define ZID_PTHREAD_CODE_OFFSET (512)
#define ZID_DATA_OFFSET         (1024)
#define ZID_STACK_BOTTOM_OFFSET (4096)
#define ZID_STACK_TOP_OFFSET    (ZID_THREAD_SELF_OFFSET)
#define ZID_THREAD_SELF_OFFSET  (8192)

#define ZID_PAGE_SIZE           (4096)
#define ZID_PAYLOAD_SIZE        (12 * 1024)

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
  gpointer mach_thread_self_impl;

  gpointer pthread_start_impl;
  gpointer pthread_start_self;
  gpointer pthread_start_fun;
  gpointer pthread_start_funarg;
  gsize pthread_start_stacksize;
  guint pthread_start_pflags;

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

static const guint32 mach_stub_code[] =
{
  0x00000000,
#if 0
  0xe2870000 | G_STRUCT_OFFSET (ZedAgentContext, thread_self),           /* add r0, r7, <offset> */
  0xe5900000,                                                            /* ldr r0, [r0] */
  0xe2873000 | G_STRUCT_OFFSET (ZedAgentContext, pthread_set_self_impl), /* add r3, r7, <offset> */
  0xe5933000,                                                            /* ldr r3, [r3] */
  0xe12fff33,                                                            /* blx r3 */

  0xe24dd004,                                                            /* sub sp, sp, 4 */
  0xe1a03007,                                                            /* mov r3, r7 */
  0xe2872000 | G_STRUCT_OFFSET (ZedAgentContext, worker_func),           /* add r2, r7, <offset> */
  0xe5922000,                                                            /* ldr r2, [r2] */
  0xe0211001,                                                            /* eor r1, r1, r1 */
  0xe1a0000d,                                                            /* mov r0, sp */
  0xe2874000 | G_STRUCT_OFFSET (ZedAgentContext, pthread_create_impl),   /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34,                                                            /* blx r4 */

  0xe0211001,                                                            /* eor r1, r1, r1 */
  0xe59d0000,                                                            /* ldr r0, [sp] */
  0xe2874000 | G_STRUCT_OFFSET (ZedAgentContext, pthread_join_impl),     /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34,                                                            /* blx r4 */

  0xe2874000 | G_STRUCT_OFFSET (ZedAgentContext, mach_thread_self_impl), /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34,                                                            /* blx r4 */

  0xe2874000 | G_STRUCT_OFFSET (ZedAgentContext, thread_terminate_impl), /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34                                                             /* blx r4 */
#endif
};

static const guint32 pthread_stub_code[] =
{
  0x00000000,
#if 0
  0xe92d40b0,                                                            /* push {r4, r5, r7, lr} */

  0xe1a07000,                                                            /* mov r7, r0 */

  0xe2872000 | G_STRUCT_OFFSET (ZedAgentContext, dlopen_mode),           /* add	r1, r7, <offset> */
  0xe5921000,                                                            /* ldr	r1, [r1] */
  0xe2870000 | G_STRUCT_OFFSET (ZedAgentContext, dylib_path),            /* add	r0, r7, <offset> */
  0xe5900000,                                                            /* ldr r0, [r0] */
  0xe2873000 | G_STRUCT_OFFSET (ZedAgentContext, dlopen_impl),           /* add	r3, r7, <offset> */
  0xe5933000,                                                            /* ldr	r3, [r3] */
  0xe12fff33,                                                            /* blx	r3 */
  0xe1a04000,                                                            /* mov	r4, r0 */

  0xe2871000 | G_STRUCT_OFFSET (ZedAgentContext, entrypoint_name),       /* add	r1, r7, <offset> */
  0xe5911000,                                                            /* ldr r1, [r1] */
  0xe1a00004,                                                            /* mov r0, r4 */
  0xe2873000 | G_STRUCT_OFFSET (ZedAgentContext, dlsym_impl),            /* add	r3, r7, <offset> */
  0xe5933000,                                                            /* ldr	r3, [r3] */
  0xe12fff33,                                                            /* blx	r3 */
  0xe1a05000,                                                            /* mov	r5, r0 */

  0xe2870000 | G_STRUCT_OFFSET (ZedAgentContext, data_string),           /* add	r0, r7, <offset> */
  0xe5900000,                                                            /* ldr r0, [r0] */
  0xe12fff35,                                                            /* blx	r5 */

  0xe1a00004,                                                            /* mov	r0, r4 */
  0xe2873000 | G_STRUCT_OFFSET (ZedAgentContext, dlclose_impl),          /* add	r3, r7, <offset> */
  0xe5933000,                                                            /* ldr	r3, [r3] */
  0xe12fff33,                                                            /* blx	r3 */

  0xe8bd80b0                                                             /* pop {r4, r5, r7, pc} */
#endif
};

typedef struct _ZedEmitContext ZedEmitContext;

struct _ZedEmitContext
{
  guint8 code[512];
  GumThumbWriter tw;
};

static void zed_fruitjector_make_trampoline (void);
static void zed_emit_pthread_start_call (ZedEmitContext * ctx);
static void zed_emit_push_ctx_value (guint field_offset, GumThumbWriter * tw);
static void zed_emit_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw);

static gboolean fill_agent_context (ZedAgentContext * ctx,
    const char * dylib_path, const char * data_string,
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
    vm_deallocate (instance->task, instance->payload_address, ZID_PAYLOAD_SIZE);
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
_zed_fruitjector_do_inject (ZedFruitjector * self, guint pid,
    const char * dylib_path, const char * data_string, GError ** error)
{
  ZedFruitContext * ctx = self->context;
  ZedInjectionInstance * instance;
  const gchar * failed_operation;
  mach_port_name_t task = 0;
  kern_return_t ret;
  vm_address_t payload_address = (vm_address_t) NULL;
  ZedAgentContext agent_ctx;
  arm_thread_state_t state;
  dispatch_source_t source;

  instance = zed_injection_instance_new (self, self->last_id++);

  ret = task_for_pid (mach_task_self (), pid, &task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");
  instance->task = task;

  ret = vm_allocate (task, &payload_address, ZID_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");
  instance->payload_address = payload_address;

  zed_fruitjector_make_trampoline ();

  ret = vm_write (task, payload_address + ZID_MACH_CODE_OFFSET,
      (vm_offset_t) mach_stub_code, sizeof (mach_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(mach_stub_code)");

  ret = vm_write (task, payload_address + ZID_PTHREAD_CODE_OFFSET,
      (vm_offset_t) pthread_stub_code, sizeof (pthread_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(pthread_stub_code)");

  if (!fill_agent_context (&agent_ctx, dylib_path, data_string, payload_address,
      error))
  {
    goto error_epilogue;
  }
  ret = vm_write (task, payload_address + ZID_DATA_OFFSET,
      (vm_offset_t) &agent_ctx, sizeof (agent_ctx));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(data)");

  ret = vm_protect (task, payload_address + ZID_CODE_OFFSET, ZID_PAGE_SIZE,
      FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  state.__r[7] = payload_address + ZID_DATA_OFFSET;

  state.__sp = payload_address + ZID_STACK_TOP_OFFSET;
  state.__lr = 0xcafebabe;
  state.__pc = payload_address + ZID_MACH_CODE_OFFSET;
  state.__cpsr = 0;

  ret = thread_create_running (task, ARM_THREAD_STATE,
      (thread_state_t) &state, ARM_THREAD_STATE_COUNT, &instance->thread);
  CHECK_MACH_RESULT (ret, ==, 0, "thread_create_running");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_id),
      GUINT_TO_POINTER (instance->id), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND,
      instance->thread, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  instance->thread_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source,
      zed_injection_instance_handle_event);
  dispatch_resume (source);

  return instance->id;

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %d", failed_operation, errno);
    goto error_epilogue;
  }

error_epilogue:
  {
    zed_injection_instance_free (instance);
    return 0;
  }
}

static gboolean
fill_agent_context (ZedAgentContext * ctx, const char * dylib_path,
    const char * data_string, vm_address_t remote_payload_base, GError ** error)
{
#if 0
  gboolean result = FALSE;
  void * syslib_handle = NULL;
  const gchar * failed_operation;

  syslib_handle = dlopen ("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_GLOBAL);
  CHECK_DL_RESULT (syslib_handle, !=, NULL, "dlopen");

  ctx->pthread_set_self_impl = dlsym (syslib_handle, "__pthread_set_self");
  CHECK_DL_RESULT (ctx->pthread_set_self_impl, !=, NULL,
      "dlsym(\"__pthread_set_self\")");
  ctx->thread_self = (gpointer) (remote_payload_base + ZID_THREAD_SELF_OFFSET);

  ctx->pthread_create_impl = dlsym (syslib_handle, "pthread_create");
  CHECK_DL_RESULT (ctx->pthread_create_impl, !=, NULL,
      "dlsym(\"pthread_create\")");
  ctx->worker_func = (gpointer) (remote_payload_base + ZID_PTHREAD_CODE_OFFSET);

  ctx->pthread_join_impl = dlsym (syslib_handle, "pthread_join");
  CHECK_DL_RESULT (ctx->pthread_join_impl, !=, NULL, "dlsym(\"pthread_join\")");

  ctx->thread_terminate_impl = dlsym (syslib_handle, "thread_terminate");
  CHECK_DL_RESULT (ctx->thread_terminate_impl, !=, NULL,
      "dlsym(\"thread_terminate\")");
  ctx->mach_thread_self_impl = dlsym (syslib_handle, "mach_thread_self");
  CHECK_DL_RESULT (ctx->mach_thread_self_impl, !=, NULL,
      "dlsym(\"mach_thread_self\")");

  ctx->dlopen_impl = dlsym (syslib_handle, "dlopen");
  CHECK_DL_RESULT (ctx->dlopen_impl, !=, NULL, "dlsym(\"dlopen\")");
  ctx->dylib_path = (gchar *) (remote_payload_base + ZID_DATA_OFFSET +
      G_STRUCT_OFFSET (ZedAgentContext, dylib_path_data));
  strcpy (ctx->dylib_path_data, dylib_path);
  ctx->dlopen_mode = RTLD_LAZY;

  ctx->dlsym_impl = dlsym (syslib_handle, "dlsym");
  CHECK_DL_RESULT (ctx->dlsym_impl, !=, NULL, "dlsym(\"dlsym\")");
  ctx->entrypoint_name = (gchar *) (remote_payload_base + ZID_DATA_OFFSET +
      G_STRUCT_OFFSET (ZedAgentContext, entrypoint_name_data));
  strcpy (ctx->entrypoint_name_data, ZID_AGENT_ENTRYPOINT_NAME);
  ctx->data_string = (gchar *) (remote_payload_base + ZID_DATA_OFFSET +
      G_STRUCT_OFFSET (ZedAgentContext, data_string_data));
  g_assert_cmpint (strlen (data_string), <, sizeof (ctx->data_string_data));
  strcpy (ctx->data_string_data, data_string);

  ctx->dlclose_impl = dlsym (syslib_handle, "dlclose");
  CHECK_DL_RESULT (ctx->dlclose_impl, !=, NULL, "dlsym(\"dlclose\")");

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
#endif
  return TRUE;
}

static void
zed_fruitjector_make_trampoline (void)
{
  ZedEmitContext ctx;

  gum_thumb_writer_init (&ctx.tw, ctx.code);

  zed_emit_pthread_start_call (&ctx);

  gum_thumb_writer_free (&ctx.tw);
}

static void
zed_emit_pthread_start_call (ZedEmitContext * ctx)
{
#define ZED_EMIT_PUSH(field) \
  zed_emit_push_ctx_value (G_STRUCT_OFFSET (ZedAgentContext, field), &ctx->tw)
#define ZED_EMIT_LOAD(reg, field) \
  zed_emit_load_reg_with_ctx_value (GUM_AREG_##reg, G_STRUCT_OFFSET (ZedAgentContext, field), &ctx->tw)

  ZED_EMIT_PUSH (pthread_start_pflags);
  ZED_EMIT_PUSH (pthread_start_stacksize);
  ZED_EMIT_PUSH (pthread_start_funarg);
  ZED_EMIT_PUSH (pthread_start_fun);

  ZED_EMIT_LOAD (R0, mach_thread_self_impl);
  gum_thumb_writer_put_blx_reg (&ctx->tw, GUM_AREG_R0);
  gum_thumb_writer_put_push_regs (&ctx->tw, 1, GUM_AREG_R0);

  ZED_EMIT_PUSH (pthread_start_self);

  gum_thumb_writer_put_pop_regs (&ctx->tw, 4, GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3);

  ZED_EMIT_LOAD (R4, pthread_start_impl);
  gum_thumb_writer_put_bx_reg (&ctx->tw, GUM_AREG_R4);

#undef ZED_EMIT_PUSH
#undef ZED_EMIT_LOAD
}

static void
zed_emit_push_ctx_value (guint field_offset, GumThumbWriter * tw)
{
  zed_emit_load_reg_with_ctx_value (GUM_AREG_R0, field_offset, tw);
  gum_thumb_writer_put_push_regs (tw, 1, GUM_AREG_R0);
}

static void
zed_emit_load_reg_with_ctx_value (GumArmReg reg, guint field_offset, GumThumbWriter * tw)
{
  gum_thumb_writer_put_add_reg_reg_imm (tw, reg, GUM_AREG_R7, field_offset);
  gum_thumb_writer_put_ldr_reg_reg (tw, reg, reg);
}

#include "zid-core.h"

#include <dlfcn.h>
#include <errno.h>
#include <dispatch/dispatch.h>
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

typedef struct _ZidFruitContext ZidFruitContext;
typedef struct _ZidInjectionInstance ZidInjectionInstance;
typedef struct _ZidAgentContext ZidAgentContext;

struct _ZidFruitContext
{
  dispatch_queue_t dispatch_queue;
};

struct _ZidInjectionInstance
{
  ZidFruitjector * fruitjector;
  guint id;
  mach_port_t task;
  mach_port_t thread;
  dispatch_source_t thread_monitor_source;
};

struct _ZidAgentContext
{
  gpointer pthread_set_self_impl;
  gpointer thread_self;

  gpointer pthread_create_impl;
  gpointer worker_func;

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

static const guint32 mach_stub_code[] =
{
  0xe2870000 | G_STRUCT_OFFSET (ZidAgentContext, thread_self),           /* add r0, r7, <offset> */
  0xe5900000,                                                            /* ldr r0, [r0] */
  0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, pthread_set_self_impl), /* add r3, r7, <offset> */
  0xe5933000,                                                            /* ldr r3, [r3] */
  0xe12fff33,                                                            /* blx r3 */

  0xe24dd004,                                                            /* sub sp, sp, 4 */
  0xe1a03007,                                                            /* mov r3, r7 */
  0xe2872000 | G_STRUCT_OFFSET (ZidAgentContext, worker_func),           /* add r2, r7, <offset> */
  0xe5922000,                                                            /* ldr r2, [r2] */
  0xe0211001,                                                            /* eor r1, r1, r1 */
  0xe1a0000d,                                                            /* mov r0, sp */
  0xe2874000 | G_STRUCT_OFFSET (ZidAgentContext, pthread_create_impl),   /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34,                                                            /* blx r4 */

  0xe0211001,                                                            /* eor r1, r1, r1 */
  0xe59d0000,                                                            /* ldr r0, [sp] */
  0xe2874000 | G_STRUCT_OFFSET (ZidAgentContext, pthread_join_impl),     /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34,                                                            /* blx r4 */

  0xe2874000 | G_STRUCT_OFFSET (ZidAgentContext, mach_thread_self_impl), /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34,                                                            /* blx r4 */

  0xe2874000 | G_STRUCT_OFFSET (ZidAgentContext, thread_terminate_impl), /* add r4, r7, <offset> */
  0xe5944000,                                                            /* ldr r4, [r4] */
  0xe12fff34                                                             /* blx r4 */
};

static const guint32 pthread_stub_code[] =
{
  0xe92d40b0,                                                            /* push {r4, r5, r7, lr} */

  0xe1a07000,                                                            /* mov r7, r0 */

  0xe2872000 | G_STRUCT_OFFSET (ZidAgentContext, dlopen_mode),           /* add	r1, r7, <offset> */
  0xe5921000,                                                            /* ldr	r1, [r1] */
  0xe2870000 | G_STRUCT_OFFSET (ZidAgentContext, dylib_path),            /* add	r0, r7, <offset> */
  0xe5900000,                                                            /* ldr r0, [r0] */
  0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, dlopen_impl),           /* add	r3, r7, <offset> */
  0xe5933000,                                                            /* ldr	r3, [r3] */
  0xe12fff33,                                                            /* blx	r3 */
  0xe1a04000,                                                            /* mov	r4, r0 */

  0xe2871000 | G_STRUCT_OFFSET (ZidAgentContext, entrypoint_name),       /* add	r1, r7, <offset> */
  0xe5911000,                                                            /* ldr r1, [r1] */
  0xe1a00004,                                                            /* mov r0, r4 */
  0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, dlsym_impl),            /* add	r3, r7, <offset> */
  0xe5933000,                                                            /* ldr	r3, [r3] */
  0xe12fff33,                                                            /* blx	r3 */
  0xe1a05000,                                                            /* mov	r5, r0 */

  0xe2870000 | G_STRUCT_OFFSET (ZidAgentContext, data_string),           /* add	r0, r7, <offset> */
  0xe5900000,                                                            /* ldr r0, [r0] */
  0xe12fff35,                                                            /* blx	r5 */

  0xe1a00004,                                                            /* mov	r0, r4 */
  0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, dlclose_impl),          /* add	r3, r7, <offset> */
  0xe5933000,                                                            /* ldr	r3, [r3] */
  0xe12fff33,                                                            /* blx	r3 */

  0xe8bd80b0                                                             /* pop {r4, r5, r7, pc} */
};

static gboolean fill_agent_context (ZidAgentContext * ctx,
    const char * dylib_path, const char * data_string,
    vm_address_t remote_payload_base, GError ** error);

void
_zid_fruitjector_create_context (ZidFruitjector * self)
{
  ZidFruitContext * ctx;

  ctx = g_new0 (ZidFruitContext, 1);
  ctx->dispatch_queue = dispatch_queue_create (
      "org.boblycat.frida.fruitjector.queue", NULL);

  self->context = ctx;
}

void
_zid_fruitjector_destroy_context (ZidFruitjector * self)
{
  ZidFruitContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);
  g_free (ctx);
}

static ZidInjectionInstance *
zid_injection_instance_new (ZidFruitjector * fruitjector, guint id)
{
  ZidInjectionInstance * instance;

  instance = g_new0 (ZidInjectionInstance, 1);
  instance->fruitjector = g_object_ref (fruitjector);
  instance->id = id;
  instance->task = MACH_PORT_NULL;
  instance->thread = MACH_PORT_NULL;

  return instance;
}

static void
zid_injection_instance_free (ZidInjectionInstance * instance)
{
  task_t self_task = mach_task_self ();

  if (instance->thread_monitor_source != NULL)
    dispatch_release (instance->thread_monitor_source);
  if (instance->thread != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->thread);
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->fruitjector);
  g_free (instance);
}

static void
zid_injection_instance_handle_event (void * context)
{
  ZidInjectionInstance * instance = context;

  _zid_fruitjector_on_instance_dead (instance->fruitjector, instance->id);
}

void
_zid_fruitjector_free_instance (ZidFruitjector * self, void * instance)
{
  zid_injection_instance_free (instance);
}

guint
_zid_fruitjector_do_inject (ZidFruitjector * self, guint pid,
    const char * dylib_path, const char * data_string, GError ** error)
{
  ZidFruitContext * ctx = self->context;
  ZidInjectionInstance * instance;
  const gchar * failed_operation;
  mach_port_name_t task = 0;
  kern_return_t ret;
  vm_address_t payload_address = (vm_address_t) NULL;
  ZidAgentContext agent_ctx;
  arm_thread_state_t state;
  dispatch_source_t source;

  instance = zid_injection_instance_new (self, self->last_id++);

  ret = task_for_pid (mach_task_self (), pid, &task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");
  instance->task = task;

  ret = vm_allocate (task, &payload_address, ZID_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");

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
  state.__pc = payload_address + ZID_CODE_OFFSET;
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
      zid_injection_instance_handle_event);
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
    zid_injection_instance_free (instance);
    return 0;
  }
}

static gboolean
fill_agent_context (ZidAgentContext * ctx, const char * dylib_path,
    const char * data_string, vm_address_t remote_payload_base, GError ** error)
{
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
      G_STRUCT_OFFSET (ZidAgentContext, dylib_path_data));
  strcpy (ctx->dylib_path_data, dylib_path);
  ctx->dlopen_mode = RTLD_LAZY;

  ctx->dlsym_impl = dlsym (syslib_handle, "dlsym");
  CHECK_DL_RESULT (ctx->dlsym_impl, !=, NULL, "dlsym(\"dlsym\")");
  ctx->entrypoint_name = (gchar *) (remote_payload_base + ZID_DATA_OFFSET +
      G_STRUCT_OFFSET (ZidAgentContext, entrypoint_name_data));
  strcpy (ctx->entrypoint_name_data, ZID_AGENT_ENTRYPOINT_NAME);
  ctx->data_string = (gchar *) (remote_payload_base + ZID_DATA_OFFSET +
      G_STRUCT_OFFSET (ZidAgentContext, data_string_data));
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
}


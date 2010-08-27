#include "zid-core.h"

#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>

#define ZID_AGENT_ENTRYPOINT_NAME "zed_agent_main"

#define ZID_CODE_OFFSET         (0)
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

typedef struct _ZidAgentContext ZidAgentContext;

struct _ZidAgentContext {
  gpointer pthread_set_self_impl;
  gpointer thread_self;

  gpointer dlopen_impl;
  gchar dylib_path[256];
  int dlopen_mode;

  gpointer dlsym_impl;
  gchar entrypoint_name[32];
  gchar data_string[256];

  gpointer dlclose_impl;

  gpointer pthread_exit_impl;
};

static const guint32 load_stub_code[] = {
    0xe2870000 | G_STRUCT_OFFSET (ZidAgentContext, thread_self),           /* add	r0, r7, <offset> */
    0xe5900000,                                                            /* ldr	r0, [r0] */
    0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, pthread_set_self_impl), /* add	r3, r7, <offset> */
    0xe5933000,                                                            /* ldr	r3, [r3] */
    0xe12fff33,                                                            /* blx	r3 */

    0xe2871000 | G_STRUCT_OFFSET (ZidAgentContext, dlopen_mode),           /* add	r1, r7, <offset> */
    0xe5911000,                                                            /* ldr	r1, [r1] */
    0xe2870000 | G_STRUCT_OFFSET (ZidAgentContext, dylib_path),            /* add	r0, r7, <offset> */
    0xe5900000,                                                            /* ldr	r0, [r0] */
    0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, dlopen_impl),           /* add	r3, r7, <offset> */
    0xe5933000,                                                            /* ldr	r3, [r3] */
    0xe12fff33,                                                            /* blx	r3 */

    0xe1a04000,                                                            /* mov	r4, r0 */
    0xe2871000 | G_STRUCT_OFFSET (ZidAgentContext, entrypoint_name),       /* add	r1, r7, <offset> */
    0xe5911000,                                                            /* ldr	r1, [r1] */
    0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, dlsym_impl),            /* add	r3, r7, <offset> */
    0xe5933000,                                                            /* ldr	r3, [r3] */
    0xe12fff33,                                                            /* blx	r3 */

    0xe1a05000,                                                            /* mov	r5, r0 */
    0xe2870000 | G_STRUCT_OFFSET (ZidAgentContext, data_string),           /* add	r0, r7, <offset> */
    0xe5900000,                                                            /* ldr	r0, [r0] */
    0xe12fff35,                                                            /* blx	r5 */

    0xe1a00004,                                                            /* mov	r0, r4 */
    0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, dlclose_impl),          /* add	r3, r7, <offset> */
    0xe5933000,                                                            /* ldr	r3, [r3] */
    0xe12fff33,                                                            /* blx	r3 */

    0xe2873000 | G_STRUCT_OFFSET (ZidAgentContext, pthread_exit_impl),     /* add	r3, r7, <offset> */
    0xe5933000,                                                            /* ldr	r3, [r3] */
    0xe12fff33,                                                            /* blx	r3 */
};

static gboolean fill_agent_context (ZidAgentContext * ctx,
    const char * dylib_path, vm_address_t thread_self, GError ** error);

void
zid_fruitjector_do_inject (ZidFruitjector * self, gint pid,
    const char * dylib_path, GError ** error)
{
  const gchar * failed_operation;
  mach_port_name_t task = 0;
  kern_return_t ret;
  vm_address_t payload_address = (vm_address_t) NULL;
  ZidAgentContext ctx;
  arm_thread_state_t state;
  thread_act_t thread;

  ret = task_for_pid (mach_task_self (), pid, &task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");

  ret = vm_allocate (task, &payload_address, ZID_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");

  ret = vm_write (task, payload_address + ZID_CODE_OFFSET,
      (vm_offset_t) load_stub_code, sizeof (load_stub_code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(code)");

  if (!fill_agent_context (&ctx, dylib_path,
      payload_address + ZID_THREAD_SELF_OFFSET, error))
  {
    goto beach;
  }
  ret = vm_write (task, payload_address + ZID_DATA_OFFSET,
      (vm_offset_t) &ctx, sizeof (ctx));
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
      (thread_state_t) &state, ARM_THREAD_STATE_COUNT, &thread);
  CHECK_MACH_RESULT (ret, ==, 0, "thread_create_running");

  goto beach;

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %d", failed_operation, errno);
    goto beach;
  }

beach:
  {
    return;
  }
}

static gboolean
fill_agent_context (ZidAgentContext * ctx,const char * dylib_path,
    vm_address_t thread_self, GError ** error)
{
  gboolean result = FALSE;
  void * syslib_handle = NULL;
  const gchar * failed_operation;

  syslib_handle = dlopen ("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_GLOBAL);
  CHECK_DL_RESULT (syslib_handle, !=, NULL, "dlopen");

  ctx->pthread_set_self_impl = dlsym (syslib_handle, "__pthread_set_self");
  CHECK_DL_RESULT (ctx->pthread_set_self_impl, !=, NULL,
      "dlsym(\"__pthread_set_self\")");
  ctx->thread_self = (gpointer) thread_self;

  ctx->dlopen_impl = dlsym (syslib_handle, "dlopen");
  CHECK_DL_RESULT (ctx->dlopen_impl, !=, NULL, "dlsym(\"dlopen\")");
  strcpy (ctx->dylib_path, dylib_path);
  ctx->dlopen_mode = RTLD_LAZY;

  ctx->dlsym_impl = dlsym (syslib_handle, "dlsym");
  CHECK_DL_RESULT (ctx->dlsym_impl, !=, NULL, "dlsym(\"dlsym\")");
  strcpy (ctx->entrypoint_name, ZID_AGENT_ENTRYPOINT_NAME);
  strcpy (ctx->data_string, "FIXME");

  ctx->dlclose_impl = dlsym (syslib_handle, "dlclose");
  CHECK_DL_RESULT (ctx->dlclose_impl, !=, NULL, "dlsym(\"dlclose\")");

  ctx->pthread_exit_impl = dlsym (syslib_handle, "pthread_exit");
  CHECK_DL_RESULT (ctx->pthread_exit_impl, !=, NULL, "dlsym(\"pthread_exit\")");

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


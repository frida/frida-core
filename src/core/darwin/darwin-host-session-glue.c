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
#include <gum/gumdarwin.h>
#include <mach/mach.h>
#include <spawn.h>
#include <string.h>

#define ZED_SYSTEM_LIBC         "/usr/lib/libSystem.B.dylib"

#define ZED_PAGE_SIZE           (4096)
#define ZED_CODE_OFFSET         (0 * ZED_PAGE_SIZE)
#define ZED_DATA_OFFSET         (1 * ZED_PAGE_SIZE)
#define ZED_PAYLOAD_SIZE        (2 * ZED_PAGE_SIZE)

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _ZedDarwinHostContext ZedDarwinHostContext;
typedef struct _ZedSpawnInstance ZedSpawnInstance;
typedef struct _ZedSpawnMessageTx ZedSpawnMessageTx;
typedef struct _ZedSpawnMessageRx ZedSpawnMessageRx;
typedef struct _ZedRemoteApi ZedRemoteApi;
typedef struct _ZedFillContext ZedFillContext;

struct _ZedDarwinHostContext
{
  dispatch_queue_t dispatch_queue;
};

struct _ZedSpawnInstance
{
  ZedDarwinHostSession * host_session;
  guint pid;
  GumCpuType cpu_type;
  mach_port_t task;
  dispatch_source_t task_monitor_source;

  GumAddress entrypoint;
  vm_address_t payload_address;
  guint8 * overwritten_code;
  guint overwritten_code_size;

  mach_port_name_t server_port;
  mach_port_name_t reply_port;
  dispatch_source_t server_recv_source;
};

struct _ZedSpawnMessageTx
{
  mach_msg_header_t header;
};

struct _ZedSpawnMessageRx
{
  mach_msg_header_t header;
  mach_msg_trailer_t trailer;
};

struct _ZedRemoteApi
{
  GumAddress mach_task_self_impl;
  GumAddress mach_port_allocate_impl;
  GumAddress mach_port_deallocate_impl;
  GumAddress mach_msg_impl;
  GumAddress abort_impl;
};

struct _ZedFillContext
{
  ZedRemoteApi * api;
  guint remaining;
};

static ZedSpawnInstance * zed_spawn_instance_new (ZedDarwinHostSession * host_session);
static void zed_spawn_instance_free (ZedSpawnInstance * instance);
static void zed_spawn_instance_resume (ZedSpawnInstance * self);

static void zed_spawn_instance_on_task_dead (void * context);
static void zed_spawn_instance_on_server_recv (void * context);

static gboolean zed_spawn_instance_find_remote_api (ZedSpawnInstance * self, ZedRemoteApi * api, GError ** error);
static gboolean zed_spawn_instance_find_remote_api_the_easy_way (ZedSpawnInstance * self, ZedRemoteApi * api, GError ** error);
static gboolean zed_spawn_instance_find_remote_api_the_hard_way (ZedSpawnInstance * self, ZedRemoteApi * api, GError ** error);
static gboolean zed_fill_function_if_matching (const gchar * name, GumAddress address, gpointer user_data);

static gboolean zed_spawn_instance_emit_redirect_code (ZedSpawnInstance * self, guint8 * code, guint * code_size, GError ** error);
static gboolean zed_spawn_instance_emit_sync_code (ZedSpawnInstance * self, const ZedRemoteApi * api, guint8 * code, guint * code_size, GError ** error);

void
_zed_darwin_host_session_create_context (ZedDarwinHostSession * self)
{
  ZedDarwinHostContext * ctx;

  ctx = g_slice_new (ZedDarwinHostContext);
  ctx->dispatch_queue = dispatch_queue_create (
      "org.boblycat.frida.darwin-host-session.queue", NULL);

  self->context = ctx;
}

void
_zed_darwin_host_session_destroy_context (ZedDarwinHostSession * self)
{
  ZedDarwinHostContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_slice_free (ZedDarwinHostContext, ctx);
}

guint
_zed_darwin_host_session_do_spawn (ZedDarwinHostSession * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  ZedDarwinHostContext * ctx = self->context;
  ZedSpawnInstance * instance;
  pid_t pid;
  posix_spawnattr_t attr;
  sigset_t signal_mask_set;
  int result;
  const gchar * failed_operation;
  kern_return_t ret;
  mach_port_name_t task;
  ZedRemoteApi api;
  vm_address_t payload_address = (vm_address_t) NULL;
  guint8 redirect_code[512];
  guint redirect_code_size;
  guint8 sync_code[512];
  guint sync_code_size;
  ZedSpawnMessageTx msg;
  mach_port_name_t name;
  dispatch_source_t source;

  instance = zed_spawn_instance_new (self);

  posix_spawnattr_init (&attr);
  sigemptyset (&signal_mask_set);
  posix_spawnattr_setsigmask (&attr, &signal_mask_set);
  posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED);

  result = posix_spawn (&pid, path, 0, &attr, argv, envp);

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

  if (!zed_spawn_instance_find_remote_api (instance, &api, error))
    goto error_epilogue;

  ret = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &instance->server_port);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_allocate server");

  ret = vm_allocate (task, &payload_address, ZED_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");
  instance->payload_address = payload_address;

  if (!zed_spawn_instance_emit_redirect_code (instance, redirect_code, &redirect_code_size, error))
    goto error_epilogue;
  instance->overwritten_code = gum_darwin_read (task, instance->entrypoint, redirect_code_size, NULL);
  instance->overwritten_code_size = redirect_code_size;
  ret = vm_protect (task, instance->entrypoint, redirect_code_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");
  ret = vm_write (task, instance->entrypoint, (vm_offset_t) redirect_code, redirect_code_size);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(redirect_code)");
  ret = vm_protect (task, instance->entrypoint, redirect_code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  if (!zed_spawn_instance_emit_sync_code (instance, &api, sync_code, &sync_code_size, error))
    goto error_epilogue;
  ret = vm_write (task, payload_address + ZED_CODE_OFFSET, (vm_offset_t) sync_code, sync_code_size);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(sync_code)");

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND_ONCE, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  msg.header.msgh_size = sizeof (msg);
  name = 0x1233;
  do
  {
    name++;
    ret = mach_port_insert_right (task, name, instance->server_port, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  }
  while (ret == KERN_NAME_EXISTS);
  CHECK_MACH_RESULT (ret, ==, 0, "mach_port_insert_right");
  msg.header.msgh_remote_port = name;
  msg.header.msgh_local_port = MACH_PORT_NULL; /* filled in by the sync code */
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 1337;
  ret = vm_write (task, payload_address + ZED_DATA_OFFSET, (vm_offset_t) &msg, sizeof (msg));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(data)");

  ret = vm_protect (task, payload_address + ZED_CODE_OFFSET, ZED_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  ret = vm_protect (task, payload_address + ZED_DATA_OFFSET, ZED_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_pid), GUINT_TO_POINTER (pid), instance);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_SEND, task, DISPATCH_MACH_SEND_DEAD, ctx->dispatch_queue);
  instance->task_monitor_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, zed_spawn_instance_on_task_dead);
  dispatch_resume (source);

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV, instance->server_port, 0, ctx->dispatch_queue);
  instance->server_recv_source = source;
  dispatch_set_context (source, instance);
  dispatch_source_set_event_handler_f (source, zed_spawn_instance_on_server_recv);
  dispatch_resume (source);

  kill (pid, SIGCONT);

  return pid;

handle_spawn_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "posix_spawn failed: %s (%d)", strerror (result), result);
    goto error_epilogue;
  }

handle_cpu_type_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to probe cpu type");
    goto error_epilogue;
  }

handle_entrypoint_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to find entrypoint");
    goto error_epilogue;
  }

handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %s (%d)", failed_operation, mach_error_string (ret), ret);
    goto error_epilogue;
  }

error_epilogue:
  {
    if (instance->pid != 0)
      kill (instance->pid, SIGKILL);
    zed_spawn_instance_free (instance);
    return 0;
  }
}

void
_zed_darwin_host_session_resume_instance (ZedDarwinHostSession * self, void * instance)
{
  zed_spawn_instance_resume (instance);
}

void
_zed_darwin_host_session_free_instance (ZedDarwinHostSession * self, void * instance)
{
  zed_spawn_instance_free (instance);
}

static ZedSpawnInstance *
zed_spawn_instance_new (ZedDarwinHostSession * host_session)
{
  ZedSpawnInstance * instance;

  instance = g_slice_new0 (ZedSpawnInstance);
  instance->host_session = g_object_ref (host_session);
  instance->task = MACH_PORT_NULL;
  instance->task_monitor_source = NULL;

  instance->overwritten_code = NULL;

  instance->server_port = MACH_PORT_NULL;
  instance->reply_port = MACH_PORT_NULL;
  instance->server_recv_source = NULL;

  return instance;
}

static void
zed_spawn_instance_free (ZedSpawnInstance * instance)
{
  task_t self_task = mach_task_self ();

  if (instance->server_recv_source != NULL)
    dispatch_release (instance->server_recv_source);
  if (instance->reply_port != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->reply_port);
  if (instance->server_port != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->server_port);

  g_free (instance->overwritten_code);

  if (instance->task_monitor_source != NULL)
    dispatch_release (instance->task_monitor_source);
  if (instance->task != MACH_PORT_NULL)
    mach_port_deallocate (self_task, instance->task);
  g_object_unref (instance->host_session);

  g_slice_free (ZedSpawnInstance, instance);
}

static void
zed_spawn_instance_resume (ZedSpawnInstance * self)
{
  ZedSpawnMessageTx msg;

  msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_remote_port = self->reply_port;
  msg.header.msgh_local_port = MACH_PORT_NULL;
  msg.header.msgh_reserved = 0;
  msg.header.msgh_id = 1437;
  mach_msg_send (&msg.header);
}

static void
zed_spawn_instance_on_task_dead (void * context)
{
  ZedSpawnInstance * self = context;

  _zed_darwin_host_session_on_instance_dead (self->host_session, self->pid);
}

static void
zed_spawn_instance_on_server_recv (void * context)
{
  ZedSpawnInstance * self = context;
  ZedSpawnMessageRx msg;
  kern_return_t ret;

  bzero (&msg, sizeof (msg));
  msg.header.msgh_size = sizeof (msg);
  msg.header.msgh_local_port = self->server_port;
  ret = mach_msg_receive (&msg.header);
  g_assert_cmpint (ret, ==, 0);
  g_assert_cmpint (msg.header.msgh_id, ==, 1337);
  self->reply_port = msg.header.msgh_remote_port;

  vm_protect (self->task, self->entrypoint, self->overwritten_code_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  vm_write (self->task, self->entrypoint, (vm_offset_t) self->overwritten_code, self->overwritten_code_size);
  vm_protect (self->task, self->entrypoint, self->overwritten_code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

  _zed_darwin_host_session_on_instance_ready (self->host_session, self->pid);
}

static gboolean
zed_spawn_instance_find_remote_api (ZedSpawnInstance * self, ZedRemoteApi * api, GError ** error)
{
  GumCpuType own_cpu_type;
  if (!gum_darwin_cpu_type_from_pid (getpid (), &own_cpu_type))
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to probe cpu type");
    return FALSE;
  }

  if (self->cpu_type == own_cpu_type)
    return zed_spawn_instance_find_remote_api_the_easy_way (self, api, error);
  else
    return zed_spawn_instance_find_remote_api_the_hard_way (self, api, error);
}

#define ZED_REMOTE_API_ASSIGN_FUNCTION(field) \
  api->field##_impl = GUM_ADDRESS (dlsym (syslib_handle, G_STRINGIFY (field))); \
  CHECK_DL_RESULT (api->field##_impl, !=, 0, "dlsym(\"" G_STRINGIFY (field) "\")")
#define CHECK_DL_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_dl_error; \
  }

static gboolean
zed_spawn_instance_find_remote_api_the_easy_way (ZedSpawnInstance * self, ZedRemoteApi * api, GError ** error)
{
  gboolean result = FALSE;
  void * syslib_handle;
  const gchar * failed_operation;

  syslib_handle = dlopen (ZED_SYSTEM_LIBC, RTLD_LAZY | RTLD_GLOBAL);
  CHECK_DL_RESULT (syslib_handle, !=, NULL, "dlopen");

  ZED_REMOTE_API_ASSIGN_FUNCTION (mach_task_self);
  ZED_REMOTE_API_ASSIGN_FUNCTION (mach_port_allocate);
  ZED_REMOTE_API_ASSIGN_FUNCTION (mach_port_deallocate);
  ZED_REMOTE_API_ASSIGN_FUNCTION (mach_msg);
  ZED_REMOTE_API_ASSIGN_FUNCTION (abort);

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
zed_spawn_instance_find_remote_api_the_hard_way (ZedSpawnInstance * self, ZedRemoteApi * api, GError ** error)
{
  ZedFillContext fill_ctx;

  fill_ctx.api = api;
  fill_ctx.remaining = 1;
  gum_darwin_enumerate_exports (self->task, ZED_SYSTEM_LIBC, zed_fill_function_if_matching, &fill_ctx);

  if (fill_ctx.remaining > 0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "failed to resolve one or more functions");
    return FALSE;
  }

  return TRUE;
}

#define ZED_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING(field) \
  if (strcmp (name, G_STRINGIFY (field)) == 0) \
  { \
    ctx->api->field##_impl = address; \
    ctx->remaining--; \
    return ctx->remaining != 0; \
  }

static gboolean
zed_fill_function_if_matching (const gchar * name,
                               GumAddress address,
                               gpointer user_data)
{
  ZedFillContext * ctx = user_data;

  ZED_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_task_self);
  ZED_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_port_allocate);
  ZED_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_port_deallocate);
  ZED_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_msg);
  ZED_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (abort);

  return TRUE;
}

#ifdef HAVE_ARM

static gboolean
zed_spawn_instance_emit_redirect_code (ZedSpawnInstance * self, guint8 * code, guint * code_size, GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not yet implemented for ARM");
  return FALSE;
}

static gboolean
zed_spawn_instance_emit_sync_code (ZedSpawnInstance * self, const ZedRemoteApi * api, guint8 * code, guint * code_size, GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not yet implemented for ARM");
  return FALSE;
}

#else

static gboolean
zed_spawn_instance_emit_redirect_code (ZedSpawnInstance * self, guint8 * code, guint * code_size, GError ** error)
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
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, self->payload_address + ZED_CODE_OFFSET);
  gum_x86_writer_put_jmp_reg (&cw, GUM_REG_XAX);

  gum_x86_writer_flush (&cw);
  *code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_free (&cw);

  return TRUE;
}

static gboolean
zed_spawn_instance_emit_sync_code (ZedSpawnInstance * self, const ZedRemoteApi * api, guint8 * code, guint * code_size, GError ** error)
{
  GumX86Writer cw;
  gconstpointer panic_label = "zed_spawn_instance_panic";

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
  gum_x86_writer_put_mov_reg_reg_ptr (&cw, GUM_REG_EBP, GUM_REG_RBP);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX); /* release space */

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, api->mach_msg_impl);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, self->payload_address + ZED_DATA_OFFSET);

  /* xbx->header.msgh_local_port = *xbp; */
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_XBX, G_STRUCT_OFFSET (ZedSpawnMessageTx, header.msgh_local_port), GUM_REG_EBP);

  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX, 7,
      GUM_ARG_REGISTER, GUM_REG_XBX,                                    /* header           */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (MACH_SEND_MSG | MACH_RCV_MSG), /* flags            */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (sizeof (ZedSpawnMessageTx)),   /* send size        */
      GUM_ARG_POINTER, GSIZE_TO_POINTER (sizeof (ZedSpawnMessageRx)),   /* max receive size */
      GUM_ARG_REGISTER, GUM_REG_RBP,                                    /* receive port     */
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
      GUM_ARG_REGISTER, GUM_REG_RBP);

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

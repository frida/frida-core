#include "frida-core.h"

#include "icon-helpers.h"

#include <dispatch/dispatch.h>
#include <errno.h>
#ifdef HAVE_ARM
# include <gum/arch-arm/gumthumbwriter.h>
#else
# include <gum/arch-x86/gumx86writer.h>
#endif
#include <gum/gum.h>
#include <gum/gumdarwin.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <string.h>

#define FRIDA_SYSTEM_LIBC         "/usr/lib/libSystem.B.dylib"

#define FRIDA_PAGE_SIZE           (4096)
#define FRIDA_CODE_OFFSET         (0 * FRIDA_PAGE_SIZE)
#define FRIDA_DATA_OFFSET         (1 * FRIDA_PAGE_SIZE)
#define FRIDA_PAYLOAD_SIZE        (2 * FRIDA_PAGE_SIZE)

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }

typedef struct _FridaDarwinHostContext FridaDarwinHostContext;
typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaSpawnMessageTx FridaSpawnMessageTx;
typedef struct _FridaSpawnMessageRx FridaSpawnMessageRx;
typedef struct _FridaRemoteApi FridaRemoteApi;
typedef struct _FridaFillContext FridaFillContext;

struct _FridaDarwinHostContext
{
  dispatch_queue_t dispatch_queue;
};

struct _FridaSpawnInstance
{
  FridaDarwinHostSession * host_session;
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

struct _FridaSpawnMessageTx
{
  mach_msg_header_t header;
};

struct _FridaSpawnMessageRx
{
  mach_msg_header_t header;
  mach_msg_trailer_t trailer;
};

struct _FridaRemoteApi
{
  GumAddress mach_task_self_impl;
  GumAddress mach_port_allocate_impl;
  GumAddress mach_port_deallocate_impl;
  GumAddress mach_msg_impl;
  GumAddress abort_impl;
};

struct _FridaFillContext
{
  FridaRemoteApi * api;
  guint remaining;
};

static FridaSpawnInstance * frida_spawn_instance_new (FridaDarwinHostSession * host_session);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static void frida_spawn_instance_on_task_dead (void * context);
static void frida_spawn_instance_on_server_recv (void * context);

static gboolean frida_spawn_instance_find_remote_api (FridaSpawnInstance * self, FridaRemoteApi * api, GError ** error);
static gboolean frida_fill_function_if_matching (const GumExportDetails * details, gpointer user_data);

static gboolean frida_spawn_instance_emit_redirect_code (FridaSpawnInstance * self, guint8 * code, guint * code_size, GError ** error);
static gboolean frida_spawn_instance_emit_sync_code (FridaSpawnInstance * self, const FridaRemoteApi * api, guint8 * code, guint * code_size, GError ** error);

#ifdef HAVE_MAC

typedef struct _FridaMacModel FridaMacModel;

struct _FridaMacModel
{
  const gchar * name;
  const gchar * icon;
};

static const FridaMacModel mac_models[] =
{
  { NULL,         "com.apple.led-cinema-display-27" },
  { "MacBookAir", "com.apple.macbookair-11-unibody" },
  { "MacBookPro", "com.apple.macbookpro-13-unibody" },
  { "MacBook",    "com.apple.macbook-unibody" },
  { "iMac",       "com.apple.imac-unibody-21" },
  { "Macmini",    "com.apple.macmini-unibody" },
  { "MacPro",     "com.apple.macpro" }
};

#endif

FridaImageData *
_frida_darwin_host_session_provider_extract_icon (void)
{
#ifdef HAVE_MAC
  size_t size;
  gchar * model_name;
  const FridaMacModel * model;
  guint i;
  gchar * filename;
  FridaImageData * icon;

  size = 0;
  sysctlbyname ("hw.model", NULL, &size, NULL, 0);
  model_name = g_malloc (size);
  sysctlbyname ("hw.model", model_name, &size, NULL, 0);

  for (model = NULL, i = 1; i != G_N_ELEMENTS (mac_models) && model == NULL; i++)
  {
    if (g_str_has_prefix (model_name, mac_models[i].name))
      model = &mac_models[i];
  }
  if (model == NULL)
    model = &mac_models[0];

  filename = g_strconcat ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/", model->icon, ".icns", NULL);
  icon = _frida_image_data_from_file (filename, 16, 16);
  g_free (filename);

  g_free (model_name);

  return icon;
#else
  return NULL;
#endif
}

void
_frida_darwin_host_session_create_context (FridaDarwinHostSession * self)
{
  FridaDarwinHostContext * ctx;

  ctx = g_slice_new (FridaDarwinHostContext);
  ctx->dispatch_queue = dispatch_queue_create (
      "org.boblycat.frida.darwin-host-session.queue", NULL);

  self->context = ctx;
}

void
_frida_darwin_host_session_destroy_context (FridaDarwinHostSession * self)
{
  FridaDarwinHostContext * ctx = self->context;

  dispatch_release (ctx->dispatch_queue);

  g_slice_free (FridaDarwinHostContext, ctx);
}

guint
_frida_darwin_host_session_do_spawn (FridaDarwinHostSession * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  FridaDarwinHostContext * ctx = self->context;
  FridaSpawnInstance * instance;
  pid_t pid;
  posix_spawnattr_t attr;
  sigset_t signal_mask_set;
  int result;
  const gchar * failed_operation;
  kern_return_t ret;
  mach_port_name_t task;
  FridaRemoteApi api;
  vm_address_t payload_address = (vm_address_t) NULL;
  guint8 redirect_code[512];
  guint redirect_code_size;
  guint8 sync_code[512];
  guint sync_code_size;
  FridaSpawnMessageTx msg;
  mach_port_name_t name;
  dispatch_source_t source;

  instance = frida_spawn_instance_new (self);

  posix_spawnattr_init (&attr);
  sigemptyset (&signal_mask_set);
  posix_spawnattr_setsigmask (&attr, &signal_mask_set);
  posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_START_SUSPENDED);

  result = posix_spawn (&pid, path, NULL, &attr, argv, envp);

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

  ret = vm_allocate (task, &payload_address, FRIDA_PAYLOAD_SIZE, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");
  instance->payload_address = payload_address;

  if (!frida_spawn_instance_emit_redirect_code (instance, redirect_code, &redirect_code_size, error))
    goto error_epilogue;
  instance->overwritten_code = gum_darwin_read (task, instance->entrypoint, redirect_code_size, NULL);
  instance->overwritten_code_size = redirect_code_size;
  ret = vm_protect (task, instance->entrypoint, redirect_code_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");
  ret = vm_write (task, instance->entrypoint, (vm_offset_t) redirect_code, redirect_code_size);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(redirect_code)");
  ret = vm_protect (task, instance->entrypoint, redirect_code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  if (!frida_spawn_instance_emit_sync_code (instance, &api, sync_code, &sync_code_size, error))
    goto error_epilogue;
  ret = vm_write (task, payload_address + FRIDA_CODE_OFFSET, (vm_offset_t) sync_code, sync_code_size);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(sync_code)");

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
  ret = vm_write (task, payload_address + FRIDA_DATA_OFFSET, (vm_offset_t) &msg, sizeof (msg));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write(data)");

  ret = vm_protect (task, payload_address + FRIDA_CODE_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  ret = vm_protect (task, payload_address + FRIDA_DATA_OFFSET, FRIDA_PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_pid), GUINT_TO_POINTER (pid), instance);

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

handle_spawn_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "posix_spawn failed: %s (%d)", strerror (errno), errno);
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
    frida_spawn_instance_free (instance);
    return 0;
  }
}

void
_frida_darwin_host_session_resume_instance (FridaDarwinHostSession * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_darwin_host_session_free_instance (FridaDarwinHostSession * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaDarwinHostSession * host_session)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
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
  g_object_unref (instance->host_session);

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

  _frida_darwin_host_session_on_instance_dead (self->host_session, self->pid);
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

  vm_protect (self->task, self->entrypoint, self->overwritten_code_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  vm_write (self->task, self->entrypoint, (vm_offset_t) self->overwritten_code, self->overwritten_code_size);
  vm_protect (self->task, self->entrypoint, self->overwritten_code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

  _frida_darwin_host_session_on_instance_ready (self->host_session, self->pid);
}

static gboolean
frida_spawn_instance_find_remote_api (FridaSpawnInstance * self, FridaRemoteApi * api, GError ** error)
{
  FridaFillContext fill_ctx;

  fill_ctx.api = api;
  fill_ctx.remaining = 1;
  gum_darwin_enumerate_exports (self->task, FRIDA_SYSTEM_LIBC, frida_fill_function_if_matching, &fill_ctx);

  if (fill_ctx.remaining > 0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "failed to resolve one or more functions");
    return FALSE;
  }

  return TRUE;
}

#define FRIDA_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING(field) \
  if (strcmp (details->name, G_STRINGIFY (field)) == 0) \
  { \
    ctx->api->field##_impl = details->address; \
    ctx->remaining--; \
    return ctx->remaining != 0; \
  }

static gboolean
frida_fill_function_if_matching (const GumExportDetails * details,
                                 gpointer user_data)
{
  FridaFillContext * ctx = user_data;

  if (details->type != GUM_EXPORT_FUNCTION)
    return TRUE;

  FRIDA_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_task_self);
  FRIDA_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_port_allocate);
  FRIDA_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_port_deallocate);
  FRIDA_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (mach_msg);
  FRIDA_REMOTE_API_ASSIGN_AND_RETURN_IF_MATCHING (abort);

  return TRUE;
}

#ifdef HAVE_ARM

static gboolean
frida_spawn_instance_emit_redirect_code (FridaSpawnInstance * self, guint8 * code, guint * code_size, GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not yet implemented for ARM");
  return FALSE;
}

static gboolean
frida_spawn_instance_emit_sync_code (FridaSpawnInstance * self, const FridaRemoteApi * api, guint8 * code, guint * code_size, GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "not yet implemented for ARM");
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
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX, self->payload_address + FRIDA_CODE_OFFSET);
  gum_x86_writer_put_jmp_reg (&cw, GUM_REG_XAX);

  gum_x86_writer_flush (&cw);
  *code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_free (&cw);

  return TRUE;
}

static gboolean
frida_spawn_instance_emit_sync_code (FridaSpawnInstance * self, const FridaRemoteApi * api, guint8 * code, guint * code_size, GError ** error)
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
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XBX, self->payload_address + FRIDA_DATA_OFFSET);

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

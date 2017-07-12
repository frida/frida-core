#include "server-ios.h"

/*
 * Regenerate with:
 *
 * $(xcrun --sdk macosx -f mig) \
 *     -sheader server-ios-jit.h \
 *     -server server-ios-jit.c \
 *     -header server-ios-jit-user.h \
 *     -user server-ios-jit-user.c \
 *     server-ios-jit.defs
 */
#include "server-ios-jit.h"

#include <gum/gum.h>
#include <gum/gumdarwin.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <unistd.h>

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

typedef struct _FridaJitRequest FridaJitRequest;

struct _FridaJitRequest
{
  union __RequestUnion__frida_jit_subsystem body;
  mach_msg_trailer_t trailer;
};

int memorystatus_control (uint32_t command, int32_t pid, uint32_t flags, void * buffer, size_t buffer_size);
kern_return_t bootstrap_check_in (mach_port_t bp, const char * service_name, mach_port_t * sp);

static gpointer frida_jit_server_process_messages (gpointer data);
static gboolean frida_jit_server_get_region (mach_vm_address_t * jit_base, mach_vm_size_t * jit_size);

void
_frida_server_ios_configure (void)
{
  mach_port_t listening_port;
  kern_return_t kr;

  memorystatus_control (MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid (), 256, NULL, 0);

  kr = bootstrap_check_in (bootstrap_port, "com.apple.uikit.viewservice.frida", &listening_port);
  if (kr != KERN_SUCCESS)
    goto checkin_error;

  g_thread_unref (g_thread_new ("jit-server", frida_jit_server_process_messages, GSIZE_TO_POINTER (listening_port)));

  return;

checkin_error:
  {
    g_info ("Unable to check in with launchd: are we running standalone?");
    return;
  }
}

static gpointer
frida_jit_server_process_messages (gpointer data)
{
  mach_port_t listening_port = GPOINTER_TO_SIZE (data);
  FridaJitRequest request;
  union __ReplyUnion__frida_jit_subsystem reply;
  mach_msg_header_t * header_in, * header_out;
  kern_return_t kr;
  boolean_t handled;

  while (TRUE)
  {
    bzero (&request, sizeof (request));

    header_in = (mach_msg_header_t *) &request;
    header_in->msgh_size = sizeof (request);
    header_in->msgh_local_port = listening_port;

    kr = mach_msg_receive (header_in);
    if (kr != KERN_SUCCESS)
      continue;

    header_out = (mach_msg_header_t *) &reply;

    handled = frida_jit_server (header_in, header_out);
    if (!handled)
      continue;

    mach_msg_send (header_out);
  }

  return NULL;
}

kern_return_t
frida_jit_alloc (mach_port_t server, vm_task_entry_t task, mach_vm_address_t * address, mach_vm_size_t size, int flags)
{
  mach_vm_address_t jit_base;
  mach_vm_size_t jit_size;
  kern_return_t kr;
  mach_vm_offset_t region_offset;

  if (!frida_jit_server_get_region (&jit_base, &jit_size))
    return KERN_FAILURE;

  kr = mach_vm_allocate (task, address, size, flags);
  if (kr != KERN_SUCCESS)
    return kr;

  region_offset = 0;

  do
  {
    mach_vm_address_t region_base;
    mach_vm_size_t region_size;
    vm_prot_t cur_protection, max_protection;

    region_base = *address + region_offset;
    region_size = MIN (size - region_offset, jit_size);

    kr = mach_vm_remap (task, &region_base, region_size, 0, VM_FLAGS_OVERWRITE,
        mach_task_self (), jit_base, TRUE, &cur_protection, &max_protection,
        VM_INHERIT_COPY);
    if (kr != KERN_SUCCESS)
    {
      mach_vm_deallocate (task, *address, size);
      return kr;
    }

    region_offset += region_size;
  }
  while (region_offset != size);

  return KERN_SUCCESS;
}

static gboolean
frida_jit_server_get_region (mach_vm_address_t * jit_base, mach_vm_size_t * jit_size)
{
  static gsize initialized = FALSE;
  static mach_vm_address_t cached_base = 0;
  static mach_vm_size_t cached_size = 0;

  if (g_once_init_enter (&initialized))
  {
    gsize size;
    gpointer base;

    size = 1027 * gum_query_page_size (); /* Stalker likes this size */
    base = mmap (NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_JIT | MAP_PRIVATE, 0, 0);
    if (base != MAP_FAILED)
    {
      cached_base = (mach_vm_address_t) base;
      cached_size = size;
    }
    else
    {
      g_info ("Unable to allocate JIT page: missing entitlements?");
    }

    g_once_init_leave (&initialized, TRUE);
  }

  *jit_base = cached_base;
  *jit_size = cached_size;

  return cached_base != 0;
}

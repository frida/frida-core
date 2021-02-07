#include "jitd.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/param.h>

#ifdef HAVE_MACOS
# include <mach/mach_vm.h>
#else
# include <frida_mach_vm.h>
#endif

typedef struct _FridaJitdRequest FridaJitdRequest;

struct _FridaJitdRequest
{
  union __RequestUnion__frida_jitd_subsystem body;
  mach_msg_trailer_t trailer;
};

extern kern_return_t bootstrap_register (mach_port_t bp, const char * service_name, mach_port_t sp);

#define frida_jitd_mark frida_jitd_do_mark
#include "jitd-server.c"

static mach_vm_address_t jit_base;
static const mach_vm_size_t jit_size = 4 * 1024 * 1024;

int
main (int argc, char * argv[])
{
  void * mmap_result;
  kern_return_t kr;
  mach_port_t listening_port;

  mmap_result = mmap (NULL, jit_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
  if (mmap_result == MAP_FAILED)
    goto jit_error;
  jit_base = (mach_vm_address_t) mmap_result;

  kr = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &listening_port);
  assert (kr == KERN_SUCCESS);

  kr = bootstrap_register (bootstrap_port, FRIDA_JITD_SERVICE_NAME, listening_port);
  if (kr != KERN_SUCCESS)
    goto checkin_error;

  while (TRUE)
  {
    FridaJitdRequest request;
    union __ReplyUnion__frida_jitd_subsystem reply;
    mach_msg_header_t * header_in, * header_out;
    boolean_t handled;

    bzero (&request, sizeof (request));

    header_in = (mach_msg_header_t *) &request;
    header_in->msgh_size = sizeof (request);
    header_in->msgh_local_port = listening_port;

    kr = mach_msg_receive (header_in);
    if (kr != KERN_SUCCESS)
      break;

    header_out = (mach_msg_header_t *) &reply;

    handled = frida_jitd_server (header_in, header_out);
    if (handled)
      mach_msg_send (header_out);

    mach_msg_destroy (header_in);
  }

  return 0;

jit_error:
  {
    fputs ("Unable to mmap() w/ MAP_JIT: missing entitlement?\n", stderr);
    return 1;
  }
checkin_error:
  {
    fputs ("Unable to check in with launchd: are we running standalone?\n", stderr);
    return 2;
  }
}

kern_return_t
frida_jitd_do_mark (mach_port_t server, vm_map_t task, mach_vm_address_t source_address, mach_vm_size_t source_size,
    mach_vm_address_t * target_address)
{
  size_t page_size, vm_size;
  kern_return_t kr;
  boolean_t target_allocated = FALSE;
  mach_vm_offset_t region_offset;

  page_size = getpagesize ();

  /* XXX: drop this and use source_size */
  vm_size = (source_size + page_size - 1) & ~(page_size - 1);

  fprintf (stderr, "\n*** source_address=0x%llx source_size=%llu vm_size=%zu *target_address=0x%llx\n", source_address, source_size, vm_size, *target_address);

  if (*target_address == 0)
  {
    kr = mach_vm_allocate (task, target_address, vm_size, VM_FLAGS_ANYWHERE);
    fprintf (stderr, "mach_vm_allocate() kr=%d *target_address=0x%llx\n", kr, *target_address);
    if (kr != KERN_SUCCESS)
      goto propagate_mach_failure;
    target_allocated = TRUE;
  }

  region_offset = 0;

  do
  {
    mach_vm_address_t region_base;
    mach_vm_size_t region_size;
    mach_vm_size_t n;
    vm_prot_t cur_protection, max_protection;

    region_base = *target_address + region_offset;
    region_size = MIN (source_size - region_offset, jit_size);

    kr = mach_vm_read_overwrite (task, source_address + region_offset, region_size, jit_base, &n);
    fprintf (stderr, "mach_vm_read_overwrite() kr=%d\n", kr);
    if (kr != KERN_SUCCESS)
      goto propagate_mach_failure;

    sys_icache_invalidate ((void *) jit_base, region_size);
    sys_dcache_flush ((void *) jit_base, region_size);

    kr = mach_vm_remap (task, &region_base, region_size, 0, VM_FLAGS_OVERWRITE, mach_task_self (),
        jit_base, TRUE, &cur_protection, &max_protection, VM_INHERIT_COPY);
    fprintf (stderr, "mach_vm_remap() kr=%d\n", kr);
    if (kr != KERN_SUCCESS)
      goto propagate_mach_failure;

    kr = mach_vm_protect (task, region_base, region_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    fprintf (stderr, "mach_vm_protect() kr=%d\n", kr);
    if (kr != KERN_SUCCESS)
      goto propagate_mach_failure;

    region_offset += region_size;
  }
  while (region_offset != source_size);

  fprintf (stderr, "yay\n");

  return KERN_SUCCESS;

propagate_mach_failure:
  {
    if (target_allocated)
      mach_vm_deallocate (task, *target_address, vm_size);

    return kr;
  }
}


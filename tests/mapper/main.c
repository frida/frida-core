#ifdef HAVE_DARWIN

#include "mapper.h"

#include <glib.h>
#include <mach/mach.h>

typedef void (* UnixAttackerEntrypoint) (const gchar * data_string);

int
main (int argc, char * argv[])
{
  FridaMapper mapper;
  mach_port_name_t task;
  mach_vm_address_t base_address = 0;
  kern_return_t kr;
  UnixAttackerEntrypoint entrypoint;

#if GLIB_CHECK_VERSION (2, 42, 0)
  glib_init ();
#endif

  if (argc != 2)
  {
    g_printerr ("usage: %s <dylib_path>\n", argv[0]);
    return 1;
  }

  frida_mapper_init (&mapper, argv[1]);

  task = mach_task_self ();

  kr = mach_vm_allocate (task, &base_address, frida_mapper_size (&mapper), VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  frida_mapper_map (&mapper, task, base_address);

  entrypoint = (UnixAttackerEntrypoint) (base_address + frida_mapper_resolve (&mapper, "frida_agent_main"));
  entrypoint ("");

  kr = mach_vm_deallocate (task, base_address, frida_mapper_size (&mapper));
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  frida_mapper_free (&mapper);

  return 0;
}

#include "mapper.c"

#else

int
main (int argc, char * argv[])
{
  return 0;
}

#endif

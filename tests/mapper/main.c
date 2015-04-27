#ifdef HAVE_DARWIN

#include "mapper.h"

#include <glib.h>
#include <mach/mach.h>

typedef void (* UnixAttackerEntrypoint) (const gchar * data_string);

gint
main (gint argc, gchar * argv[])
{
  const gchar * dylib_path;
  mach_port_name_t task;
  GumCpuType cpu_type;
  FridaMapper * mapper;
  mach_vm_address_t base_address = 0;
  kern_return_t kr;
  FridaMapperConstructor constructor;
  FridaMapperDestructor destructor;
  UnixAttackerEntrypoint entrypoint;

#if GLIB_CHECK_VERSION (2, 46, 0)
  glib_init ();
#endif

  if (argc != 2)
  {
    g_printerr ("usage: %s <dylib_path>\n", argv[0]);
    return 1;
  }

  dylib_path = argv[1];
  task = mach_task_self ();
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  cpu_type = GUM_CPU_IA32;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  cpu_type = GUM_CPU_AMD64;
#elif defined (HAVE_ARM)
  cpu_type = GUM_CPU_ARM;
#elif defined (HAVE_ARM64)
  cpu_type = GUM_CPU_ARM64;
#else
# error Unsupported CPU type
#endif

  mapper = frida_mapper_new (dylib_path, task, cpu_type);

  kr = mach_vm_allocate (task, &base_address, frida_mapper_size (mapper), VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  frida_mapper_map (mapper, base_address);

  constructor = (FridaMapperConstructor) frida_mapper_constructor (mapper);
  destructor = (FridaMapperDestructor) frida_mapper_destructor (mapper);
  entrypoint = (UnixAttackerEntrypoint) frida_mapper_resolve (mapper, "frida_agent_main");

  constructor ();
  entrypoint ("");
  destructor ();

  kr = mach_vm_deallocate (task, base_address, frida_mapper_size (mapper));
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  frida_mapper_free (mapper);

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

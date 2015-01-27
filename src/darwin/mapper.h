#ifndef __FRIDA_DARWIN_MAPPER_H__
#define __FRIDA_DARWIN_MAPPER_H__

#include <gum/gumdarwin.h>

typedef struct _FridaMapper FridaMapper;

struct _FridaMapper
{
  GBytes * bytes;
  GumCpuType cpu_type;
  gsize page_size;
  const struct mach_header * header_32;
  const struct mach_header_64 * header_64;
  const struct load_command * load_commands;
  gsize load_command_count;
  gsize mapped_size;
};

void frida_mapper_init (FridaMapper * mapper, const gchar * dylib_path, GumCpuType cpu_type);
void frida_mapper_free (FridaMapper * mapper);

gsize frida_mapper_size (FridaMapper * self);
void frida_mapper_map (FridaMapper * self, mach_port_t task, mach_vm_address_t base_address);
gsize frida_mapper_resolve (FridaMapper * self, const gchar * symbol);

#endif

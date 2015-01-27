#ifndef __FRIDA_DARWIN_MAPPER_H__
#define __FRIDA_DARWIN_MAPPER_H__

#include <gum/gumdarwin.h>

typedef struct _FridaMapper FridaMapper;

struct _FridaMapper
{
  GMappedFile * file;
  GBytes * bytes;
  gconstpointer data;
};

void frida_mapper_init (FridaMapper * mapper, const gchar * dylib_path);
void frida_mapper_free (FridaMapper * mapper);

gsize frida_mapper_size (FridaMapper * self);
void frida_mapper_map (FridaMapper * self, mach_port_t task, mach_vm_address_t base_address);
gsize frida_mapper_resolve (FridaMapper * self, const gchar * symbol);

#endif

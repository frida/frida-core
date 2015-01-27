#include "mapper.h"

void
frida_mapper_init (FridaMapper * mapper, const gchar * dylib_path)
{
  mapper->file = g_mapped_file_new (dylib_path, FALSE, NULL);
  g_assert (mapper->file != NULL);

  mapper->bytes = g_mapped_file_get_bytes (mapper->file);

  mapper->data = g_bytes_get_data (mapper->bytes, NULL);
}

void
frida_mapper_free (FridaMapper * mapper)
{
  g_bytes_unref (mapper->bytes);
  mapper->bytes = NULL;

  g_mapped_file_unref (mapper->file);
  mapper->file = NULL;
}

gsize
frida_mapper_size (FridaMapper * self)
{
  return 4096; /* TODO */
}

void
frida_mapper_map (FridaMapper * self, mach_port_t task, mach_vm_address_t base_address)
{
  /* TODO */
}

gsize
frida_mapper_resolve (FridaMapper * self, const gchar * symbol)
{
  return 0; /* TODO */
}

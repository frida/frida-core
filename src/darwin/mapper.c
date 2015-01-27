#include "mapper.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>

void
frida_mapper_init (FridaMapper * mapper, const gchar * dylib_path, GumCpuType cpu_type)
{
  GMappedFile * file;
  gconstpointer data;
  const struct fat_header * fat_header;

  file = g_mapped_file_new (dylib_path, FALSE, NULL);
  g_assert (file != NULL);

  mapper->bytes = g_mapped_file_get_bytes (file);

  g_mapped_file_unref (file);

  mapper->cpu_type = cpu_type;

  mapper->header_32 = NULL;
  mapper->header_64 = NULL;

  data = g_bytes_get_data (mapper->bytes, NULL);
  fat_header = data;
  switch (fat_header->magic)
  {
    case FAT_CIGAM:
    {
      uint32_t count, i;

      count = OSSwapInt32 (fat_header->nfat_arch);
      for (i = 0; i != count; i++)
      {
        struct fat_arch * fat_arch = ((struct fat_arch *) (fat_header + 1)) + i;
        gconstpointer mach_header = data + OSSwapInt32 (fat_arch->offset);
        switch (((struct mach_header *) mach_header)->magic)
        {
          case MH_MAGIC:
            mapper->header_32 = mach_header;
            break;
          case MH_MAGIC_64:
            mapper->header_64 = mach_header;
            break;
          default:
            g_assert_not_reached ();
            break;
        }
      }
    }
    case MH_MAGIC:
      mapper->header_32 = data;
      break;
    case MH_MAGIC_64:
      mapper->header_64 = data;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  if (cpu_type == GUM_CPU_IA32 || cpu_type == GUM_CPU_ARM)
    g_assert (mapper->header_32 != NULL);

  if (cpu_type == GUM_CPU_AMD64 || cpu_type == GUM_CPU_ARM64)
    g_assert (mapper->header_64 != NULL);
}

void
frida_mapper_free (FridaMapper * mapper)
{
  g_bytes_unref (mapper->bytes);
  mapper->bytes = NULL;
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

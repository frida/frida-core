#include "mapper.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

void
frida_mapper_init (FridaMapper * mapper, const gchar * dylib_path, GumCpuType cpu_type)
{
  GMappedFile * file;
  gconstpointer data;
  const struct fat_header * fat_header;
  gconstpointer p;
  gsize i;

  memset (mapper, 0, sizeof (FridaMapper));

  file = g_mapped_file_new (dylib_path, FALSE, NULL);
  g_assert (file != NULL);

  mapper->bytes = g_mapped_file_get_bytes (file);

  g_mapped_file_unref (file);

  mapper->cpu_type = cpu_type;
  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM:
      mapper->page_size = 4096;
      break;
    case GUM_CPU_ARM64:
      mapper->page_size = 16384;
      break;
  }

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

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_ARM:
      g_assert (mapper->header_32 != NULL);
      mapper->header = mapper->header_32;
      mapper->header_64 = NULL;
      mapper->commands = (const struct load_command *) (mapper->header_32 + 1);
      mapper->command_count = mapper->header_32->ncmds;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      g_assert (mapper->header_64 != NULL);
      mapper->header = mapper->header_64;
      mapper->header_32 = NULL;
      mapper->commands = (const struct load_command *) (mapper->header_64 + 1);
      mapper->command_count = mapper->header_64->ncmds;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  p = mapper->commands;
  for (i = 0; i != mapper->command_count; i++)
  {
    const struct load_command * lc = p;

    switch (lc->cmd)
    {
      case LC_SYMTAB:
        mapper->symtab = p;
        break;
      case LC_DYSYMTAB:
        mapper->dysymtab = p;
        break;
      default:
        break;
    }

    p += lc->cmdsize;
  }
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
  gconstpointer p;
  gsize i;

  if (self->mapped_size != 0)
    return self->mapped_size;

  p = self->commands;
  for (i = 0; i != self->command_count; i++)
  {
    const struct load_command * lc = (const struct load_command *) p;

    switch (lc->cmd)
    {
      case LC_SEGMENT:
      {
        struct segment_command * sc = (struct segment_command *) lc;
        self->mapped_size += sc->vmsize;
        if (sc->vmsize % self->page_size != 0)
          self->mapped_size += self->page_size - (sc->vmsize % self->page_size);
        break;
      }
      case LC_SEGMENT_64:
      {
        struct segment_command_64 * sc = (struct segment_command_64 *) lc;
        self->mapped_size += sc->vmsize;
        if (sc->vmsize % self->page_size != 0)
          self->mapped_size += self->page_size - (sc->vmsize % self->page_size);
        break;
      }
      default:
        break;
    }

    p += lc->cmdsize;
  }

  return self->mapped_size;
}

void
frida_mapper_map (FridaMapper * self, mach_port_t task, mach_vm_address_t base_address)
{
  gconstpointer p;
  gsize i;

  p = self->commands;
  for (i = 0; i != self->command_count; i++)
  {
    const struct load_command * lc = (const struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      mach_vm_address_t vm_address;
      mach_vm_size_t vm_size;
      GumAddress file_offset, file_size;
      vm_prot_t protection;

      if (lc->cmd == LC_SEGMENT)
      {
        struct segment_command * sc = (struct segment_command *) lc;
        vm_address = sc->vmaddr;
        vm_size = sc->vmsize;
        file_offset = sc->fileoff;
        file_size = sc->filesize;
        protection = sc->initprot;
      }
      else
      {
        struct segment_command_64 * sc = (struct segment_command_64 *) lc;
        vm_address = sc->vmaddr;
        vm_size = sc->vmsize;
        file_offset = sc->fileoff;
        file_size = sc->filesize;
        protection = sc->initprot;
      }

      mach_vm_write (task, base_address + vm_address, (vm_offset_t) self->header + file_offset, file_size);

      mach_vm_protect (task, base_address + vm_address, vm_size, FALSE, protection);
    }

    p += lc->cmdsize;
  }
}

GumAddress
frida_mapper_resolve (FridaMapper * self, const gchar * symbol)
{
  const struct symtab_command * st = self->symtab;
  const struct dysymtab_command * ds = self->dysymtab;
  gconstpointer symbase, strbase;
  gsize i;

  symbase = self->header + st->symoff;
  strbase = self->header + st->stroff;

  for (i = ds->iextdefsym; i != ds->iextdefsym + ds->nextdefsym; i++)
  {
    const gchar * name;
    GumAddress address;

    if (self->header_32 != NULL)
    {
      const struct nlist * sym = symbase + (i * sizeof (struct nlist));
      name = strbase + sym->n_un.n_strx;
      address = sym->n_value;
    }
    else
    {
      const struct nlist_64 * sym = symbase + (i * sizeof (struct nlist_64));
      name = strbase + sym->n_un.n_strx;
      address = sym->n_value;
    }

    if (name[0] == '_')
      name++;

    if (strcmp (name, symbol) == 0)
      return address;
  }

  return 0;
}

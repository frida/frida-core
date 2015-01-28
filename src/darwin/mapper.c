#include "mapper.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

static GumAddress frida_mapper_segment_start (FridaMapper * self, gsize index, mach_vm_address_t base_address);
static GumAddress frida_mapper_segment_end (FridaMapper * self, gsize index, mach_vm_address_t base_address);

static guint64 frida_mapper_read_uleb128 (const guint8 ** p);

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
      mapper->pointer_size = 4;
      mapper->page_size = 4096;
      break;
    case GUM_CPU_AMD64:
      mapper->pointer_size = 8;
      mapper->page_size = 4096;
      break;
    case GUM_CPU_ARM:
      mapper->pointer_size = 4;
      mapper->page_size = 4096;
      break;
    case GUM_CPU_ARM64:
      mapper->pointer_size = 8;
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
      case LC_DYLD_INFO_ONLY:
        mapper->info = p;
        break;
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

  {
    const guint8 * start = self->header + self->info->bind_off;
    const guint8 * end = start + self->info->bind_size;
    const guint8 * p = start;
    gboolean done = FALSE;

    guint8 type = 0;
    gint segment_index = 0;
    GumAddress address = frida_mapper_segment_start (self, 0, base_address);
    GumAddress segment_end = frida_mapper_segment_end (self, 0, base_address);
    const gchar * symbol_name = NULL;
    guint8 symbol_flags = 0;
    gint library_ordinal = 0;
    GumAddress addend = 0;

    while (!done && p != end)
    {
      guint8 opcode = *p & BIND_OPCODE_MASK;
      guint8 immediate = *p & BIND_IMMEDIATE_MASK;

      p++;

      switch (opcode)
      {
        case BIND_OPCODE_DONE:
          g_print ("BIND_OPCODE_DONE\n");
          done = TRUE;
          break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
          g_print ("BIND_OPCODE_SET_DYLIB_ORDINAL_IMM\n");
          library_ordinal = immediate;
          break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
          g_print ("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB\n");
          library_ordinal = frida_mapper_read_uleb128 (&p);
          break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
          g_print ("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM\n");
          if (immediate == 0)
          {
            library_ordinal = 0;
          }
          else
          {
            gint8 value = BIND_OPCODE_MASK | immediate;
            library_ordinal = value;
          }
          break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
          g_print ("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM\n");
          symbol_name = (gchar *) p;
          symbol_flags = immediate;
          while (*p != '\0')
            p++;
          p++;
          break;
        case BIND_OPCODE_SET_TYPE_IMM:
          g_print ("BIND_OPCODE_SET_TYPE_IMM\n");
          type = immediate;
          break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
          g_print ("BIND_OPCODE_SET_ADDEND_SLEB\n");
          addend = frida_mapper_read_uleb128 (&p);
          break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
          g_print ("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB\n");
          segment_index = immediate;
          address = frida_mapper_segment_start (self, segment_index, base_address);
          address += frida_mapper_read_uleb128 (&p);
          segment_end = frida_mapper_segment_end (self, segment_index, base_address);
          break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
          g_print ("BIND_OPCODE_ADD_ADDR_ULEB\n");
          address += frida_mapper_read_uleb128 (&p);
          break;
        case BIND_OPCODE_DO_BIND:
          g_print ("BIND_OPCODE_DO_BIND\n");
          /* TODO: bind! */
          address += self->pointer_size;
          break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
          g_print ("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB\n");
          /* TODO: bind! */
          address += self->pointer_size + frida_mapper_read_uleb128 (&p);
          break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
          g_print ("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED\n");
          /* TODO: bind! */
          address += self->pointer_size + (immediate * self->pointer_size);
          break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {
          gsize count, skip;

          g_print ("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB\n");

          count = frida_mapper_read_uleb128 (&p);
          skip = frida_mapper_read_uleb128 (&p);
          for (i = 0; i != count; ++i)
          {
            /* TODO: bind! */
            address += self->pointer_size + skip;
          }

          break;
        }
        default:
          g_assert_not_reached ();
          break;
      }
    }
  }

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

/* TODO: introduce a segment structure and consider doing the parsing just once */

static GumAddress
frida_mapper_segment_start (FridaMapper * self, gsize index, mach_vm_address_t base_address)
{
  gsize current_index, i;
  gconstpointer p;

  p = self->commands;
  current_index = 0;
  for (i = 0; i != self->command_count; i++)
  {
    const struct load_command * lc = (const struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      if (current_index == index)
      {
        if (lc->cmd == LC_SEGMENT)
        {
          struct segment_command * sc = (struct segment_command *) lc;
          return base_address + sc->vmaddr;
        }
        else
        {
          struct segment_command_64 * sc = (struct segment_command_64 *) lc;
          return base_address + sc->vmaddr;
        }
      }
      current_index++;
    }

    p += lc->cmdsize;
  }

  g_assert_not_reached ();
  return 0;
}

static GumAddress
frida_mapper_segment_end (FridaMapper * self, gsize index, mach_vm_address_t base_address)
{
  gsize current_index, i;
  gconstpointer p;

  p = self->commands;
  current_index = 0;
  for (i = 0; i != self->command_count; i++)
  {
    const struct load_command * lc = (const struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      if (current_index == index)
      {
        if (lc->cmd == LC_SEGMENT)
        {
          struct segment_command * sc = (struct segment_command *) lc;
          return base_address + sc->vmaddr + sc->vmsize;
        }
        else
        {
          struct segment_command_64 * sc = (struct segment_command_64 *) lc;
          return base_address + sc->vmaddr + sc->vmsize;
        }
      }
      current_index++;
    }

    p += lc->cmdsize;
  }

  g_assert_not_reached ();
  return 0;
}

static guint64
frida_mapper_read_uleb128 (const guint8 ** data)
{
  const guint8 * p = *data;
  guint64 result = 0;
  gint offset = 0;

  do
  {
    guint64 chunk = *p & 0x7f;

    g_assert_cmpint (offset, <=, 63);
    result |= (chunk << offset);
    offset += 7;
  }
  while (*p++ & 0x80);

  *data = p;

  return result;
}

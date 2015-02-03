#include "mapper.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define MAX_MACH_HEADER_SIZE (64 * 1024)

typedef struct _FridaSegment FridaSegment;
typedef struct _FridaMapping FridaMapping;
typedef struct _FridaBindDetails FridaBindDetails;

struct _FridaLibrary
{
  gint ref_count;
  gchar * name;
  mach_port_t task;
  GumAddress base_address;
  guint8 * exports;
  gsize exports_size;
};

struct _FridaSegment
{
  GumAddress vm_address;
  guint64 vm_size;
  guint64 file_offset;
  guint64 file_size;
  vm_prot_t protection;
};

struct _FridaMapping
{
  gint ref_count;
  FridaLibrary * library;
  FridaMapper * mapper;
};

struct _FridaBindDetails
{
  GumAddress address;
  guint8 type;
  gint library_ordinal;
  const gchar * symbol_name;
  guint8 symbol_flags;
  GumAddress addend;
};

static FridaMapper * frida_mapper_new_with_parent (FridaMapper * parent, const gchar * name, mach_port_t task, GumCpuType cpu_type);

static FridaMapping * frida_mapper_resolve_dependency (FridaMapper * self, const gchar * name, FridaMapper * referrer);
static gboolean frida_mapper_add_existing_mapping_from_module (const GumModuleDetails * details, gpointer user_data);
static FridaMapping * frida_mapper_add_existing_mapping (FridaMapper * self, FridaLibrary * library, GumAddress base_address);
static FridaMapping * frida_mapper_add_pending_mapping (FridaMapper * self, const gchar * name, FridaMapper * mapper);
static void frida_mapper_bind (FridaMapper * self, GumAddress base_address);
static void frida_mapper_do_bind (FridaMapper * self, const FridaBindDetails * details);
static GumAddress frida_mapper_segment_start (FridaMapper * self, gsize index, GumAddress base_address);
static GumAddress frida_mapper_segment_end (FridaMapper * self, gsize index, GumAddress base_address);

static guint64 frida_mapper_read_uleb128 (const guint8 ** p, const guint8 * end);
static void frida_mapper_skip_uleb128 (const guint8 ** p);

static FridaMapping * frida_mapping_ref (FridaMapping * self);
static void frida_mapping_unref (FridaMapping * self);

static FridaLibrary * frida_library_new (const gchar * name, mach_port_t task, GumAddress base_address);
static FridaLibrary * frida_library_ref (FridaLibrary * self);
static void frida_library_unref (FridaLibrary * self);
static const guint8 * frida_library_resolve (FridaLibrary * self, const gchar * symbol);
static gboolean frida_library_load_exports (FridaLibrary * self);

FridaMapper *
frida_mapper_new (const gchar * name, mach_port_t task, GumCpuType cpu_type)
{
  return frida_mapper_new_with_parent (NULL, name, task, cpu_type);
}

static FridaMapper *
frida_mapper_new_with_parent (FridaMapper * parent, const gchar * name, mach_port_t task, GumCpuType cpu_type)
{
  FridaMapper * mapper;
  gpointer data;
  const struct fat_header * fat_header;
  gpointer p;
  gsize i;

  mapper = g_slice_new0 (FridaMapper);

  mapper->parent = parent;

  mapper->file = g_mapped_file_new (name, TRUE, NULL);
  g_assert (mapper->file != NULL);

  mapper->task = task;
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

  data = g_mapped_file_get_contents (mapper->file);
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
        gpointer mach_header = data + OSSwapInt32 (fat_arch->offset);
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
      mapper->commands = (struct load_command *) (mapper->header_32 + 1);
      mapper->command_count = mapper->header_32->ncmds;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      g_assert (mapper->header_64 != NULL);
      mapper->header = mapper->header_64;
      mapper->header_32 = NULL;
      mapper->commands = (struct load_command *) (mapper->header_64 + 1);
      mapper->command_count = mapper->header_64->ncmds;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  mapper->library = frida_library_new (name, task, 0);
  mapper->segments = g_array_new (FALSE, FALSE, sizeof (FridaSegment));
  mapper->dependencies = g_ptr_array_new_full (5, (GDestroyNotify) frida_mapping_unref);

  if (parent == NULL)
  {
    mapper->mappings = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) frida_mapping_unref);
    frida_mapper_add_pending_mapping (mapper, name, mapper);
    gum_darwin_enumerate_modules (task, frida_mapper_add_existing_mapping_from_module, mapper);
  }

  p = mapper->commands;
  for (i = 0; i != mapper->command_count; i++)
  {
    const struct load_command * lc = p;

    switch (lc->cmd)
    {
      case LC_SEGMENT:
      case LC_SEGMENT_64:
      {
        FridaSegment segment;

        if (lc->cmd == LC_SEGMENT)
        {
          struct segment_command * sc = p;
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          struct segment_command_64 * sc = p;
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }

        g_array_append_val (mapper->segments, segment);

        break;
      }
      case LC_LOAD_DYLIB:
      {
        struct dylib_command * dc = p;
        const gchar * name;
        FridaMapping * dependency;

        name = p + dc->dylib.name.offset;
        dependency = frida_mapper_resolve_dependency (mapper, name, mapper);
        g_ptr_array_add (mapper->dependencies, dependency);

        break;
      }
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

  return mapper;
}

void
frida_mapper_free (FridaMapper * mapper)
{
  if (mapper->mappings != NULL)
    g_hash_table_unref (mapper->mappings);

  g_ptr_array_unref (mapper->dependencies);
  g_array_unref (mapper->segments);
  frida_library_unref (mapper->library);

  g_mapped_file_unref (mapper->file);

  g_slice_free (FridaMapper, mapper);
}

static FridaMapping *
frida_mapper_resolve_dependency (FridaMapper * self, const gchar * name, FridaMapper * referrer)
{
  FridaMapping * mapping;

  if (self->parent != NULL)
    return frida_mapper_resolve_dependency (self->parent, name, referrer);

  mapping = g_hash_table_lookup (self->mappings, name);
  if (mapping == NULL)
  {
    FridaMapper * mapper;

    mapper = frida_mapper_new_with_parent (self, name, self->task, self->cpu_type);
    mapping = frida_mapper_add_pending_mapping (self, name, mapper);
  }

  return frida_mapping_ref (mapping);
}

static gboolean
frida_mapper_add_existing_mapping_from_module (const GumModuleDetails * details, gpointer user_data)
{
  FridaMapper * self = user_data;
  GumAddress base_address = details->range->base_address;
  FridaLibrary * library;

  library = frida_library_new (details->path, self->task, base_address);
  frida_mapper_add_existing_mapping (self, library, base_address);
  frida_library_unref (library);

  return TRUE;
}

static FridaMapping *
frida_mapper_add_existing_mapping (FridaMapper * self, FridaLibrary * library, GumAddress base_address)
{
  FridaMapping * mapping;

  mapping = g_slice_new (FridaMapping);
  mapping->library = frida_library_ref (library);
  mapping->mapper = NULL;

  g_hash_table_insert (self->mappings, g_strdup (library->name), mapping);

  return mapping;
}

static FridaMapping *
frida_mapper_add_pending_mapping (FridaMapper * self, const gchar * name, FridaMapper * mapper)
{
  FridaMapping * mapping;

  mapping = g_slice_new (FridaMapping);
  mapping->library = frida_library_ref (mapper->library);
  mapping->mapper = mapper;

  g_hash_table_insert (self->mappings, g_strdup (name), mapping);

  return mapping;
}

gsize
frida_mapper_size (FridaMapper * self)
{
  gsize result = 0;
  guint i;

  for (i = 0; i != self->segments->len; i++)
  {
    FridaSegment * segment = &g_array_index (self->segments, FridaSegment, i);
    result += segment->vm_size;
    if (segment->vm_size % self->page_size != 0)
      result += self->page_size - (segment->vm_size % self->page_size);
  }

  return result;
}

void
frida_mapper_map (FridaMapper * self, GumAddress base_address)
{
  guint i;

  self->library->base_address = base_address;

  frida_mapper_bind (self, base_address);

  for (i = 0; i != self->segments->len; i++)
  {
    FridaSegment * s = &g_array_index (self->segments, FridaSegment, i);

    mach_vm_write (self->task, base_address + s->vm_address, (vm_offset_t) self->header + s->file_offset, s->file_size);

    mach_vm_protect (self->task, base_address + s->vm_address, s->vm_size, FALSE, s->protection);
  }
}

GumAddress
frida_mapper_resolve (FridaMapper * self, FridaLibrary * library, const gchar * symbol)
{
  const guint8 * node;

  if (self->parent != NULL)
    return frida_mapper_resolve (self->parent, library, symbol);

  node = frida_library_resolve (library, symbol);
  g_print ("resolve %s :: %s => %p\n", library->name, symbol, node);

  return 0;
}

static void
frida_mapper_bind (FridaMapper * self, GumAddress base_address)
{
  const guint8 * start = self->header + self->info->bind_off;
  const guint8 * end = start + self->info->bind_size;
  const guint8 * p = start;
  gboolean done = FALSE;

  FridaBindDetails details;
  GumAddress segment_end;

  details.address = frida_mapper_segment_start (self, 0, base_address);
  details.type = 0;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  segment_end = frida_mapper_segment_end (self, 0, base_address);

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
        details.library_ordinal = immediate;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        g_print ("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB\n");
        details.library_ordinal = frida_mapper_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        g_print ("BIND_OPCODE_SET_DYLIB_SPECIAL_IMM\n");
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        g_print ("BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM\n");
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        g_print ("BIND_OPCODE_SET_TYPE_IMM\n");
        details.type = immediate;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        g_print ("BIND_OPCODE_SET_ADDEND_SLEB\n");
        details.addend = frida_mapper_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        g_print ("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB\n");
        details.address = frida_mapper_segment_start (self, segment_index, base_address);
        details.address += frida_mapper_read_uleb128 (&p, end);
        segment_end = frida_mapper_segment_end (self, segment_index, base_address);
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        g_print ("BIND_OPCODE_ADD_ADDR_ULEB\n");
        details.address += frida_mapper_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_print ("BIND_OPCODE_DO_BIND\n");
        g_assert_cmpuint (details.address, <, segment_end);
        frida_mapper_do_bind (self, &details);
        details.address += self->pointer_size;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        g_print ("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB\n");
        g_assert_cmpuint (details.address, <, segment_end);
        frida_mapper_do_bind (self, &details);
        details.address += self->pointer_size + frida_mapper_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        g_print ("BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED\n");
        g_assert_cmpuint (details.address, <, segment_end);
        frida_mapper_do_bind (self, &details);
        details.address += self->pointer_size + (immediate * self->pointer_size);
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        g_print ("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB\n");

        count = frida_mapper_read_uleb128 (&p, end);
        skip = frida_mapper_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert_cmpuint (details.address, <, segment_end);
          frida_mapper_do_bind (self, &details);
          details.address += self->pointer_size + skip;
        }

        break;
      }
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

static void
frida_mapper_do_bind (FridaMapper * self, const FridaBindDetails * details)
{
  FridaMapping * dependency;
  GumAddress address;

  g_assert_cmpint (details->library_ordinal, >=, 1); /* FIXME */
  dependency = g_ptr_array_index (self->dependencies, details->library_ordinal - 1);
  g_print ("bind(address=%p, type=0x%02x, library=%s, symbol_name=%s, symbol_flags=0x%02x, addend=%p)\n",
      (gpointer) details->address, (gint) details->type, dependency->library->name, details->symbol_name, (gint) details->symbol_flags, (gpointer) details->addend);

  address = frida_mapper_resolve (self, dependency->library, details->symbol_name);
  g_print ("  *** %s to %p\n", details->symbol_name, (gpointer) address);
}

static GumAddress
frida_mapper_segment_start (FridaMapper * self, gsize index, GumAddress base_address)
{
  FridaSegment * segment = &g_array_index (self->segments, FridaSegment, index);
  return base_address + segment->vm_address;
}

static GumAddress
frida_mapper_segment_end (FridaMapper * self, gsize index, GumAddress base_address)
{
  FridaSegment * segment = &g_array_index (self->segments, FridaSegment, index);
  return base_address + segment->vm_address + segment->vm_size;
}

static guint64
frida_mapper_read_uleb128 (const guint8 ** data, const guint8 * end)
{
  const guint8 * p = *data;
  guint64 result = 0;
  gint offset = 0;

  do
  {
    guint64 chunk;

    g_assert (p != end);
    g_assert_cmpint (offset, <=, 63);

    chunk = *p & 0x7f;
    result |= (chunk << offset);
    offset += 7;
  }
  while (*p++ & 0x80);

  *data = p;

  return result;
}

static void
frida_mapper_skip_uleb128 (const guint8 ** data)
{
  const guint8 * p = *data;
  while ((*p & 0x80) != 0)
    p++;
  p++;
  *data = p;
}

static FridaMapping *
frida_mapping_ref (FridaMapping * self)
{
  self->ref_count++;
  return self;
}

static void
frida_mapping_unref (FridaMapping * self)
{
  if (--self->ref_count == 0)
  {
    frida_library_unref (self->library);
    g_slice_free (FridaMapping, self);
  }
}

static FridaLibrary *
frida_library_new (const gchar * name, mach_port_t task, GumAddress base_address)
{
  FridaLibrary * library;

  library = g_slice_new0 (FridaLibrary);
  library->ref_count = 1;
  library->name = g_strdup (name);
  library->task = task;
  library->base_address = base_address;

  return library;
}

static FridaLibrary *
frida_library_ref (FridaLibrary * self)
{
  self->ref_count++;
  return self;
}

static void
frida_library_unref (FridaLibrary * self)
{
  if (--self->ref_count == 0)
  {
    g_free (self->name);
    g_slice_free (FridaLibrary, self);
  }
}

static const guint8 *
frida_library_resolve (FridaLibrary * self, const gchar * symbol)
{
  const guint8 * start, * end, * p;

  if (self->exports == NULL)
  {
    if (!frida_library_load_exports (self))
      return NULL;
  }

  start = self->exports;
  end = start + self->exports_size;
  p = start;
  while (p != NULL)
  {
    gint64 terminal_size;
    const guint8 * children;
    guint8 child_count, i;
    guint64 node_offset;

    terminal_size = frida_mapper_read_uleb128 (&p, end);

    if (*symbol == '\0' && terminal_size != 0)
      return p;

    children = p + terminal_size;
    child_count = *children++;
    p = children;
    node_offset = 0;
    for (i = 0; i != child_count; i++)
    {
      const gchar * symbol_cur;
      gboolean matching_edge;

      symbol_cur = symbol;
      matching_edge = TRUE;
      while (*p != '\0')
      {
        if (matching_edge)
        {
          if (*p != *symbol_cur)
            matching_edge = FALSE;
          symbol_cur++;
        }
        p++;
      }
      p++;

      if (matching_edge)
      {
        node_offset = frida_mapper_read_uleb128 (&p, end);
        symbol = symbol_cur;
        break;
      }
      else
      {
        frida_mapper_skip_uleb128 (&p);
      }
    }

    if (node_offset != 0)
      p = start + node_offset;
    else
      p = NULL;
  }

  return NULL;
}

static gboolean
frida_library_load_exports (FridaLibrary * self)
{
  guint8 * chunk = NULL;
  gsize chunk_size;
  gint64 slide;
  GumAddress linkedit;
  struct dyld_info_command * info;

  g_assert_cmpint (self->base_address, !=, 0);

  chunk = gum_darwin_read (self->task, self->base_address, MAX_MACH_HEADER_SIZE, &chunk_size);
  if (chunk == NULL)
    goto beach;

  if (!gum_darwin_find_slide (self->base_address, chunk, chunk_size, &slide))
    goto beach;

  if (!gum_darwin_find_linkedit (chunk, chunk_size, &linkedit))
    goto beach;
  linkedit += slide;

  if (!gum_darwin_find_command (LC_DYLD_INFO_ONLY, chunk, chunk_size, (gpointer *) &info))
    goto beach;

  self->exports = gum_darwin_read (self->task, linkedit + info->export_off, info->export_size, &self->exports_size);
  g_print ("Loaded exports %s: %d bytes\n", self->name, (gint) self->exports_size);

beach:
  g_free (chunk);
  return self->exports != NULL;
}

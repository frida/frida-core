#include "mapper.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define MAX_METADATA_SIZE (64 * 1024)

#ifndef EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
# define EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE 2
#endif

typedef struct _FridaSegment FridaSegment;
typedef struct _FridaMapping FridaMapping;
typedef struct _FridaSymbolDetails FridaSymbolDetails;
typedef struct _FridaBindDetails FridaBindDetails;

typedef void (* FridaFoundBindFunc) (const FridaBindDetails * details, gpointer user_data);

struct _FridaLibrary
{
  gint ref_count;

  gchar * name;

  mach_port_t task;
  GumCpuType cpu_type;
  gsize pointer_size;
  gsize page_size;
  GumAddress base_address;

  gpointer metadata;
  const struct dyld_info_command * info;
  const struct symtab_command * symtab;
  const struct dysymtab_command * dysymtab;
  GArray * segments;
  guint8 * exports;
  const guint8 * exports_end;
  GPtrArray * dependencies;
};

struct _FridaSegment
{
  gchar name[16];
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

struct _FridaSymbolDetails
{
  guint64 flags;

  guint64 offset;

  gint reexport_library_ordinal;
  const gchar * reexport_symbol;
};

struct _FridaBindDetails
{
  const FridaSegment * segment;
  guint64 offset;
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
static void frida_mapper_bind (const FridaBindDetails * details, gpointer user_data);
static void frida_mapper_enumerate_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data);
static void frida_mapper_enumerate_lazy_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data);

static FridaMapping * frida_mapping_ref (FridaMapping * self);
static void frida_mapping_unref (FridaMapping * self);

static FridaLibrary * frida_library_new (const gchar * name, mach_port_t task, GumCpuType cpu_type, GumAddress base_address);
static FridaLibrary * frida_library_ref (FridaLibrary * self);
static void frida_library_unref (FridaLibrary * self);
static const FridaSegment * frida_library_segment (FridaLibrary * self, gsize index);
static const gchar * frida_library_dependency (FridaLibrary * self, gint ordinal);
static gboolean frida_library_resolve (FridaLibrary * self, const gchar * symbol, FridaSymbolDetails * details);
static const guint8 * frida_library_find_export_node (FridaLibrary * self, const gchar * name);
static gboolean frida_library_ensure_metadata (FridaLibrary * self);
static gboolean frida_library_take_metadata (FridaLibrary * self, gpointer metadata, gsize metadata_size);

static guint64 frida_read_uleb128 (const guint8 ** p, const guint8 * end);
static void frida_skip_uleb128 (const guint8 ** p);

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
  struct mach_header * header_32 = NULL;
  struct mach_header_64 * header_64 = NULL;
  gsize size_32 = 0;
  gsize size_64 = 0;
  GPtrArray * dependencies;
  guint i;

  mapper = g_slice_new0 (FridaMapper);

  mapper->parent = parent;

  mapper->file = g_mapped_file_new (name, TRUE, NULL);
  g_assert (mapper->file != NULL);

  data = g_mapped_file_get_contents (mapper->file);
  fat_header = data;
  switch (fat_header->magic)
  {
    case FAT_CIGAM:
    {
      uint32_t count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count; i++)
      {
        struct fat_arch * fat_arch = ((struct fat_arch *) (fat_header + 1)) + i;
        gpointer mach_header = data + GUINT32_FROM_BE (fat_arch->offset);
        switch (((struct mach_header *) mach_header)->magic)
        {
          case MH_MAGIC:
            header_32 = mach_header;
            size_32 = GUINT32_FROM_BE (fat_arch->size);
            break;
          case MH_MAGIC_64:
            header_64 = mach_header;
            size_64 = GUINT32_FROM_BE (fat_arch->size);
            break;
          default:
            g_assert_not_reached ();
            break;
        }
      }
    }
    case MH_MAGIC:
      header_32 = data;
      size_32 = g_mapped_file_get_length (mapper->file);
      break;
    case MH_MAGIC_64:
      header_64 = data;
      size_64 = g_mapped_file_get_length (mapper->file);
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_ARM:
      g_assert (header_32 != NULL);
      mapper->data = header_32;
      mapper->size = size_32;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      g_assert (header_64 != NULL);
      mapper->data = header_64;
      mapper->size = size_64;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  mapper->library = frida_library_new (name, task, cpu_type, 0);
  frida_library_take_metadata (mapper->library, g_memdup (mapper->data, mapper->size), mapper->size);
  mapper->dependencies = g_ptr_array_new_full (5, (GDestroyNotify) frida_mapping_unref);

  if (parent == NULL)
  {
    mapper->mappings = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) frida_mapping_unref);
    frida_mapper_add_pending_mapping (mapper, name, mapper);
    gum_darwin_enumerate_modules (task, frida_mapper_add_existing_mapping_from_module, mapper);
  }

  dependencies = mapper->library->dependencies;
  for (i = 0; i != dependencies->len; i++)
  {
    FridaMapping * dependency;

    dependency = frida_mapper_resolve_dependency (mapper, g_ptr_array_index (dependencies, i), mapper);
    g_ptr_array_add (mapper->dependencies, dependency);
  }

  return mapper;
}

void
frida_mapper_free (FridaMapper * mapper)
{
  if (mapper->mappings != NULL)
    g_hash_table_unref (mapper->mappings);

  g_ptr_array_unref (mapper->dependencies);
  frida_library_unref (mapper->library);

  g_mapped_file_unref (mapper->file);

  g_slice_free (FridaMapper, mapper);
}

static FridaMapping *
frida_mapper_dependency (FridaMapper * self, gint ordinal)
{
  FridaMapping * result;

  g_assert_cmpint (ordinal, >=, 1); /* FIXME */
  result = g_ptr_array_index (self->dependencies, ordinal - 1);
  g_assert (result != NULL);

  return result;
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

    mapper = frida_mapper_new_with_parent (self, name, self->library->task, self->library->cpu_type);
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

  library = frida_library_new (details->path, self->library->task, self->library->cpu_type, base_address);
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
  FridaLibrary * library = self->library;
  gsize result = 0;
  guint i;

  for (i = 0; i != library->segments->len; i++)
  {
    FridaSegment * segment = &g_array_index (library->segments, FridaSegment, i);
    result += segment->vm_size;
    if (segment->vm_size % library->page_size != 0)
      result += library->page_size - (segment->vm_size % library->page_size);
  }

  return result;
}

void
frida_mapper_map (FridaMapper * self, GumAddress base_address)
{
  FridaLibrary * library = self->library;
  guint i;

  library->base_address = base_address;

  frida_mapper_enumerate_binds (self, frida_mapper_bind, self);
  frida_mapper_enumerate_lazy_binds (self, frida_mapper_bind, self);

  for (i = 0; i != library->segments->len; i++)
  {
    FridaSegment * s = &g_array_index (library->segments, FridaSegment, i);

    mach_vm_write (library->task, base_address + s->vm_address, (vm_offset_t) self->data + s->file_offset, s->file_size);

    mach_vm_protect (library->task, base_address + s->vm_address, s->vm_size, FALSE, s->protection);
  }
}

GumAddress
frida_mapper_resolve (FridaMapper * self, FridaLibrary * library, const gchar * symbol)
{
  FridaSymbolDetails details;

  if (self->parent != NULL)
    return frida_mapper_resolve (self->parent, library, symbol);

  if (!frida_library_resolve (library, symbol, &details))
    return 0;

  if ((details.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    const gchar * target_name;
    FridaMapping * target;

    target_name = frida_library_dependency (library, details.reexport_library_ordinal);
    target = g_hash_table_lookup (self->mappings, target_name);
    return frida_mapper_resolve (self, target->library, details.reexport_symbol);
  }

  switch (details.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK)
  {
    case EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
      g_assert_cmpint (details.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, ==, 0); /* TODO: necessary? */
      return library->base_address + details.offset;
    case EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
    case EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
      /* TODO: necessary? */
      g_assert_not_reached ();
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  return 0;
}

static void
frida_mapper_bind (const FridaBindDetails * details, gpointer user_data)
{
  FridaMapper * self = user_data;
  FridaMapping * dependency;
  GumAddress address;

  dependency = frida_mapper_dependency (self, details->library_ordinal);
  g_print ("bind(segment=%s, offset=%p, type=0x%02x, library=%s, symbol_name=%s, symbol_flags=0x%02x, addend=%p)\n",
      details->segment->name, (gpointer) details->offset, (gint) details->type, dependency->library->name, details->symbol_name, (gint) details->symbol_flags, (gpointer) details->addend);

  address = frida_mapper_resolve (self, dependency->library, details->symbol_name);
  g_print ("  *** %s to %p\n", details->symbol_name, (gpointer) address);
}

static void
frida_mapper_enumerate_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data)
{
  FridaLibrary * library = self->library;
  const guint8 * start, * end, * p;
  gboolean done;
  FridaBindDetails details;
  guint64 max_offset;

  start = self->data + library->info->bind_off;
  end = start + library->info->bind_size;
  p = start;
  done = FALSE;

  details.segment = frida_library_segment (library, 0);
  details.offset = 0;
  details.type = 0;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->vm_size;

  while (!done && p != end)
  {
    guint8 opcode = *p & BIND_OPCODE_MASK;
    guint8 immediate = *p & BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case BIND_OPCODE_DONE:
        done = TRUE;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
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
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = frida_library_segment (library, segment_index);
        details.offset = frida_read_uleb128 (&p, end);
        max_offset = details.segment->vm_size;
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (&details, user_data);
        details.offset += library->pointer_size;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (&details, user_data);
        details.offset += library->pointer_size + frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (&details, user_data);
        details.offset += library->pointer_size + (immediate * library->pointer_size);
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        count = frida_read_uleb128 (&p, end);
        skip = frida_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          func (&details, user_data);
          details.offset += library->pointer_size + skip;
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
frida_mapper_enumerate_lazy_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data)
{
  FridaLibrary * library = self->library;
  const guint8 * start, * end, * p;
  FridaBindDetails details;
  guint64 max_offset;

  start = self->data + library->info->lazy_bind_off;
  end = start + library->info->lazy_bind_size;
  p = start;

  details.segment = frida_library_segment (library, 0);
  details.offset = 0;
  details.type = BIND_TYPE_POINTER;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->vm_size;

  while (p != end)
  {
    guint8 opcode = *p & BIND_OPCODE_MASK;
    guint8 immediate = *p & BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case BIND_OPCODE_DONE:
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
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
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = frida_library_segment (library, segment_index);
        details.offset = frida_read_uleb128 (&p, end);
        max_offset = details.segment->vm_size;
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (&details, user_data);
        details.offset += library->pointer_size;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      default:
        g_assert_not_reached ();
        break;
    }
  }
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
frida_library_new (const gchar * name, mach_port_t task, GumCpuType cpu_type, GumAddress base_address)
{
  FridaLibrary * library;

  library = g_slice_new0 (FridaLibrary);
  library->ref_count = 1;

  library->name = g_strdup (name);

  library->task = task;
  library->cpu_type = cpu_type;
  switch (cpu_type)
  {
    case GUM_CPU_IA32:
      library->pointer_size = 4;
      library->page_size = 4096;
      break;
    case GUM_CPU_AMD64:
      library->pointer_size = 8;
      library->page_size = 4096;
      break;
    case GUM_CPU_ARM:
      library->pointer_size = 4;
      library->page_size = 4096;
      break;
    case GUM_CPU_ARM64:
      library->pointer_size = 8;
      library->page_size = 16384;
      break;
  }
  library->base_address = base_address;

  library->segments = g_array_new (FALSE, FALSE, sizeof (FridaSegment));
  library->dependencies = g_ptr_array_sized_new (5);

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
    g_ptr_array_unref (self->dependencies);
    g_free (self->exports);
    g_array_unref (self->segments);
    g_free (self->metadata);

    g_free (self->name);

    g_slice_free (FridaLibrary, self);
  }
}

static const FridaSegment *
frida_library_segment (FridaLibrary * self, gsize index)
{
  return &g_array_index (self->segments, FridaSegment, index);
}

static const gchar *
frida_library_dependency (FridaLibrary * self, gint ordinal)
{
  const gchar * result;

  g_assert_cmpint (ordinal, >=, 1); /* FIXME */

  if (!frida_library_ensure_metadata (self))
    return NULL;

  result = g_ptr_array_index (self->dependencies, ordinal - 1);
  g_assert (result != NULL);

  return result;
}

static gboolean
frida_library_resolve (FridaLibrary * self, const gchar * symbol, FridaSymbolDetails * details)
{
  const guint8 * p;

  p = frida_library_find_export_node (self, symbol);
  if (p == NULL)
      return FALSE;
  details->flags = frida_read_uleb128 (&p, self->exports_end);
  if ((details->flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    details->offset = 0;

    details->reexport_library_ordinal = frida_read_uleb128 (&p, self->exports_end);
    details->reexport_symbol = (*p != '\0') ? (gchar *) p : symbol;
  }
  else
  {
    details->offset = frida_read_uleb128 (&p, self->exports_end);

    details->reexport_library_ordinal = 0;
    details->reexport_symbol = NULL;
  }

  return TRUE;
}

static const guint8 *
frida_library_find_export_node (FridaLibrary * self, const gchar * symbol)
{
  const guint8 * p;

  if (!frida_library_ensure_metadata (self))
    return NULL;

  p = self->exports;
  while (p != NULL)
  {
    gint64 terminal_size;
    const guint8 * children;
    guint8 child_count, i;
    guint64 node_offset;

    terminal_size = frida_read_uleb128 (&p, self->exports_end);

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
        node_offset = frida_read_uleb128 (&p, self->exports_end);
        symbol = symbol_cur;
        break;
      }
      else
      {
        frida_skip_uleb128 (&p);
      }
    }

    if (node_offset != 0)
      p = self->exports + node_offset;
    else
      p = NULL;
  }

  return NULL;
}

static gboolean
frida_library_ensure_metadata (FridaLibrary * self)
{
  gpointer metadata;
  gsize metadata_size;

  if (self->metadata != NULL)
    return TRUE;

  g_assert_cmpint (self->base_address, !=, 0);

  metadata = gum_darwin_read (self->task, self->base_address, MAX_METADATA_SIZE, &metadata_size);
  if (metadata == NULL)
    return FALSE;

  return frida_library_take_metadata (self, metadata, metadata_size);
}

static gboolean
frida_library_take_metadata (FridaLibrary * self, gpointer metadata, gsize metadata_size)
{
  gboolean success = FALSE;
  struct mach_header * header;
  gpointer p;
  guint cmd_index;
  GumAddress linkedit;

  g_assert (self->metadata == NULL);

  header = (struct mach_header *) metadata;
  if (header->magic == MH_MAGIC)
    p = metadata + sizeof (struct mach_header);
  else
    p = metadata + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    switch (lc->cmd)
    {
      case LC_SEGMENT:
      case LC_SEGMENT_64:
      {
        FridaSegment segment;

        if (lc->cmd == LC_SEGMENT)
        {
          const struct segment_command * sc = p;
          strcpy (segment.name, sc->segname);
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          const struct segment_command_64 * sc = p;
          strcpy (segment.name, sc->segname);
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }

        g_array_append_val (self->segments, segment);

        break;
      }
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = p;
        gchar * name;

        name = p + dc->dylib.name.offset;
        g_ptr_array_add (self->dependencies, name);

        break;
      }
      case LC_DYLD_INFO_ONLY:
        self->info = p;
        break;
      case LC_SYMTAB:
        self->symtab = p;
        break;
      case LC_DYSYMTAB:
        self->dysymtab = p;
        break;
      default:
        break;
    }

    p += lc->cmdsize;
  }

  if (!gum_darwin_find_linkedit (metadata, metadata_size, &linkedit))
    goto beach;

  if (self->base_address != 0)
  {
    gint64 slide;
    gsize exports_size;

    if (!gum_darwin_find_slide (self->base_address, metadata, metadata_size, &slide))
      goto beach;
    linkedit += slide;

    self->exports = gum_darwin_read (self->task, linkedit + self->info->export_off, self->info->export_size, &exports_size);
    self->exports_end = self->exports != NULL ? self->exports + exports_size : NULL;
  }
  else
  {
    self->exports = g_memdup (metadata + linkedit + self->info->export_off, self->info->export_size);
    self->exports_end = self->exports + self->info->export_size;
  }

  success = self->exports != NULL;

beach:
  if (success)
    self->metadata = metadata;
  else
    g_free (metadata);

  return success;
}

static guint64
frida_read_uleb128 (const guint8 ** data, const guint8 * end)
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
frida_skip_uleb128 (const guint8 ** data)
{
  const guint8 * p = *data;
  while ((*p & 0x80) != 0)
    p++;
  p++;
  *data = p;
}

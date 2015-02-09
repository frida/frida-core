#include "mapper.h"

#include <fcntl.h>
#include <unistd.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#include <mach-o/arch.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define MAX_METADATA_SIZE (64 * 1024)

#ifndef EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
# define EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE 2
#endif

#if defined (HAVE_I386)
# define BASE_FOOTPRINT_SIZE_32 22
# define BASE_FOOTPRINT_SIZE_64 26
# define DEPENDENCY_FOOTPRINT_SIZE_32 14
# define DEPENDENCY_FOOTPRINT_SIZE_64 24
# define RESOLVER_FOOTPRINT_SIZE_32 21
# define RESOLVER_FOOTPRINT_SIZE_64 38
# define INIT_FOOTPRINT_SIZE_32 22
# define INIT_FOOTPRINT_SIZE_64 35
# define TERM_FOOTPRINT_SIZE_32 22
# define TERM_FOOTPRINT_SIZE_64 35
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
# define BASE_FOOTPRINT_SIZE_32 8
# define BASE_FOOTPRINT_SIZE_64 64
# define DEPENDENCY_FOOTPRINT_SIZE_32 0 /* TODO */
# define DEPENDENCY_FOOTPRINT_SIZE_64 0 /* TODO */
# define RESOLVER_FOOTPRINT_SIZE_32 0 /* TODO */
# define RESOLVER_FOOTPRINT_SIZE_64 0 /* TODO */
# define INIT_FOOTPRINT_SIZE_32 22
# define INIT_FOOTPRINT_SIZE_64 44
# define TERM_FOOTPRINT_SIZE_32 22
# define TERM_FOOTPRINT_SIZE_64 44
#endif

typedef struct _FridaLibrary FridaLibrary;
typedef struct _FridaLibraryImage FridaLibraryImage;
typedef struct _FridaLibraryImageSegment FridaLibraryImageSegment;
typedef struct _FridaSegment FridaSegment;
typedef struct _FridaSectionDetails FridaSectionDetails;
typedef struct _FridaMapping FridaMapping;
typedef struct _FridaSymbolValue FridaSymbolValue;
typedef struct _FridaSymbolDetails FridaSymbolDetails;
typedef struct _FridaRebaseDetails FridaRebaseDetails;
typedef struct _FridaBindDetails FridaBindDetails;
typedef struct _FridaInitPointersDetails FridaInitPointersDetails;
typedef struct _FridaTermPointersDetails FridaTermPointersDetails;

typedef struct _FridaEmitSectionInitPointersContext FridaEmitSectionInitPointersContext;
typedef struct _FridaEmitSectionTermPointersContext FridaEmitSectionTermPointersContext;

typedef struct _FridaDyldCacheHeader FridaDyldCacheHeader;
typedef struct _FridaDyldCacheMappingInfo FridaDyldCacheMappingInfo;
typedef struct _FridaDyldCacheImageInfo FridaDyldCacheImageInfo;

typedef void (* FridaFoundSectionFunc) (FridaLibrary * self, const FridaSectionDetails * details, gpointer user_data);
typedef void (* FridaFoundRebaseFunc) (FridaMapper * self, const FridaRebaseDetails * details, gpointer user_data);
typedef void (* FridaFoundBindFunc) (FridaMapper * self, const FridaBindDetails * details, gpointer user_data);
typedef void (* FridaFoundInitPointersFunc) (FridaMapper * self, const FridaInitPointersDetails * details, gpointer user_data);
typedef void (* FridaFoundTermPointersFunc) (FridaMapper * self, const FridaTermPointersDetails * details, gpointer user_data);

struct _FridaMapper
{
  FridaMapper * parent;

  gboolean mapped;

  FridaLibrary * library;
  FridaLibraryImage * image;

  GPtrArray * dependencies;

  gsize vm_size;
  gpointer runtime;
  GumAddress runtime_address;
  gsize runtime_vm_size;
  gsize runtime_file_size;
  gsize constructor_offset;
  gsize destructor_offset;

  GSList * children;
  GHashTable * mappings;
};

struct _FridaLibrary
{
  gint ref_count;

  gchar * name;

  mach_port_t task;
  GumCpuType cpu_type;
  gsize pointer_size;
  gsize page_size;
  GumAddress base_address;

  FridaLibraryImage * image;
  const struct dyld_info_command * info;
  const struct symtab_command * symtab;
  const struct dysymtab_command * dysymtab;
  GumAddress preferred_address;
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

struct _FridaSectionDetails
{
  const gchar * segment_name;
  const gchar * section_name;
  GumAddress vm_address;
  guint64 size;
  guint32 file_offset;
  guint32 flags;
};

struct _FridaMapping
{
  gint ref_count;
  FridaLibrary * library;
  FridaMapper * mapper;
};

struct _FridaSymbolValue
{
  GumAddress address;
  GumAddress resolver;
};

struct _FridaSymbolDetails
{
  guint64 flags;

  union
  {
    struct {
      guint64 offset;
    };
    struct {
      guint64 stub;
      guint64 resolver;
    };
    struct {
      gint reexport_library_ordinal;
      const gchar * reexport_symbol;
    };
  };
};

struct _FridaRebaseDetails
{
  const FridaSegment * segment;
  guint64 offset;
  guint8 type;
  GumAddress slide;
};

struct _FridaBindDetails
{
  const FridaSegment * segment;
  guint64 offset;
  guint8 type;
  gint library_ordinal;
  const gchar * symbol_name;
  guint8 symbol_flags;
  gint64 addend;
};

struct _FridaInitPointersDetails
{
  GumAddress address;
  guint64 count;
};

struct _FridaTermPointersDetails
{
  GumAddress address;
  guint64 count;
};

struct _FridaEmitSectionInitPointersContext
{
  FridaMapper * mapper;
  FridaFoundInitPointersFunc func;
  gpointer user_data;
};

struct _FridaEmitSectionTermPointersContext
{
  FridaMapper * mapper;
  FridaFoundTermPointersFunc func;
  gpointer user_data;
};

struct _FridaLibraryImage
{
  gpointer data;
  guint64 size;
  gconstpointer linkedit;

  guint64 source_offset;
  guint64 source_size;
  guint64 shared_offset;
  guint64 shared_size;
  GArray * shared_segments;

  GMappedFile * file;
  gpointer malloc_data;
};

struct _FridaLibraryImageSegment
{
  guint64 offset;
  guint64 size;
  gint protection;
};

struct _FridaDyldCacheHeader
{
  gchar magic[16];
  guint32 mapping_offset;
  guint32 mapping_count;
  guint32 images_offset;
  guint32 images_count;
};

struct _FridaDyldCacheMappingInfo
{
  GumAddress address;
  guint64 size;
  guint64 offset;
  guint32 max_protection;
  guint32 initial_protection;
};

struct _FridaDyldCacheImageInfo
{
  GumAddress address;
  guint64 mtime;
  guint64 inode;
  guint32 name_offset;
  guint32 padding;
};

static FridaMapper * frida_mapper_new_with_parent (FridaMapper * parent, const gchar * name, mach_port_t task, GumCpuType cpu_type);
static void frida_mapper_init_dependencies (FridaMapper * self);
static void frida_mapper_init_footprint_budget (FridaMapper * self);

static void frida_mapper_emit_runtime (FridaMapper * self);
static void frida_mapper_accumulate_bind_footprint_size (FridaMapper * self, const FridaBindDetails * details, gpointer user_data);
static void frida_mapper_accumulate_init_footprint_size (FridaMapper * self, const FridaInitPointersDetails * details, gpointer user_data);
static void frida_mapper_accumulate_term_footprint_size (FridaMapper * self, const FridaTermPointersDetails * details, gpointer user_data);

static gpointer frida_mapper_data_from_offset (FridaMapper * self, guint64 offset);
static FridaMapping * frida_mapper_dependency (FridaMapper * self, gint ordinal);
static FridaMapping * frida_mapper_resolve_dependency (FridaMapper * self, const gchar * name, FridaMapper * referrer);
static gboolean frida_mapper_resolve_symbol (FridaMapper * self, FridaLibrary * library, const gchar * symbol, FridaSymbolValue * value);
static gboolean frida_mapper_add_existing_mapping_from_module (const GumModuleDetails * details, gpointer user_data);
static FridaMapping * frida_mapper_add_existing_mapping (FridaMapper * self, FridaLibrary * library, GumAddress base_address);
static FridaMapping * frida_mapper_add_pending_mapping (FridaMapper * self, const gchar * name, FridaMapper * mapper);
static void frida_mapper_rebase (FridaMapper * self, const FridaRebaseDetails * details, gpointer user_data);
static void frida_mapper_bind (FridaMapper * self, const FridaBindDetails * details, gpointer user_data);

static void frida_mapper_enumerate_rebases (FridaMapper * self, FridaFoundRebaseFunc func, gpointer user_data);
static void frida_mapper_enumerate_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data);
static void frida_mapper_enumerate_lazy_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data);
static void frida_mapper_enumerate_init_pointers (FridaMapper * self, FridaFoundInitPointersFunc func, gpointer user_data);
static void frida_mapper_enumerate_term_pointers (FridaMapper * self, FridaFoundTermPointersFunc func, gpointer user_data);

static void frida_mapper_emit_section_init_pointers (FridaLibrary * self, const FridaSectionDetails * details, gpointer user_data);
static void frida_mapper_emit_section_term_pointers (FridaLibrary * self, const FridaSectionDetails * details, gpointer user_data);

static void frida_mapping_free (FridaMapping * self);

static FridaLibrary * frida_library_new_from_file (const gchar * name, mach_port_t task, GumCpuType cpu_type);
static FridaLibrary * frida_library_new_from_memory (const gchar * name, mach_port_t task, GumCpuType cpu_type, GumAddress base_address);
static FridaLibrary * frida_library_new (const gchar * name, mach_port_t task, GumCpuType cpu_type);
static FridaLibrary * frida_library_ref (FridaLibrary * self);
static void frida_library_unref (FridaLibrary * self);
static void frida_library_set_base_address (FridaLibrary * self, GumAddress base_address);
static GumAddress frida_library_slide (FridaLibrary * self);
static const FridaSegment * frida_library_segment (FridaLibrary * self, gsize index);
static void frida_library_enumerate_sections (FridaLibrary * self, FridaFoundSectionFunc func, gpointer user_data);
static const gchar * frida_library_dependency (FridaLibrary * self, gint ordinal);
static gboolean frida_library_resolve (FridaLibrary * self, const gchar * symbol, FridaSymbolDetails * details);
static const guint8 * frida_library_find_export_node (FridaLibrary * self, const gchar * name);
static gboolean frida_library_ensure_image_loaded (FridaLibrary * self);
static gboolean frida_library_try_load_image_from_cache (FridaLibrary * self, const gchar * name, GumCpuType cpu_type);
static void frida_library_load_image_from_filesystem (FridaLibrary * self, const gchar * name, GumCpuType cpu_type);
static gboolean frida_library_load_image_from_memory (FridaLibrary * self);
static gboolean frida_library_take_image (FridaLibrary * self, FridaLibraryImage * image);

static FridaLibraryImage * frida_library_image_new (void);
static FridaLibraryImage * frida_library_image_dup (const FridaLibraryImage * other);
static void frida_library_image_free (FridaLibraryImage * image);

static const FridaDyldCacheImageInfo * frida_dyld_cache_find_image_by_name (const gchar * name, const FridaDyldCacheImageInfo * images, gsize image_count, gconstpointer cache);
static guint64 frida_dyld_cache_compute_image_size (const FridaDyldCacheImageInfo * image, const FridaDyldCacheImageInfo * images, gsize image_count);
static guint64 frida_dyld_cache_offset_from_address (GumAddress address, const FridaDyldCacheMappingInfo * mappings, gsize mapping_count);

static const gchar * frida_current_architecture_name (void);

static gint64 frida_read_sleb128 (const guint8 ** data, const guint8 * end);
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

  mapper = g_slice_new0 (FridaMapper);
  mapper->parent = parent;

  mapper->mapped = FALSE;

  mapper->library = frida_library_new_from_file (name, task, cpu_type);
  mapper->image = frida_library_image_dup (mapper->library->image);

  if (parent != NULL)
    frida_mapper_add_pending_mapping (parent, name, mapper);

  frida_mapper_init_dependencies (mapper);
  frida_mapper_init_footprint_budget (mapper);

  return mapper;
}

static void
frida_mapper_init_dependencies (FridaMapper * self)
{
  FridaLibrary * library = self->library;
  GPtrArray * dependencies;
  guint i;

  self->dependencies = g_ptr_array_sized_new (5);

  if (self->parent == NULL)
  {
    self->mappings = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) frida_mapping_free);
    frida_mapper_add_pending_mapping (self, library->name, self);
    gum_darwin_enumerate_modules (library->task, frida_mapper_add_existing_mapping_from_module, self);
  }

  dependencies = library->dependencies;
  for (i = 0; i != dependencies->len; i++)
  {
    FridaMapping * dependency;

    dependency = frida_mapper_resolve_dependency (self, g_ptr_array_index (dependencies, i), self);
    g_ptr_array_add (self->dependencies, dependency);
  }
}

static void
frida_mapper_init_footprint_budget (FridaMapper * self)
{
  FridaLibrary * library = self->library;
  gsize segments_size, runtime_size;
  guint i;

  segments_size = 0;
  for (i = 0; i != library->segments->len; i++)
  {
    FridaSegment * segment = &g_array_index (library->segments, FridaSegment, i);
    segments_size += segment->vm_size;
    if (segment->vm_size % library->page_size != 0)
      segments_size += library->page_size - (segment->vm_size % library->page_size);
  }

  runtime_size = 0;
  frida_mapper_enumerate_binds (self, frida_mapper_accumulate_bind_footprint_size, &runtime_size);
  frida_mapper_enumerate_lazy_binds (self, frida_mapper_accumulate_bind_footprint_size, &runtime_size);
  frida_mapper_enumerate_init_pointers (self, frida_mapper_accumulate_init_footprint_size, &runtime_size);
  frida_mapper_enumerate_term_pointers (self, frida_mapper_accumulate_term_footprint_size, &runtime_size);
  if (library->pointer_size == 4)
  {
    runtime_size += g_slist_length (self->children) * DEPENDENCY_FOOTPRINT_SIZE_32;
    runtime_size += BASE_FOOTPRINT_SIZE_32;
  }
  else
  {
    runtime_size += g_slist_length (self->children) * DEPENDENCY_FOOTPRINT_SIZE_64;
    runtime_size += BASE_FOOTPRINT_SIZE_64;
  }

  self->runtime_vm_size = runtime_size;
  if (runtime_size % library->page_size != 0)
    self->runtime_vm_size += library->page_size - (runtime_size % library->page_size);
  self->runtime_file_size = runtime_size;

  self->vm_size = segments_size + self->runtime_vm_size;
}

void
frida_mapper_free (FridaMapper * mapper)
{
  if (mapper->mappings != NULL)
    g_hash_table_unref (mapper->mappings);

  g_slist_free_full (mapper->children, (GDestroyNotify) frida_mapper_free);

  g_free (mapper->runtime);

  g_ptr_array_unref (mapper->dependencies);

  frida_library_image_free (mapper->image);
  frida_library_unref (mapper->library);

  g_slice_free (FridaMapper, mapper);
}

gsize
frida_mapper_size (FridaMapper * self)
{
  gsize result;
  GSList * cur;

  result = self->vm_size;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    FridaMapper * child = cur->data;

    result += child->vm_size;
  }

  return result;
}

void
frida_mapper_map (FridaMapper * self, GumAddress base_address)
{
  GSList * cur;
  FridaLibrary * library = self->library;
  guint i;
  GArray * shared_segments;

  g_assert (!self->mapped);

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    FridaMapper * child = cur->data;

    frida_mapper_map (child, base_address);

    base_address += child->vm_size;
  }

  frida_library_set_base_address (library, base_address);
  self->runtime_address = base_address + self->vm_size - self->runtime_vm_size;

  frida_mapper_enumerate_rebases (self, frida_mapper_rebase, NULL);
  frida_mapper_enumerate_binds (self, frida_mapper_bind, NULL);
  frida_mapper_enumerate_lazy_binds (self, frida_mapper_bind, NULL);

  frida_mapper_emit_runtime (self);

  for (i = 0; i != library->segments->len; i++)
  {
    FridaSegment * s = &g_array_index (library->segments, FridaSegment, i);

    mach_vm_write (library->task, base_address + s->vm_address, (vm_offset_t) (self->image->data + s->file_offset), s->file_size);
    mach_vm_protect (library->task, base_address + s->vm_address, s->vm_size, FALSE, s->protection);
  }

  shared_segments = self->image->shared_segments;
  for (i = 0; i != shared_segments->len; i++)
  {
    FridaLibraryImageSegment * s = &g_array_index (shared_segments, FridaLibraryImageSegment, i);

    mach_vm_write (library->task, base_address + s->offset, (vm_offset_t) self->image->data + s->offset, s->size);
    mach_vm_protect (library->task, base_address + s->offset, s->size, FALSE, s->protection);
  }

  mach_vm_write (library->task, self->runtime_address, (vm_offset_t) self->runtime, self->runtime_file_size);
  mach_vm_protect (library->task, self->runtime_address, self->runtime_vm_size, FALSE,
      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY | VM_PROT_EXECUTE);

  self->mapped = TRUE;
}

GumAddress
frida_mapper_constructor (FridaMapper * self)
{
  g_assert (self->mapped);

  return self->runtime_address + self->constructor_offset;
}

GumAddress
frida_mapper_destructor (FridaMapper * self)
{
  g_assert (self->mapped);

  return self->runtime_address + self->destructor_offset;
}

GumAddress
frida_mapper_resolve (FridaMapper * self, const gchar * symbol)
{
  gchar * mangled_symbol;
  FridaSymbolValue value;
  gboolean success;

  g_assert (self->mapped);

  mangled_symbol = g_strconcat ("_", symbol, NULL);
  success = frida_mapper_resolve_symbol (self, self->library, mangled_symbol, &value);
  g_free (mangled_symbol);
  if (!success)
    return 0;
  else if (value.resolver != 0)
    return 0;

  return value.address;
}

#if defined (HAVE_I386)

static void frida_mapper_emit_child_constructor_call (FridaMapper * child, GumX86Writer * cw);
static void frida_mapper_emit_child_destructor_call (FridaMapper * child, GumX86Writer * cw);
static void frida_mapper_emit_resolve_if_needed (FridaMapper * self, const FridaBindDetails * details, GumX86Writer * cw);
static void frida_mapper_emit_init_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumX86Writer * cw);
static void frida_mapper_emit_term_calls (FridaMapper * self, const FridaTermPointersDetails * details, GumX86Writer * cw);

static void
frida_mapper_emit_runtime (FridaMapper * self)
{
  GumX86Writer cw;

  self->runtime = g_malloc (self->runtime_file_size);

  gum_x86_writer_init (&cw, self->runtime);
  gum_x86_writer_set_target_cpu (&cw, self->library->cpu_type);

  self->constructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, self->library->pointer_size);

  g_slist_foreach (self->children, (GFunc) frida_mapper_emit_child_constructor_call, &cw);
  frida_mapper_enumerate_binds (self, (FridaFoundBindFunc) frida_mapper_emit_resolve_if_needed, &cw);
  frida_mapper_enumerate_lazy_binds (self, (FridaFoundBindFunc) frida_mapper_emit_resolve_if_needed, &cw);
  frida_mapper_enumerate_init_pointers (self, (FridaFoundInitPointersFunc) frida_mapper_emit_init_calls, &cw);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, self->library->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, self->library->pointer_size);

  frida_mapper_enumerate_term_pointers (self, (FridaFoundTermPointersFunc) frida_mapper_emit_term_calls, &cw);
  g_slist_foreach (self->children, (GFunc) frida_mapper_emit_child_destructor_call, &cw);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, self->library->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  g_assert_cmpint (gum_x86_writer_offset (&cw), <=, self->runtime_file_size);
  gum_x86_writer_free (&cw);
}

static void
frida_mapper_emit_child_constructor_call (FridaMapper * child, GumX86Writer * cw)
{
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, frida_mapper_constructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_REG_XCX);
}

static void
frida_mapper_emit_child_destructor_call (FridaMapper * child, GumX86Writer * cw)
{
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, frida_mapper_destructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_REG_XCX);
}

static void
frida_mapper_emit_resolve_if_needed (FridaMapper * self, const FridaBindDetails * details, GumX86Writer * cw)
{
  FridaMapping * dependency;
  FridaSymbolValue value;
  gboolean success;
  GumAddress entry;

  dependency = frida_mapper_dependency (self, details->library_ordinal);
  success = frida_mapper_resolve_symbol (self, dependency->library, details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return;

  entry = self->library->base_address + details->segment->vm_address + details->offset;

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, value.resolver);
  gum_x86_writer_put_call_reg (cw, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, details->addend);
  gum_x86_writer_put_add_reg_reg (cw, GUM_REG_XAX, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, entry);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_REG_XCX, GUM_REG_XAX);
}

static void
frida_mapper_emit_init_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumX86Writer * cw)
{
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBP, details->address);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XBP);
  /* TODO: pass argc, argv, envp, apple, program vars */
  gum_x86_writer_put_call_reg (cw, GUM_REG_XAX);

  gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XBP, self->library->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JNZ, next_label, GUM_NO_HINT);
}

static void
frida_mapper_emit_term_calls (FridaMapper * self, const FridaTermPointersDetails * details, GumX86Writer * cw)
{
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBP, details->address + ((details->count - 1) * self->library->pointer_size));
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XBP);
  gum_x86_writer_put_call_reg (cw, GUM_REG_XAX);

  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XBP, self->library->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JNZ, next_label, GUM_NO_HINT);
}

#elif defined (HAVE_ARM) || defined (HAVE_ARM64)

static void frida_mapper_emit_arm_runtime (FridaMapper * self);
static void frida_mapper_emit_arm_init_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumThumbWriter * tw);
static void frida_mapper_emit_arm_term_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumThumbWriter * tw);

static void frida_mapper_emit_arm64_runtime (FridaMapper * self);
static void frida_mapper_emit_arm64_init_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumArm64Writer * aw);
static void frida_mapper_emit_arm64_term_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumArm64Writer * aw);

static void
frida_mapper_emit_runtime (FridaMapper * self)
{
  self->runtime = g_malloc (self->runtime_file_size);

  if (self->library->cpu_type == GUM_CPU_ARM)
    frida_mapper_emit_arm_runtime (self);
  else
    frida_mapper_emit_arm64_runtime (self);
}

static void
frida_mapper_emit_arm_runtime (FridaMapper * self)
{
  GumThumbWriter tw;

  gum_thumb_writer_init (&tw, self->runtime);

  self->constructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_LR);

  /*
  g_slist_foreach (self->children, (GFunc) frida_mapper_emit_child_constructor_call, &tw);
  frida_mapper_enumerate_binds (self, (FridaFoundBindFunc) frida_mapper_emit_resolve_if_needed, &tw);
  frida_mapper_enumerate_lazy_binds (self, (FridaFoundBindFunc) frida_mapper_emit_resolve_if_needed, &tw);
  */
  frida_mapper_enumerate_init_pointers (self, (FridaFoundInitPointersFunc) frida_mapper_emit_arm_init_calls, &tw);

  gum_thumb_writer_put_pop_regs (&tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_PC);

  self->destructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_LR);

  frida_mapper_enumerate_term_pointers (self, (FridaFoundTermPointersFunc) frida_mapper_emit_arm_term_calls, &tw);
  /*
  g_slist_foreach (self->children, (GFunc) frida_mapper_emit_child_destructor_call, &tw);
  */

  gum_thumb_writer_put_pop_regs (&tw, 5, GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7, GUM_AREG_PC);

  gum_thumb_writer_flush (&tw);
  g_assert_cmpint (gum_thumb_writer_offset (&tw), <=, self->runtime_file_size);
  gum_thumb_writer_free (&tw);
}

static void
frida_mapper_emit_arm_init_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumThumbWriter * tw)
{
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R4, details->address);
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, GUM_AREG_R0, GUM_AREG_R4);
  /* TODO: pass argc, argv, envp, apple, program vars */
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R0);

  gum_thumb_writer_put_add_reg_reg_imm (tw, GUM_AREG_R4, GUM_AREG_R4, 4);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, GUM_AREG_R5, GUM_AREG_R5, 1);
  gum_thumb_writer_put_cbnz_reg_label (tw, GUM_AREG_R5, next_label);
}

static void
frida_mapper_emit_arm_term_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumThumbWriter * tw)
{
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R4, details->address + ((details->count - 1) * 4));
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, GUM_AREG_R0, GUM_AREG_R4);
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R0);

  gum_thumb_writer_put_sub_reg_reg_imm (tw, GUM_AREG_R4, GUM_AREG_R4, 4);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, GUM_AREG_R5, GUM_AREG_R5, 1);
  gum_thumb_writer_put_cbnz_reg_label (tw, GUM_AREG_R5, next_label);
}

static void
frida_mapper_emit_arm64_runtime (FridaMapper * self)
{
  GumArm64Writer aw;

  gum_arm64_writer_init (&aw, self->runtime);

  self->constructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, GUM_A64REG_FP, GUM_A64REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, GUM_A64REG_X21, GUM_A64REG_X22);

  /*
  g_slist_foreach (self->children, (GFunc) frida_mapper_emit_child_constructor_call, &aw);
  frida_mapper_enumerate_binds (self, (FridaFoundBindFunc) frida_mapper_emit_resolve_if_needed, &aw);
  frida_mapper_enumerate_lazy_binds (self, (FridaFoundBindFunc) frida_mapper_emit_resolve_if_needed, &aw);
  */
  frida_mapper_enumerate_init_pointers (self, (FridaFoundInitPointersFunc) frida_mapper_emit_arm64_init_calls, &aw);

  gum_arm64_writer_put_pop_reg_reg (&aw, GUM_A64REG_X21, GUM_A64REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_ret (&aw);

  self->destructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, GUM_A64REG_FP, GUM_A64REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, GUM_A64REG_X21, GUM_A64REG_X22);

  frida_mapper_enumerate_term_pointers (self, (FridaFoundTermPointersFunc) frida_mapper_emit_arm64_term_calls, &aw);
  /*
  g_slist_foreach (self->children, (GFunc) frida_mapper_emit_child_destructor_call, &aw);
  */

  gum_arm64_writer_put_pop_reg_reg (&aw, GUM_A64REG_X21, GUM_A64REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, GUM_A64REG_X19, GUM_A64REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, GUM_A64REG_FP, GUM_A64REG_LR);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_flush (&aw);
  g_assert_cmpint (gum_arm64_writer_offset (&aw), <=, self->runtime_file_size);
  gum_arm64_writer_free (&aw);
}

static void
frida_mapper_emit_arm64_init_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumArm64Writer * aw)
{
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X19, details->address);
  gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X20, details->count);

  gum_arm64_writer_put_label (aw, next_label);

  gum_arm64_writer_put_ldr_reg_reg_offset (aw, GUM_A64REG_X0, GUM_A64REG_X19, 0);
  /* TODO: pass argc, argv, envp, apple, program vars */
  gum_arm64_writer_put_blr_reg (aw, GUM_A64REG_X0);

  gum_arm64_writer_put_add_reg_reg_imm (aw, GUM_A64REG_X19, GUM_A64REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, GUM_A64REG_X20, GUM_A64REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, GUM_A64REG_X20, next_label);
}

static void
frida_mapper_emit_arm64_term_calls (FridaMapper * self, const FridaInitPointersDetails * details, GumArm64Writer * aw)
{
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X19, details->address + ((details->count - 1) * 8));
  gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X20, details->count);

  gum_arm64_writer_put_label (aw, next_label);

  gum_arm64_writer_put_ldr_reg_reg_offset (aw, GUM_A64REG_X0, GUM_A64REG_X19, 0);
  gum_arm64_writer_put_blr_reg (aw, GUM_A64REG_X0);

  gum_arm64_writer_put_sub_reg_reg_imm (aw, GUM_A64REG_X19, GUM_A64REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, GUM_A64REG_X20, GUM_A64REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, GUM_A64REG_X20, next_label);
}

#endif

static void
frida_mapper_accumulate_bind_footprint_size (FridaMapper * self, const FridaBindDetails * details, gpointer user_data)
{
  gsize * total = user_data;
  FridaMapping * dependency;
  FridaSymbolValue value;

  dependency = frida_mapper_dependency (self, details->library_ordinal);
  if (frida_mapper_resolve_symbol (self, dependency->library, details->symbol_name, &value))
  {
    if (value.resolver != 0)
    {
      *total += self->library->pointer_size == 4 ? RESOLVER_FOOTPRINT_SIZE_32 : RESOLVER_FOOTPRINT_SIZE_64;
    }
  }
}

static void
frida_mapper_accumulate_init_footprint_size (FridaMapper * self, const FridaInitPointersDetails * details, gpointer user_data)
{
  gsize * total = user_data;

  *total += self->library->pointer_size == 4 ? INIT_FOOTPRINT_SIZE_32 : INIT_FOOTPRINT_SIZE_64;
}

static void
frida_mapper_accumulate_term_footprint_size (FridaMapper * self, const FridaTermPointersDetails * details, gpointer user_data)
{
  gsize * total = user_data;

  *total += self->library->pointer_size == 4 ? TERM_FOOTPRINT_SIZE_32 : TERM_FOOTPRINT_SIZE_64;
}

static gpointer
frida_mapper_data_from_offset (FridaMapper * self, guint64 offset)
{
  FridaLibraryImage * image = self->image;
  guint64 source_offset = image->source_offset;

  if (source_offset != 0)
  {
    g_assert_cmpint (offset, >=, source_offset);
    g_assert_cmpint (offset, <, source_offset + image->shared_offset + image->shared_size);
  }
  else
  {
    g_assert_cmpint (offset, <, image->size);
  }

  return image->data + (offset - source_offset);
}

static FridaMapping *
frida_mapper_dependency (FridaMapper * self, gint ordinal)
{
  FridaMapping * result;

  switch (ordinal)
  {
    case BIND_SPECIAL_DYLIB_SELF:
      result = frida_mapper_resolve_dependency (self, self->library->name, self);
      break;
    case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
    case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
      g_assert_not_reached ();
      break;
    default:
      result = g_ptr_array_index (self->dependencies, ordinal - 1);
      g_assert (result != NULL);
      break;
  }

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
    GSList * referrer_node;

    mapper = frida_mapper_new_with_parent (self, name, self->library->task, self->library->cpu_type);
    referrer_node = g_slist_find (self->children, referrer);
    if (referrer_node != NULL)
      self->children = g_slist_insert_before (self->children, referrer_node, mapper);
    else
      self->children = g_slist_prepend (self->children, mapper);

    mapping = g_hash_table_lookup (self->mappings, name);
    g_assert (mapping != NULL);
  }

  return mapping;
}

static gboolean
frida_mapper_resolve_symbol (FridaMapper * self, FridaLibrary * library, const gchar * symbol, FridaSymbolValue * value)
{
  FridaSymbolDetails details;

  if (self->parent != NULL)
    return frida_mapper_resolve_symbol (self->parent, library, symbol, value);

  if (!frida_library_resolve (library, symbol, &details))
    return 0;

  if ((details.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    const gchar * target_name;
    FridaMapping * target;

    target_name = frida_library_dependency (library, details.reexport_library_ordinal);
    target = frida_mapper_resolve_dependency (self, target_name, self);
    return frida_mapper_resolve_symbol (self, target->library, details.reexport_symbol, value);
  }

  switch (details.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK)
  {
    case EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
      if ((details.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
      {
        /* XXX: we ignore interposing */
        value->address = library->base_address + details.stub;
        value->resolver = library->base_address + details.resolver;
        return TRUE;
      }
      value->address = library->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
      value->address = library->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
      value->address = details.offset;
      value->resolver = 0;
      return TRUE;
    default:
      g_assert_not_reached ();
      break;
  }
}

static gboolean
frida_mapper_add_existing_mapping_from_module (const GumModuleDetails * details, gpointer user_data)
{
  FridaMapper * self = user_data;
  GumAddress base_address = details->range->base_address;
  FridaLibrary * library;

  library = frida_library_new_from_memory (details->path, self->library->task, self->library->cpu_type, base_address);
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

static void
frida_mapper_rebase (FridaMapper * self, const FridaRebaseDetails * details, gpointer user_data)
{
  gpointer entry;

  g_assert_cmpint (details->offset, <, details->segment->file_size);

  entry = frida_mapper_data_from_offset (self, details->segment->file_offset + details->offset);

  switch (details->type)
  {
    case REBASE_TYPE_POINTER:
    case REBASE_TYPE_TEXT_ABSOLUTE32:
      if (self->library->pointer_size == 4)
        *((guint32 *) entry) += (guint32) details->slide;
      else
        *((guint64 *) entry) += (guint64) details->slide;
      break;
    case REBASE_TYPE_TEXT_PCREL32:
    default:
      g_assert_not_reached ();
  }
}

static void
frida_mapper_bind (FridaMapper * self, const FridaBindDetails * details, gpointer user_data)
{
  FridaMapping * dependency;
  FridaSymbolValue value;
  gboolean success, is_weak_import;
  gpointer entry;

  g_assert_cmpint (details->type, ==, BIND_TYPE_POINTER);

  dependency = frida_mapper_dependency (self, details->library_ordinal);
  success = frida_mapper_resolve_symbol (self, dependency->library, details->symbol_name, &value);
  if (success)
    value.address += details->addend;
  is_weak_import = (details->symbol_flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;
  g_assert (success || is_weak_import);

  entry = frida_mapper_data_from_offset (self, details->segment->file_offset + details->offset);
  if (self->library->pointer_size == 4)
    *((guint32 *) entry) = value.address;
  else
    *((guint64 *) entry) = value.address;
}

static void
frida_mapper_enumerate_rebases (FridaMapper * self, FridaFoundRebaseFunc func, gpointer user_data)
{
  FridaLibrary * library = self->library;
  const guint8 * start, * end, * p;
  gboolean done;
  FridaRebaseDetails details;
  guint64 max_offset;

  start = self->library->image->linkedit + library->info->rebase_off;
  end = start + library->info->rebase_size;
  p = start;
  done = FALSE;

  details.segment = frida_library_segment (library, 0);
  details.offset = 0;
  details.type = 0;
  details.slide = frida_library_slide (library);

  max_offset = details.segment->file_size;

  while (!done && p != end)
  {
    guint8 opcode = *p & REBASE_OPCODE_MASK;
    guint8 immediate = *p & REBASE_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case REBASE_OPCODE_DONE:
        done = TRUE;
        break;
      case REBASE_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = frida_library_segment (library, segment_index);
        details.offset = frida_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case REBASE_OPCODE_ADD_ADDR_ULEB:
        details.offset += frida_read_uleb128 (&p, end);
        break;
      case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        details.offset += immediate * library->pointer_size;
        break;
      case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
      {
        guint8 i;

        for (i = 0; i != immediate; i++)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          func (self, &details, user_data);
          details.offset += library->pointer_size;
        }

        break;
      }
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
      {
        guint64 count, i;

        count = frida_read_uleb128 (&p, end);
        for (i = 0; i != count; i++)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          func (self, &details, user_data);
          details.offset += library->pointer_size;
        }

        break;
      }
      case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (self, &details, user_data);
        details.offset += library->pointer_size + frida_read_uleb128 (&p, end);
        break;
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        count = frida_read_uleb128 (&p, end);
        skip = frida_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          func (self, &details, user_data);
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
frida_mapper_enumerate_binds (FridaMapper * self, FridaFoundBindFunc func, gpointer user_data)
{
  FridaLibrary * library = self->library;
  const guint8 * start, * end, * p;
  gboolean done;
  FridaBindDetails details;
  guint64 max_offset;

  start = self->library->image->linkedit + library->info->bind_off;
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

  max_offset = details.segment->file_size;

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
        details.addend = frida_read_sleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = frida_library_segment (library, segment_index);
        details.offset = frida_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (self, &details, user_data);
        details.offset += library->pointer_size;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (self, &details, user_data);
        details.offset += library->pointer_size + frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (self, &details, user_data);
        details.offset += library->pointer_size + (immediate * library->pointer_size);
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip, i;

        count = frida_read_uleb128 (&p, end);
        skip = frida_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          func (self, &details, user_data);
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

  start = self->library->image->linkedit + library->info->lazy_bind_off;
  end = start + library->info->lazy_bind_size;
  p = start;

  details.segment = frida_library_segment (library, 0);
  details.offset = 0;
  details.type = BIND_TYPE_POINTER;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->file_size;

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
        details.addend = frida_read_sleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = frida_library_segment (library, segment_index);
        details.offset = frida_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += frida_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_assert_cmpuint (details.offset, <, max_offset);
        func (self, &details, user_data);
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

static void
frida_mapper_enumerate_init_pointers (FridaMapper * self, FridaFoundInitPointersFunc func, gpointer user_data)
{
  FridaEmitSectionInitPointersContext ctx;
  ctx.mapper = self;
  ctx.func = func;
  ctx.user_data = user_data;
  frida_library_enumerate_sections (self->library, frida_mapper_emit_section_init_pointers, &ctx);
}

static void
frida_mapper_enumerate_term_pointers (FridaMapper * self, FridaFoundTermPointersFunc func, gpointer user_data)
{
  FridaEmitSectionTermPointersContext ctx;
  ctx.mapper = self;
  ctx.func = func;
  ctx.user_data = user_data;
  frida_library_enumerate_sections (self->library, frida_mapper_emit_section_term_pointers, &ctx);
}

static void
frida_mapper_emit_section_init_pointers (FridaLibrary * self, const FridaSectionDetails * details, gpointer user_data)
{
  if ((details->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS)
  {
    FridaEmitSectionInitPointersContext * ctx = user_data;
    FridaInitPointersDetails d;
    d.address = details->vm_address;
    d.count = details->size / self->pointer_size;
    ctx->func (ctx->mapper, &d, ctx->user_data);
  }
}

static void
frida_mapper_emit_section_term_pointers (FridaLibrary * self, const FridaSectionDetails * details, gpointer user_data)
{
  if ((details->flags & SECTION_TYPE) == S_MOD_TERM_FUNC_POINTERS)
  {
    FridaEmitSectionTermPointersContext * ctx = user_data;
    FridaTermPointersDetails d;
    d.address = details->vm_address;
    d.count = details->size / self->pointer_size;
    ctx->func (ctx->mapper, &d, ctx->user_data);
  }
}

static void
frida_mapping_free (FridaMapping * self)
{
  frida_library_unref (self->library);
  g_slice_free (FridaMapping, self);
}

static FridaLibrary *
frida_library_new_from_file (const gchar * name, mach_port_t task, GumCpuType cpu_type)
{
  FridaLibrary * library;

  library = frida_library_new (name, task, cpu_type);
  if (!frida_library_try_load_image_from_cache (library, name, cpu_type))
    frida_library_load_image_from_filesystem (library, name, cpu_type);

  return library;
}

static FridaLibrary *
frida_library_new_from_memory (const gchar * name, mach_port_t task, GumCpuType cpu_type, GumAddress base_address)
{
  FridaLibrary * library;

  library = frida_library_new (name, task, cpu_type);
  frida_library_set_base_address (library, base_address);

  return library;
}

static FridaLibrary *
frida_library_new (const gchar * name, mach_port_t task, GumCpuType cpu_type)
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
    if (self->image != NULL)
      frida_library_image_free (self->image);

    g_free (self->name);

    g_slice_free (FridaLibrary, self);
  }
}

static void
frida_library_set_base_address (FridaLibrary * self, GumAddress base_address)
{
  self->base_address = base_address;
}

static GumAddress
frida_library_slide (FridaLibrary * self)
{
  return self->base_address - self->preferred_address;
}

static const FridaSegment *
frida_library_segment (FridaLibrary * self, gsize index)
{
  return &g_array_index (self->segments, FridaSegment, index);
}

static void
frida_library_enumerate_sections (FridaLibrary * self, FridaFoundSectionFunc func, gpointer user_data)
{
  const struct mach_header * header;
  gconstpointer command;
  gsize command_index;
  GumAddress slide;

  header = (struct mach_header *) self->image->data;
  if (header->magic == MH_MAGIC)
    command = self->image->data + sizeof (struct mach_header);
  else
    command = self->image->data + sizeof (struct mach_header_64);
  slide = frida_library_slide (self);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const struct load_command * lc = command;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      gconstpointer sections;
      gsize section_count, section_index;

      if (lc->cmd == LC_SEGMENT)
      {
        const struct segment_command * sc = command;
        sections = sc + 1;
        section_count = sc->nsects;
      }
      else
      {
        const struct segment_command_64 * sc = command;
        sections = sc + 1;
        section_count = sc->nsects;
      }

      for (section_index = 0; section_index != section_count; section_index++)
      {
        FridaSectionDetails details;

        if (lc->cmd == LC_SEGMENT)
        {
          const struct section * s = sections + (section_index * sizeof (struct section));
          details.segment_name = s->segname;
          details.section_name = s->sectname;
          details.vm_address = s->addr + (guint32) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }
        else
        {
          const struct section_64 * s = sections + (section_index * sizeof (struct section_64));
          details.segment_name = s->segname;
          details.section_name = s->sectname;
          details.vm_address = s->addr + (guint64) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }

        func (self, &details, user_data);
      }
    }

    command += lc->cmdsize;
  }
}

static const gchar *
frida_library_dependency (FridaLibrary * self, gint ordinal)
{
  const gchar * result;

  g_assert_cmpint (ordinal, >=, 1); /* TODO */

  if (!frida_library_ensure_image_loaded (self))
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
    details->reexport_library_ordinal = frida_read_uleb128 (&p, self->exports_end);
    details->reexport_symbol = (*p != '\0') ? (gchar *) p : symbol;
  }
  else if ((details->flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
  {
    details->stub = frida_read_uleb128 (&p, self->exports_end);
    details->resolver = frida_read_uleb128 (&p, self->exports_end);
  }
  else
  {
    details->offset = frida_read_uleb128 (&p, self->exports_end);
  }

  return TRUE;
}

static const guint8 *
frida_library_find_export_node (FridaLibrary * self, const gchar * symbol)
{
  const guint8 * p;

  if (!frida_library_ensure_image_loaded (self))
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
frida_library_ensure_image_loaded (FridaLibrary * self)
{
  if (self->image != NULL)
    return TRUE;
  else
    return frida_library_load_image_from_memory (self);
}

static gboolean
frida_library_try_load_image_from_cache (FridaLibrary * self, const gchar * name, GumCpuType cpu_type)
{
  gboolean success = FALSE;
  gchar * path;
  gint fd = -1, result;
  GMappedFile * file = NULL;
  gpointer cache;
  const FridaDyldCacheHeader * header;
  const FridaDyldCacheImageInfo * images, * image;
  const FridaDyldCacheMappingInfo * mappings, * first_mapping, * second_mapping, * last_mapping, * mapping;
  guint64 image_offset, image_size;
  FridaLibraryImage * library_image;

  path = g_strconcat (
      "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_",
      frida_current_architecture_name (),
      NULL);

  fd = open (path, 0);
  if (fd == -1)
    goto beach;

  result = fcntl (fd, F_NOCACHE, TRUE);
  g_assert (result == 0);

  file = g_mapped_file_new_from_fd (fd, FALSE, NULL);
  g_assert (file != NULL);

  fd = -1; /* TODO: verify assumption that GMappedFile takes ownership of fd */

  cache = g_mapped_file_get_contents (file);
  g_assert (cache != NULL);

  header = cache;
  images = cache + header->images_offset;
  mappings = cache + header->mapping_offset;
  first_mapping = &mappings[0];
  second_mapping = &mappings[1];
  last_mapping = &mappings[header->mapping_count - 1];

  image = frida_dyld_cache_find_image_by_name (name, images, header->images_count, cache);
  if (image == NULL)
    goto beach;

  image_offset = frida_dyld_cache_offset_from_address (image->address, mappings, header->mapping_count);
  image_size = frida_dyld_cache_compute_image_size (image, images, header->images_count);

  g_assert_cmpint (image_offset, >=, first_mapping->offset);
  g_assert_cmpint (image_offset, <, first_mapping->offset + first_mapping->size);

  library_image = frida_library_image_new ();

  library_image->source_offset = image_offset;
  library_image->source_size = image_size;
  library_image->shared_offset = second_mapping->offset - image_offset;
  library_image->shared_size = (last_mapping->offset + last_mapping->size) - second_mapping->offset;
  for (mapping = second_mapping; mapping != last_mapping + 1; mapping++)
  {
    FridaLibraryImageSegment segment;
    segment.offset = library_image->shared_offset + (mapping->offset - second_mapping->offset);
    segment.size = mapping->size;
    segment.protection = mapping->initial_protection;
    g_array_append_val (library_image->shared_segments, segment);
  }

  library_image->data = cache + image_offset;
  library_image->size = library_image->shared_offset + library_image->shared_size;
  library_image->linkedit = cache;

  library_image->file = g_mapped_file_ref (file);

  success = frida_library_take_image (self, library_image);
  g_assert (success);

beach:
  if (file != NULL)
    g_mapped_file_unref (file);

  if (fd != -1)
    close (fd);

  g_free (path);

  return success;
}

static void
frida_library_load_image_from_filesystem (FridaLibrary * self, const gchar * name, GumCpuType cpu_type)
{
  FridaLibraryImage * image;
  gpointer file_data;
  struct fat_header * fat_header;
  struct mach_header * header_32 = NULL;
  struct mach_header_64 * header_64 = NULL;
  gsize size_32 = 0;
  gsize size_64 = 0;
  gboolean success;

  image = frida_library_image_new ();

  image->file = g_mapped_file_new (name, FALSE, NULL);
  g_assert (image->file != NULL);

  file_data = g_mapped_file_get_contents (image->file);

  fat_header = file_data;
  switch (fat_header->magic)
  {
    case FAT_CIGAM:
    {
      uint32_t count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count; i++)
      {
        struct fat_arch * fat_arch = ((struct fat_arch *) (fat_header + 1)) + i;
        gpointer mach_header = file_data + GUINT32_FROM_BE (fat_arch->offset);
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

      break;
    }
    case MH_MAGIC:
      header_32 = file_data;
      size_32 = g_mapped_file_get_length (image->file);
      break;
    case MH_MAGIC_64:
      header_64 = file_data;
      size_64 = g_mapped_file_get_length (image->file);
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
      image->data = header_32;
      image->size = size_32;
      image->linkedit = header_32;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      g_assert (header_64 != NULL);
      image->data = header_64;
      image->size = size_64;
      image->linkedit = header_64;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  success = frida_library_take_image (self, image);
  g_assert (success);
}

static gboolean
frida_library_load_image_from_memory (FridaLibrary * self)
{
  gpointer data;
  gsize data_size;
  FridaLibraryImage * image;

  g_assert_cmpint (self->base_address, !=, 0);

  data = gum_darwin_read (self->task, self->base_address, MAX_METADATA_SIZE, &data_size);
  if (data == NULL)
    return FALSE;

  image = frida_library_image_new ();

  image->data = data;
  image->size = data_size;

  image->malloc_data = data;

  return frida_library_take_image (self, image);
}

static gboolean
frida_library_take_image (FridaLibrary * self, FridaLibraryImage * image)
{
  gboolean success = FALSE;
  const struct mach_header * header;
  gconstpointer command;
  gsize command_index;

  g_assert (self->image == NULL);

  header = (struct mach_header *) image->data;
  if (header->magic == MH_MAGIC)
    command = image->data + sizeof (struct mach_header);
  else
    command = image->data + sizeof (struct mach_header_64);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const struct load_command * lc = (struct load_command *) command;

    switch (lc->cmd)
    {
      case LC_SEGMENT:
      case LC_SEGMENT_64:
      {
        FridaSegment segment;

        if (lc->cmd == LC_SEGMENT)
        {
          const struct segment_command * sc = command;
          strcpy (segment.name, sc->segname);
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          const struct segment_command_64 * sc = command;
          strcpy (segment.name, sc->segname);
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }

        g_array_append_val (self->segments, segment);

        if (strcmp (segment.name, "__TEXT") == 0)
        {
          self->preferred_address = segment.vm_address;
        }

        break;
      }
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = command;
        const gchar * name;

        name = command + dc->dylib.name.offset;
        g_ptr_array_add (self->dependencies, (gpointer) name);

        break;
      }
      case LC_DYLD_INFO_ONLY:
        self->info = command;
        break;
      case LC_SYMTAB:
        self->symtab = command;
        break;
      case LC_DYSYMTAB:
        self->dysymtab = command;
        break;
      default:
        break;
    }

    command += lc->cmdsize;
  }

  if (image->linkedit == NULL)
  {
    GumAddress memory_linkedit;
    gsize exports_size;

    if (!gum_darwin_find_linkedit (image->data, image->size, &memory_linkedit))
      goto beach;

    memory_linkedit += frida_library_slide (self);

    self->exports = gum_darwin_read (self->task, memory_linkedit + self->info->export_off, self->info->export_size, &exports_size);
    self->exports_end = self->exports != NULL ? self->exports + exports_size : NULL;
  }
  else
  {
    self->exports = g_memdup (image->linkedit + self->info->export_off, self->info->export_size);
    self->exports_end = self->exports + self->info->export_size;
  }

  success = self->exports != NULL;

beach:
  if (success)
    self->image = image;
  else
    frida_library_image_free (image);

  return success;
}

static FridaLibraryImage *
frida_library_image_new (void)
{
  FridaLibraryImage * image;

  image = g_slice_new0 (FridaLibraryImage);
  image->shared_segments = g_array_new (FALSE, FALSE, sizeof (FridaLibraryImageSegment));

  return image;
}

static FridaLibraryImage *
frida_library_image_dup (const FridaLibraryImage * other)
{
  FridaLibraryImage * image;

  image = g_slice_new0 (FridaLibraryImage);

  image->size = other->size;

  image->source_offset = other->source_offset;
  image->source_size = other->source_size;
  image->shared_offset = other->shared_offset;
  image->shared_size = other->shared_size;
  image->shared_segments = g_array_ref (other->shared_segments);

  if (other->file != NULL)
    image->file = g_mapped_file_ref (other->file);

  if (other->shared_segments->len > 0)
  {
    guint i;

    image->malloc_data = g_malloc (other->size);
    image->data = image->malloc_data;

    g_assert (other->source_size != 0);
    memcpy (image->data, other->data, other->source_size);

    for (i = 0; i != other->shared_segments->len; i++)
    {
      FridaLibraryImageSegment * s = &g_array_index (other->shared_segments, FridaLibraryImageSegment, i);
      memcpy (image->data + s->offset, other->data + s->offset, s->size);
    }
  }
  else
  {
    image->malloc_data = g_memdup (other->data, other->size);
    image->data = image->malloc_data;
  }

  if (other->file != NULL)
  {
    gpointer file_data;
    gsize file_size;

    file_data = g_mapped_file_get_contents (other->file);
    file_size = g_mapped_file_get_length (other->file);
    if (other->linkedit >= file_data && other->linkedit < file_data + file_size)
      image->linkedit = other->linkedit;
  }

  if (image->linkedit == NULL && other->linkedit != NULL)
  {
    g_assert (other->linkedit >= other->data && other->linkedit < other->data + other->size);
    image->linkedit = image->data + (other->linkedit - other->data);
  }

  return image;
}

static void
frida_library_image_free (FridaLibraryImage * image)
{
  g_free (image->malloc_data);
  if (image->file != NULL)
    g_mapped_file_unref (image->file);

  g_array_unref (image->shared_segments);

  g_slice_free (FridaLibraryImage, image);
}

static const FridaDyldCacheImageInfo *
frida_dyld_cache_find_image_by_name (const gchar * name, const FridaDyldCacheImageInfo * images, gsize image_count, gconstpointer cache)
{
  gsize i;

  for (i = 0; i != image_count; i++)
  {
    const FridaDyldCacheImageInfo * image = &images[i];
    const gchar * current_name;

    current_name = cache + image->name_offset;
    if (strcmp (current_name, name) == 0)
      return image;
  }

  return NULL;
}

static guint64
frida_dyld_cache_compute_image_size (const FridaDyldCacheImageInfo * image, const FridaDyldCacheImageInfo * images, gsize image_count)
{
  const FridaDyldCacheImageInfo * next_image;
  gsize i;

  next_image = NULL;
  for (i = 0; i != image_count; i++)
  {
    const FridaDyldCacheImageInfo * candidate = &images[i];

    if (candidate->address > image->address && (next_image == NULL || candidate->address < next_image->address))
    {
      next_image = candidate;
    }
  }
  g_assert (next_image != NULL);

  return next_image->address - image->address;
}

static guint64
frida_dyld_cache_offset_from_address (GumAddress address, const FridaDyldCacheMappingInfo * mappings, gsize mapping_count)
{
  gsize i;

  for (i = 0; i != mapping_count; i++)
  {
    const FridaDyldCacheMappingInfo * mapping = &mappings[i];

    if (address >= mapping->address && address < mapping->address + mapping->size)
    {
      return address - mapping->address + mapping->offset;
    }
  }

  g_assert_not_reached ();
}

static const gchar *
frida_current_architecture_name (void)
{
  guint count, i;

  count = _dyld_image_count ();
  for (i = 0; i != count; i++)
  {
    const gchar * name;

    name = _dyld_get_image_name (i);
    if (strcmp (name, "/usr/lib/libSystem.B.dylib") == 0)
    {
      const struct mach_header * header;
      const NXArchInfo * info;

      header = _dyld_get_image_header (i);
      info = NXGetArchInfoFromCpuType (header->cputype, header->cpusubtype);

      return info->name;
    }
  }

  g_assert_not_reached ();
}

static gint64
frida_read_sleb128 (const guint8 ** data, const guint8 * end)
{
  const guint8 * p = *data;
  gint64 result = 0;
  gint offset = 0;
  guint8 value;

  do
  {
    gint64 chunk;

    g_assert (p != end);
    g_assert_cmpint (offset, <=, 63);

    value = *p;
    chunk = value & 0x7f;
    result |= (chunk << offset);
    offset += 7;
  }
  while (*p++ & 0x80);

  if ((value & 0x40) != 0)
    result |= G_GINT64_CONSTANT (-1) << offset;

  *data = p;

  return result;
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

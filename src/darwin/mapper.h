#ifndef __FRIDA_DARWIN_MAPPER_H__
#define __FRIDA_DARWIN_MAPPER_H__

#include <gum/gumdarwin.h>

typedef struct _FridaMapper FridaMapper;
typedef struct _FridaLibrary FridaLibrary;

struct _FridaMapper
{
  FridaMapper * parent;

  GMappedFile * file;
  mach_port_t task;
  GumCpuType cpu_type;
  gsize page_size;
  gsize pointer_size;

  gpointer header;
  struct mach_header * header_32;
  struct mach_header_64 * header_64;
  struct load_command * commands;
  gsize command_count;
  struct dyld_info_command * info;
  struct symtab_command * symtab;
  struct dysymtab_command * dysymtab;

  FridaLibrary * library;
  GArray * segments;
  GPtrArray * dependencies;

  GHashTable * mappings;
};

FridaMapper * frida_mapper_new (const gchar * name, mach_port_t task, GumCpuType cpu_type);
void frida_mapper_free (FridaMapper * mapper);

gsize frida_mapper_size (FridaMapper * self);
void frida_mapper_map (FridaMapper * self, GumAddress base_address);
GumAddress frida_mapper_resolve (FridaMapper * self, const gchar * symbol);

#endif

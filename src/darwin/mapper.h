#ifndef __FRIDA_DARWIN_MAPPER_H__
#define __FRIDA_DARWIN_MAPPER_H__

#include <gum/gumdarwin.h>

typedef struct _FridaMapper FridaMapper;
typedef struct _FridaLibrary FridaLibrary;

struct _FridaMapper
{
  FridaMapper * parent;

  GMappedFile * file;
  gpointer data;
  gsize size;

  FridaLibrary * library;
  GPtrArray * dependencies;

  GHashTable * mappings;
};

FridaMapper * frida_mapper_new (const gchar * name, mach_port_t task, GumCpuType cpu_type);
void frida_mapper_free (FridaMapper * mapper);

gsize frida_mapper_size (FridaMapper * self);
void frida_mapper_map (FridaMapper * self, GumAddress base_address);
GumAddress frida_mapper_resolve (FridaMapper * self, FridaLibrary * library, const gchar * symbol);

#endif

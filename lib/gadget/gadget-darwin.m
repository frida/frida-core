#include "frida-gadget.h"

#import <Foundation/Foundation.h>
#include <gum/gumdarwin.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <pthread.h>

gchar *
frida_gadget_environment_detect_bundle_id (void)
{
  @autoreleasepool
  {
    NSString * identifier = NSBundle.mainBundle.bundleIdentifier;
    return g_strdup (identifier.UTF8String);
  }
}

gchar *
frida_gadget_environment_detect_bundle_name (void)
{
  @autoreleasepool
  {
    NSString * name = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleName"];
    return g_strdup (name.UTF8String);
  }
}

gchar *
frida_gadget_environment_detect_documents_dir (void)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS) || defined (HAVE_XROS)
  @autoreleasepool
  {
    NSArray<NSString *> * paths = NSSearchPathForDirectoriesInDomains (NSDocumentDirectory, NSUserDomainMask, YES);
    NSString * first = paths.firstObject;
    return g_strdup (first.UTF8String);
  }
#else
  return NULL;
#endif
}

gboolean
frida_gadget_environment_has_objc_class (const gchar * name)
{
  return objc_getClass (name) != NULL;
}

void
frida_gadget_environment_set_thread_name (const gchar * name)
{
  /* For now only implemented on i/macOS as Fruity.Injector relies on it there. */
  pthread_setname_np (name);
}

void
frida_gadget_environment_detect_darwin_location_fields (GumAddress our_address, gchar ** executable_name, gchar ** our_path,
    GumMemoryRange ** our_range)
{
  mach_port_t task;
  GumDarwinModuleResolver * resolver;
  GPtrArray * modules;
  guint i;

  task = mach_task_self ();

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  gum_darwin_module_resolver_fetch_modules (resolver, &modules, NULL);

  for (i = 0; i != modules->len; i++)
  {
    GumModule * module;
    const GumMemoryRange * range;

    module = g_ptr_array_index (modules, i);
    range = gum_module_get_range (module);

    if (*executable_name == NULL)
    {
      gum_mach_header_t * header = GSIZE_TO_POINTER (range->base_address);
      if (header->filetype == MH_EXECUTE)
        *executable_name = g_strdup (gum_module_get_name (module));
    }

    if (our_address >= range->base_address && our_address < range->base_address + range->size)
    {
      if (*our_path == NULL)
        *our_path = g_strdup (gum_module_get_path (module));

      if (*our_range == NULL)
        *our_range = gum_memory_range_copy (range);
    }

    if (*executable_name != NULL && *our_path != NULL && *our_range != NULL)
      break;
  }

  g_ptr_array_unref (modules);

  g_object_unref (resolver);
}

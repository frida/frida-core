#include "frida-gadget.h"

#import <Foundation/Foundation.h>
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
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
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

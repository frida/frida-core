#import "springboard.h"

#include <dlfcn.h>

#define FRIDA_ASSIGN_SBS_FUNC(N) \
    api->N = dlsym (api->sbs, G_STRINGIFY (N)); \
    g_assert (api->N != NULL)
#define FRIDA_ASSIGN_SBS_CONSTANT(N) \
    str = dlsym (api->sbs, G_STRINGIFY (N)); \
    g_assert (str != NULL); \
    api->N = *str
#define FRIDA_ASSIGN_FBS_CONSTANT(N) \
    str = dlsym (api->fbs, G_STRINGIFY (N)); \
    g_assert (str != NULL); \
    api->N = *str

static FridaSpringboardApi * frida_springboard_api = NULL;

FridaSpringboardApi *
_frida_get_springboard_api (void)
{
  if (frida_springboard_api == NULL)
  {
    FridaSpringboardApi * api;
    NSString ** str;
    id (* objc_get_class_impl) (const gchar * name);

    api = g_new0 (FridaSpringboardApi, 1);

    api->sbs = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_GLOBAL | RTLD_LAZY);
    g_assert (api->sbs != NULL);

    api->fbs = dlopen ("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_GLOBAL | RTLD_LAZY);

    FRIDA_ASSIGN_SBS_FUNC (SBSCopyFrontmostApplicationDisplayIdentifier);
    FRIDA_ASSIGN_SBS_FUNC (SBSCopyApplicationDisplayIdentifiers);
    FRIDA_ASSIGN_SBS_FUNC (SBSCopyDisplayIdentifierForProcessID);
    FRIDA_ASSIGN_SBS_FUNC (SBSCopyLocalizedApplicationNameForDisplayIdentifier);
    FRIDA_ASSIGN_SBS_FUNC (SBSCopyIconImagePNGDataForDisplayIdentifier);
    FRIDA_ASSIGN_SBS_FUNC (SBSLaunchApplicationWithIdentifierAndLaunchOptions);
    FRIDA_ASSIGN_SBS_FUNC (SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions);
    FRIDA_ASSIGN_SBS_FUNC (SBSApplicationLaunchingErrorString);

    FRIDA_ASSIGN_SBS_CONSTANT (SBSApplicationLaunchOptionUnlockDeviceKey);

    if (api->fbs != NULL)
    {
      objc_get_class_impl = dlsym (RTLD_DEFAULT, "objc_getClass");
      g_assert (objc_get_class_impl != NULL);

      api->FBSSystemService = objc_get_class_impl ("FBSSystemService");
      g_assert (api->FBSSystemService != nil);

      FRIDA_ASSIGN_FBS_CONSTANT (FBSOpenApplicationOptionKeyUnlockDevice);
      FRIDA_ASSIGN_FBS_CONSTANT (FBSOpenApplicationOptionKeyDebuggingOptions);

      FRIDA_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyArguments);
      FRIDA_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyEnvironment);
      FRIDA_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyStandardOutPath);
      FRIDA_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyStandardErrorPath);
      FRIDA_ASSIGN_FBS_CONSTANT (FBSDebugOptionKeyDisableASLR);
    }

    frida_springboard_api = api;
  }

  return frida_springboard_api;
}

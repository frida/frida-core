#import "springboard.h"

#include <dlfcn.h>

static FridaSpringboardApi * frida_springboard_api = NULL;

FridaSpringboardApi *
_frida_get_springboard_api (void)
{
  if (frida_springboard_api == NULL)
  {
    FridaSpringboardApi * api;
    NSString ** str;
    id (* objc_get_class_impl) (const gchar * name);

    api = g_new (FridaSpringboardApi, 1);

    api->sbs = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (api->sbs != NULL);

    api->fbs = dlopen ("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (api->fbs != NULL);

    api->SBSCopyFrontmostApplicationDisplayIdentifier = dlsym (api->sbs, "SBSCopyFrontmostApplicationDisplayIdentifier");
    g_assert (api->SBSCopyFrontmostApplicationDisplayIdentifier != NULL);

    api->SBSCopyApplicationDisplayIdentifiers = dlsym (api->sbs, "SBSCopyApplicationDisplayIdentifiers");
    g_assert (api->SBSCopyApplicationDisplayIdentifiers != NULL);

    api->SBSCopyDisplayIdentifierForProcessID = dlsym (api->sbs, "SBSCopyDisplayIdentifierForProcessID");
    g_assert (api->SBSCopyDisplayIdentifierForProcessID != NULL);

    api->SBSCopyLocalizedApplicationNameForDisplayIdentifier = dlsym (api->sbs, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");
    g_assert (api->SBSCopyLocalizedApplicationNameForDisplayIdentifier != NULL);

    api->SBSCopyIconImagePNGDataForDisplayIdentifier = dlsym (api->sbs, "SBSCopyIconImagePNGDataForDisplayIdentifier");
    g_assert (api->SBSCopyIconImagePNGDataForDisplayIdentifier != NULL);

    api->SBSLaunchApplicationWithIdentifierAndLaunchOptions = dlsym (api->sbs, "SBSLaunchApplicationWithIdentifierAndLaunchOptions");
    g_assert (api->SBSLaunchApplicationWithIdentifierAndLaunchOptions != NULL);

    api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions = dlsym (api->sbs, "SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions");
    g_assert (api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions != NULL);

    api->SBSApplicationLaunchingErrorString = dlsym (api->sbs, "SBSApplicationLaunchingErrorString");
    g_assert (api->SBSApplicationLaunchingErrorString != NULL);

    str = dlsym (api->sbs, "SBSApplicationLaunchOptionUnlockDeviceKey");
    g_assert (str != NULL);
    api->SBSApplicationLaunchOptionUnlockDeviceKey = *str;

    objc_get_class_impl = dlsym (RTLD_DEFAULT, "objc_getClass");
    g_assert (objc_get_class_impl != NULL);

    api->FBSSystemService = objc_get_class_impl ("FBSSystemService");
    g_assert (api->FBSSystemService != nil);

    frida_springboard_api = api;
  }

  return frida_springboard_api;
}

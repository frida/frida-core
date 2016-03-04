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

    api = g_new (FridaSpringboardApi, 1);

    api->module = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (api->module != NULL);

    api->SBSCopyFrontmostApplicationDisplayIdentifier = dlsym (api->module, "SBSCopyFrontmostApplicationDisplayIdentifier");
    g_assert (api->SBSCopyFrontmostApplicationDisplayIdentifier != NULL);

    api->SBSCopyApplicationDisplayIdentifiers = dlsym (api->module, "SBSCopyApplicationDisplayIdentifiers");
    g_assert (api->SBSCopyApplicationDisplayIdentifiers != NULL);

    api->SBSCopyDisplayIdentifierForProcessID = dlsym (api->module, "SBSCopyDisplayIdentifierForProcessID");
    g_assert (api->SBSCopyDisplayIdentifierForProcessID != NULL);

    api->SBSCopyLocalizedApplicationNameForDisplayIdentifier = dlsym (api->module, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");
    g_assert (api->SBSCopyLocalizedApplicationNameForDisplayIdentifier != NULL);

    api->SBSCopyIconImagePNGDataForDisplayIdentifier = dlsym (api->module, "SBSCopyIconImagePNGDataForDisplayIdentifier");
    g_assert (api->SBSCopyIconImagePNGDataForDisplayIdentifier != NULL);

    api->SBSLaunchApplicationWithIdentifierAndLaunchOptions = dlsym (api->module, "SBSLaunchApplicationWithIdentifierAndLaunchOptions");
    g_assert (api->SBSLaunchApplicationWithIdentifierAndLaunchOptions != NULL);

    api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions = dlsym (api->module, "SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions");
    g_assert (api->SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions != NULL);

    api->SBSApplicationLaunchingErrorString = dlsym (api->module, "SBSApplicationLaunchingErrorString");
    g_assert (api->SBSApplicationLaunchingErrorString != NULL);

    str = dlsym (api->module, "SBSApplicationLaunchOptionUnlockDeviceKey");
    g_assert (str != NULL);
    api->SBSApplicationLaunchOptionUnlockDeviceKey = *str;

    api->SBSLaunchApplicationForDebugging = dlsym (api->module, "SBSLaunchApplicationForDebugging");
    g_assert (api->SBSLaunchApplicationForDebugging != NULL);

    frida_springboard_api = api;
  }

  return frida_springboard_api;
}

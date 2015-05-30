#import "springboard.h"

#include <dlfcn.h>

static FridaSpringboardApi * frida_springboard_api = NULL;

FridaSpringboardApi *
_frida_get_springboard_api (void)
{
  if (frida_springboard_api == NULL)
  {
    FridaSpringboardApi * api;

    api = g_new (FridaSpringboardApi, 1);

    api->module = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (api->module != NULL);

    api->SBSCopyDisplayIdentifierForProcessID = dlsym (api->module, "SBSCopyDisplayIdentifierForProcessID");
    g_assert (api->SBSCopyDisplayIdentifierForProcessID != NULL);

    api->SBSCopyLocalizedApplicationNameForDisplayIdentifier = dlsym (api->module, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");
    g_assert (api->SBSCopyLocalizedApplicationNameForDisplayIdentifier != NULL);

    api->SBSCopyIconImagePNGDataForDisplayIdentifier = dlsym (api->module, "SBSCopyIconImagePNGDataForDisplayIdentifier");
    g_assert (api->SBSCopyIconImagePNGDataForDisplayIdentifier != NULL);

    api->SBSLaunchApplicationWithIdentifier = dlsym (api->module, "SBSLaunchApplicationWithIdentifier");
    g_assert (api->SBSLaunchApplicationWithIdentifier != NULL);

    frida_springboard_api = api;
  }

  return frida_springboard_api;
}

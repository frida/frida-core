#ifndef __FRIDA_DARWIN_SPRINGBOARD_H__
#define __FRIDA_DARWIN_SPRINGBOARD_H__

#include <glib.h>
#import <UIKit/UIKit.h>

#define SBSApplicationLaunchUnlockDevice 4

typedef struct _FridaSpringboardApi FridaSpringboardApi;

struct _FridaSpringboardApi
{
  void * module;

  NSString * (* SBSCopyDisplayIdentifierForProcessID) (UInt32 pid);
  NSString * (* SBSCopyLocalizedApplicationNameForDisplayIdentifier) (NSString * identifier);
  NSData * (* SBSCopyIconImagePNGDataForDisplayIdentifier) (NSString * identifier);
  UInt32 (* SBSLaunchApplicationWithIdentifier) (NSString * identifier, UInt32 flags);
};

G_GNUC_INTERNAL FridaSpringboardApi * _frida_get_springboard_api (void);

#endif

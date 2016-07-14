#ifndef __FRIDA_DARWIN_SPRINGBOARD_H__
#define __FRIDA_DARWIN_SPRINGBOARD_H__

#include <glib.h>
#import <UIKit/UIKit.h>

typedef struct _FridaSpringboardApi FridaSpringboardApi;
typedef enum _FBProcessKillReason FBProcessKillReason;

enum _FBProcessKillReason
{
  FBProcessKillReasonUnknown,
  FBProcessKillReasonUser,
  FBProcessKillReasonPurge,
  FBProcessKillReasonGracefulPurge,
  FBProcessKillReasonThermal,
  FBProcessKillReasonNone,
  FBProcessKillReasonShutdown,
  FBProcessKillReasonLaunchTest,
  FBProcessKillReasonInsecureDrawing
};

@interface FBSSystemService : NSObject

+ (FBSSystemService *)sharedService;

- (pid_t)pidForApplication:(NSString *)identifier;
- (void)terminateApplication:(NSString *)identifier
                   forReason:(FBProcessKillReason)reason
                   andReport:(BOOL)report
             withDescription:(NSString *)description;

@end

struct _FridaSpringboardApi
{
  void * sbs;
  void * fbs;

  NSString * (* SBSCopyFrontmostApplicationDisplayIdentifier) (void);
  NSArray * (* SBSCopyApplicationDisplayIdentifiers) (BOOL active, BOOL debuggable);
  NSString * (* SBSCopyDisplayIdentifierForProcessID) (UInt32 pid);
  NSString * (* SBSCopyLocalizedApplicationNameForDisplayIdentifier) (NSString * identifier);
  NSData * (* SBSCopyIconImagePNGDataForDisplayIdentifier) (NSString * identifier);
  UInt32 (* SBSLaunchApplicationWithIdentifierAndLaunchOptions) (NSString * identifier, NSDictionary * options, BOOL suspended);
  UInt32 (* SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions) (NSString * identifier, NSURL * url, NSDictionary * params, NSDictionary * options, BOOL suspended);
  NSString * (* SBSApplicationLaunchingErrorString) (UInt32 error);

  NSString * SBSApplicationLaunchOptionUnlockDeviceKey;

  id FBSSystemService;
};

G_GNUC_INTERNAL FridaSpringboardApi * _frida_get_springboard_api (void);

#endif

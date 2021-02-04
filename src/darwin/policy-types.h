#import <Foundation/Foundation.h>

#define FRIDA_POLICYD_SERVICE_NAME @"re.frida.policyd"

@protocol FridaPolicyBackend

- (void)soften:(int)pid reply:(void (^)(NSError *))reply;

@end

#import "policy-server.h"

#import "policy-types.h"

#include <errno.h>
#include <signal.h>
#include <objc/message.h>
#include <sys/wait.h>

#define PT_DETACH    11
#define PT_ATTACHEXC 14

extern int ptrace(int request, pid_t pid, void *addr, int data);

@interface FridaPolicyServer (Private) <NSXPCListenerDelegate, FridaPolicyBackend>

@property (strong, nonatomic) NSXPCListener *listener;

@end

@implementation FridaPolicyServer

- (id)init {
  if ((self = [super init])) {
    NSXPCListener *(*sendInitMessage)(NSXPCListener *, SEL, NSString *) = (void *)objc_msgSend;
    self.listener = sendInitMessage([NSXPCListener alloc], @selector(initWithMachServiceName:), FRIDA_POLICYD_SERVICE_NAME);
  }
  return self;
}

- (void)run {
  [self.listener resume];
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
  newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(FridaPolicyBackend)];
  newConnection.exportedObject = self;
  [newConnection resume];
  return YES;
}

- (void)soften:(int)pid reply:(void (^)(NSError *))reply {
  if (ptrace(PT_ATTACHEXC, pid, NULL, 0) == -1) {
    NSError *error = (errno == EBUSY) ? nil : [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];
    reply(error);
    return;
  }

  int status;
  waitpid(pid, &status, 0);

  ptrace(PT_DETACH, pid, NULL, 0);

  kill(pid, SIGCONT);

  reply(nil);
}

@end

#include "inject-context.h"

#include "syscall.c"

#include <stdbool.h>
#include <unistd.h>

typedef int FridaUnloadPolicy;
typedef struct _FridaPosixInjectorState FridaPosixInjectorState;
typedef union _FridaControlMessage FridaControlMessage;

enum _FridaUnloadPolicy
{
  FRIDA_UNLOAD_POLICY_IMMEDIATE,
  FRIDA_UNLOAD_POLICY_RESIDENT,
  FRIDA_UNLOAD_POLICY_DEFERRED,
};

struct _FridaPosixInjectorState
{
  int fifo_fd;
};

union _FridaControlMessage
{
  struct cmsghdr header;
  uint8_t storage[CMSG_SPACE (sizeof (int))];
};

static void * frida_main (void * user_data);
static int frida_receive_fd (int sockfd, FridaLibcApi * libc);

static pid_t frida_gettid (void);

bool
frida_load (FridaLoaderContext * ctx)
{
  ctx->libc->pthread_create (&ctx->worker, NULL, frida_main, ctx);

  return true;
}

static void *
frida_main (void * user_data)
{
  FridaLoaderContext * ctx = user_data;
  FridaLibcApi * libc = ctx->libc;
  FridaUnloadPolicy unload_policy;
  int peer_fd, our_fd, agent_so_fd;
  char agent_path_storage[32];
  const char * agent_path;
  void * agent_handle = NULL;
  void (* agent_entrypoint) (const char * agent_parameters, FridaUnloadPolicy * unload_policy, void * injector_state);
  FridaPosixInjectorState injector_state;

  unload_policy = FRIDA_UNLOAD_POLICY_IMMEDIATE;

  peer_fd = ctx->socket_endpoints[0];
  if (peer_fd != -1)
    libc->close (peer_fd);

  our_fd = ctx->socket_endpoints[1];
  if (our_fd != -1)
  {
    agent_so_fd = frida_receive_fd (our_fd, libc);

    libc->sprintf (agent_path_storage, "/proc/self/fd/%d", agent_so_fd);
    agent_path = agent_path_storage;
  }
  else
  {
    agent_so_fd = -1;

    agent_path = ctx->agent_path;
  }

  agent_handle = libc->dlopen (agent_path, RTLD_GLOBAL | RTLD_LAZY);

  if (agent_so_fd != -1)
    libc->close (agent_so_fd);

  if (agent_handle == NULL)
    goto beach;

  agent_entrypoint = libc->dlsym (agent_handle, ctx->agent_entrypoint);
  if (agent_entrypoint == NULL)
    goto beach;

  injector_state.fifo_fd = our_fd;
  agent_entrypoint (ctx->agent_parameters, &unload_policy, &injector_state);

beach:
  if (unload_policy == FRIDA_UNLOAD_POLICY_IMMEDIATE && agent_handle != NULL)
    libc->dlclose (agent_handle);

  if (unload_policy != FRIDA_UNLOAD_POLICY_DEFERRED)
    libc->pthread_detach (ctx->worker);

  if (our_fd != -1)
  {
    FridaByeMessage bye = {
      .unload_policy = unload_policy,
      .thread_id = frida_gettid (),
    };
    libc->send (our_fd, &bye, sizeof (bye), MSG_NOSIGNAL);
    libc->close (our_fd);
  }

  return NULL;
}

static int
frida_receive_fd (int sockfd, FridaLibcApi * libc)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  FridaControlMessage control;
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,
    .msg_iov = &io,
    .msg_iovlen = 1,
    .msg_control = &control,
    .msg_controllen = sizeof (control),
  };

  res = libc->recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0)
    return -1;

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static pid_t
frida_gettid (void)
{
  return frida_syscall_0 (SYS_gettid);
}

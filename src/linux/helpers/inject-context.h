#ifndef __FRIDA_INJECT_CONTEXT_H__
#define __FRIDA_INJECT_CONTEXT_H__

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>

typedef struct _FridaBootstrapContext FridaBootstrapContext;
typedef struct _FridaLoaderContext FridaLoaderContext;
typedef struct _FridaLibcApi FridaLibcApi;
typedef struct _FridaByeMessage FridaByeMessage;

struct _FridaBootstrapContext
{
  size_t loader_size;
  void * loader_base;
  int enable_socket_endpoints;
  int socket_endpoints[2];
  FridaLibcApi * libc;
};

struct _FridaLoaderContext
{
  char * agent_path;
  char * agent_entrypoint;
  char * agent_parameters;

  int socket_endpoints[2];
  FridaLibcApi * libc;

  pthread_t worker;
};

struct _FridaLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
  int (* munmap) (void * addr, size_t length);
  int (* socketpair) (int domain, int type, int protocol, int sv[2]);
  ssize_t (* recvmsg) (int sockfd, struct msghdr * msg, int flags);
  ssize_t (* send) (int sockfd, const void * buf, size_t len, int flags);
  int (* close) (int fd);

  int (* pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg);
  int (* pthread_detach) (pthread_t thread);

  void * (* dlopen) (const char * filename, int flags);
  int (* dlclose) (void * handle);
  void * (* dlsym) (void * handle, const char * symbol);
};

struct _FridaByeMessage
{
  int unload_policy;
  pid_t thread_id;
};

#endif

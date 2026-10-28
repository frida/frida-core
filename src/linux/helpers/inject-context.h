#ifndef __FRIDA_INJECT_CONTEXT_H__
#define __FRIDA_INJECT_CONTEXT_H__

#ifdef NOLIBC
# ifdef __ANDROID__
typedef long pthread_t;
# else
typedef void * pthread_t;
typedef struct _pthread_attr_t pthread_attr_t;
typedef unsigned int socklen_t;
# endif
struct msghdr;
struct sockaddr;
#else
# include <dlfcn.h>
# include <pthread.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/socket.h>
#endif

typedef size_t FridaBootstrapStatus;
typedef struct _FridaBootstrapContext FridaBootstrapContext;
typedef struct _FridaLoaderContext FridaLoaderContext;
typedef struct _FridaLibcApi FridaLibcApi;
typedef struct _FridaMappedAgentRequest FridaMappedAgentRequest;
typedef struct _FridaMappedAgent FridaMappedAgent;
typedef struct _FridaMappedAgentOp FridaMappedAgentOp;
typedef uint32_t FridaMappedAgentOpType;
typedef uint8_t FridaMessageType;
typedef struct _FridaHelloMessage FridaHelloMessage;
typedef struct _FridaReservedMessage FridaReservedMessage;
typedef struct _FridaByeMessage FridaByeMessage;
typedef int FridaRtldFlavor;

enum _FridaBootstrapStatus
{
  FRIDA_BOOTSTRAP_ALLOCATION_SUCCESS,
  FRIDA_BOOTSTRAP_ALLOCATION_ERROR,

  FRIDA_BOOTSTRAP_SUCCESS,
  FRIDA_BOOTSTRAP_AUXV_NOT_FOUND,
  FRIDA_BOOTSTRAP_TOO_EARLY,
  FRIDA_BOOTSTRAP_LIBC_LOAD_ERROR,
  FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED,
};

struct _FridaBootstrapContext
{
  void * allocation_base;
  size_t allocation_size;

  size_t page_size;
  const char * fallback_ld;
  const char * fallback_libc;
  FridaRtldFlavor rtld_flavor;
  void * rtld_base;
  void * r_brk;
  int enable_ctrlfds;
  int ctrlfds[2];
  FridaLibcApi * libc;
};

struct _FridaLoaderContext
{
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  FridaLibcApi * libc;

  pthread_t worker;
  void * agent_handle;
  void (* agent_entrypoint_impl) (const char * data, int * unload_policy, void * injector_state);

  int agent_mapped;
  void (* agent_destructor) (void);
  void * agent_base;
  size_t agent_size;
};

struct _FridaLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, long offset);
  int (* munmap) (void * addr, size_t length);
  int (* socket) (int domain, int type, int protocol);
  int (* socketpair) (int domain, int type, int protocol, int sv[2]);
  int (* connect) (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
  ssize_t (* recvmsg) (int sockfd, struct msghdr * msg, int flags);
  ssize_t (* send) (int sockfd, const void * buf, size_t len, int flags);
  int (* fcntl) (int fd, int cmd, ...);
  int (* close) (int fd);

  int (* pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg);
  int (* pthread_detach) (pthread_t thread);

  void * (* dlopen) (const char * filename, int flags, const void * caller_addr);
  int dlopen_flags;
  int (* dlclose) (void * handle);
  void * (* dlsym) (void * handle, const char * symbol, const void * caller_addr);
  char * (* dlerror) (void);
};

struct _FridaMappedAgentRequest
{
  uint64_t size;
  uint32_t dependency_count;
  uint32_t padding;
};

struct _FridaMappedAgent
{
  uint64_t constructor;
  uint64_t destructor;
  uint64_t entrypoint;
  uint32_t op_count;
  uint32_t padding;
};

struct _FridaMappedAgentOp
{
  FridaMappedAgentOpType type;
  int32_t prot;
  uint64_t address;
  uint64_t size;
  uint64_t offset;
};

enum _FridaMappedAgentOpType
{
  FRIDA_MAPPED_AGENT_OP_WRITE,
  FRIDA_MAPPED_AGENT_OP_MAP,
  FRIDA_MAPPED_AGENT_OP_PROTECT,
  FRIDA_MAPPED_AGENT_OP_MARK_CODE,
};

enum _FridaMessageType
{
  FRIDA_MESSAGE_HELLO,
  FRIDA_MESSAGE_RESERVED,
  FRIDA_MESSAGE_READY,
  FRIDA_MESSAGE_ACK,
  FRIDA_MESSAGE_BYE,
  FRIDA_MESSAGE_ERROR_DLOPEN,
  FRIDA_MESSAGE_ERROR_DLSYM,
  FRIDA_MESSAGE_ERROR_MAP,
};

struct _FridaHelloMessage
{
  pid_t thread_id;
};

struct _FridaReservedMessage
{
  uint64_t base;
};

struct _FridaByeMessage
{
  int unload_policy;
};

enum _FridaRtldFlavor
{
  FRIDA_RTLD_UNKNOWN,
  FRIDA_RTLD_NONE,
  FRIDA_RTLD_GLIBC,
  FRIDA_RTLD_UCLIBC,
  FRIDA_RTLD_MUSL,
  FRIDA_RTLD_ANDROID,
};

#endif

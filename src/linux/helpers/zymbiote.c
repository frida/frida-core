#include <errno.h>
#include <jni.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef struct _FridaApi FridaApi;

struct _FridaApi
{
  char name[64];

  void    (* original_set_argv0) (JNIEnv * env, jobject clazz, jstring name);
  int     (* original_setcontext) (uid_t uid, bool is_system_server, const char * seinfo, const char * name);

  int     (* socket) (int domain, int type, int protocol);
  int     (* connect) (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
  int *   (* __errno) (void);
  pid_t   (* getpid) (void);
  pid_t   (* getppid) (void);
  ssize_t (* sendmsg) (int sockfd, const struct msghdr * msg, int flags);
  ssize_t (* recv) (int sockfd, void * buf, size_t len, int flags);
  int     (* close) (int fd);
  int     (* raise) (int sig);
};

static volatile const FridaApi frida =
{
  .name = "/frida-zymbiote-00000000000000000000000000000000",
};

int frida_zymbiote_replacement_setargv0 (JNIEnv * env, jobject clazz, jstring name);
int frida_zymbiote_replacement_setcontext (uid_t uid, bool is_system_server, const char * seinfo, const char * name);

static void frida_wait_for_permission_to_resume (const char * package_name, bool * revert_now);

static int frida_stop_and_return_from_setargv0 (JNIEnv * env, jobject clazz, jstring name);
static int frida_stop_and_return_from_setcontext (uid_t uid, bool is_system_server, const char * seinfo, const char * name);

static int frida_get_errno (void);

static int frida_connect (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
static ssize_t frida_sendmsg (int sockfd, const struct msghdr * msg, int flags);
static bool frida_sendmsg_all (int sockfd, struct iovec * iov, size_t iovlen, int flags);
static ssize_t frida_recv (int sockfd, void * buf, size_t len, int flags);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
int
frida_zymbiote_replacement_setargv0 (JNIEnv * env, jobject clazz, jstring name)
{
  const char * name_utf8;
  bool revert_now;

  frida.original_set_argv0 (env, clazz, name);

  name_utf8 = (*env)->GetStringUTFChars (env, name, NULL);

  frida_wait_for_permission_to_resume (name_utf8, &revert_now);

  (*env)->ReleaseStringUTFChars (env, name, name_utf8);

  if (revert_now)
  {
    __attribute__ ((musttail))
    return frida_stop_and_return_from_setargv0 (env, clazz, name);
  }

  return 0;
}

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
int
frida_zymbiote_replacement_setcontext (uid_t uid, bool is_system_server, const char * seinfo, const char * name)
{
  int res;
  bool revert_now;

  res = frida.original_setcontext (uid, is_system_server, seinfo, name);
  if (res == -1)
    return -1;

  frida_wait_for_permission_to_resume (name, &revert_now);

  if (revert_now)
  {
    __attribute__ ((musttail))
    return frida_stop_and_return_from_setcontext (uid, is_system_server, seinfo, name);
  }

  return res;
}

static void
frida_wait_for_permission_to_resume (const char * package_name, bool * revert_now)
{
  int fd;
  struct sockaddr_un addr;
  socklen_t addrlen;
  unsigned int name_len;

  *revert_now = false;

  fd = frida.socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';

  name_len = 0;
  for (unsigned int i = 0; i != sizeof (frida.name); i++)
  {
    if (frida.name[i] == '\0')
      break;

    if (1u + i >= sizeof (addr.sun_path))
      break;

    addr.sun_path[1u + i] = frida.name[i];
    name_len++;
  }

  addrlen = (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1u + name_len);

  if (frida_connect (fd, (const struct sockaddr *) &addr, addrlen) == -1)
    goto beach;

  {
    struct
    {
      uint32_t pid;
      uint32_t ppid;
      uint32_t package_name_len;
    } header;
    struct iovec iov[2];

    header.pid = frida.getpid ();
    header.ppid = frida.getppid ();

    header.package_name_len = 0;
    while (package_name[header.package_name_len] != '\0')
      header.package_name_len++;

    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof (header);

    iov[1].iov_base = (void *) package_name;
    iov[1].iov_len = header.package_name_len;

    if (!frida_sendmsg_all (fd, iov, 2, MSG_NOSIGNAL))
      goto beach;
  }

  {
    uint8_t rx;

    if (frida_recv (fd, &rx, 1, 0) != 1)
      goto beach;
  }

  *revert_now = true;

beach:
  if (fd != -1)
    frida.close (fd);
}

#if defined (__i386__)

# define FRIDA_TAILCALL_TO_RAISE_SIGSTOP()                             \
  __asm__ __volatile__ (                                               \
      "movl   $%c[sig], 4(%%esp)\n"                                    \
                                                                       \
      "call   1f\n"                                                    \
      "1: pop %%eax\n"                                                 \
                                                                       \
      "addl   $(frida-1b), %%eax\n"                                    \
      "movl   %c[raise_off](%%eax), %%eax\n"                           \
                                                                       \
      "jmp    *%%eax\n"                                                \
    :                                                                  \
    : [sig] "i" (SIGSTOP),                                             \
      [raise_off] "i" (offsetof (FridaApi, raise))                     \
    : "eax", "memory"                                                  \
  )

#elif defined (__x86_64__)

# define FRIDA_TAILCALL_TO_RAISE_SIGSTOP()                             \
  __asm__ __volatile__ (                                               \
      "mov    $%c[sig], %%edi\n"                                       \
                                                                       \
      "leaq   frida(%%rip), %%r11\n"                                   \
      "movq   %c[raise_off](%%r11), %%r11\n"                           \
                                                                       \
      "jmp    *%%r11\n"                                                \
    :                                                                  \
    : [sig] "i" (SIGSTOP),                                             \
      [raise_off] "i" (offsetof (FridaApi, raise))                     \
    : "r11", "rdi", "memory"                                           \
  )

#elif defined (__arm__)

# define FRIDA_TAILCALL_TO_RAISE_SIGSTOP()                             \
  __asm__ __volatile__ (                                               \
      "mov    r0, %[sig]\n"                                            \
                                                                       \
      "adr    r12, frida\n"                                            \
      "ldr    r12, [r12, %[raise_off]]\n"                              \
                                                                       \
      "bx     r12\n"                                                   \
    :                                                                  \
    : [sig] "i" (SIGSTOP),                                             \
      [raise_off] "i" (offsetof (FridaApi, raise))                     \
    : "r12", "memory"                                                  \
  )

#elif defined (__aarch64__)

# define FRIDA_TAILCALL_TO_RAISE_SIGSTOP()                             \
  __asm__ __volatile__ (                                               \
      "mov    w0, #%[sig]\n"                                           \
                                                                       \
      "adrp   x16, frida\n"                                            \
      "add    x16, x16, :lo12:frida\n"                                 \
      "ldr    x16, [x16, %[raise_off]]\n"                              \
                                                                       \
      "br     x16\n"                                                   \
    :                                                                  \
    : [sig] "i" (SIGSTOP),                                             \
      [raise_off] "i" (offsetof (FridaApi, raise))                     \
    : "x16", "memory"                                                  \
  )

#else
# error Unsupported architecture
#endif

__attribute__ ((naked, noinline))
static int
frida_stop_and_return_from_setargv0 (JNIEnv * env, jobject clazz, jstring name)
{
  FRIDA_TAILCALL_TO_RAISE_SIGSTOP ();
}

__attribute__ ((naked, noinline))
static int
frida_stop_and_return_from_setcontext (uid_t uid, bool is_system_server, const char * seinfo, const char * name)
{
  FRIDA_TAILCALL_TO_RAISE_SIGSTOP ();
}

static int
frida_get_errno (void)
{
  return *frida.__errno ();
}

static int
frida_connect (int sockfd, const struct sockaddr * addr, socklen_t addrlen)
{
  for (;;)
  {
    if (frida.connect (sockfd, addr, addrlen) == 0)
      return 0;

    if (frida_get_errno () == EINTR)
      continue;

    return -1;
  }
}

static ssize_t
frida_sendmsg (int sockfd, const struct msghdr * msg, int flags)
{
  for (;;)
  {
    ssize_t n = frida.sendmsg (sockfd, msg, flags);
    if (n != -1)
      return n;

    if (frida_get_errno () == EINTR)
      continue;

    return -1;
  }
}

static bool
frida_sendmsg_all (int sockfd, struct iovec * iov, size_t iovlen, int flags)
{
  size_t idx = 0;
  size_t off = 0;

  while (idx != iovlen)
  {
    struct msghdr m;

    m.msg_name = NULL;
    m.msg_namelen = 0;
    m.msg_iov = &iov[idx];
    m.msg_iovlen = iovlen - idx;
    m.msg_control = NULL;
    m.msg_controllen = 0;
    m.msg_flags = 0;

    ssize_t n = frida_sendmsg (sockfd, &m, flags);
    if (n == -1)
      return false;

    size_t remaining = n;

    while (remaining != 0)
    {
      size_t avail = iov[idx].iov_len - off;

      if (remaining < avail)
      {
        iov[idx].iov_base = iov[idx].iov_base + remaining;
        iov[idx].iov_len -= remaining;
        remaining = 0;
      }
      else
      {
        remaining -= avail;
        idx++;
        off = 0;
        if (idx == iovlen)
          break;
      }
    }
  }

  return true;
}

static ssize_t
frida_recv (int sockfd, void * buf, size_t len, int flags)
{
  for (;;)
  {
    ssize_t n = frida.recv (sockfd, buf, len, flags);
    if (n != -1)
      return n;

    if (frida_get_errno () == EINTR)
      continue;

    return -1;
  }
}

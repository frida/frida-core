#define FRIDA_PRINTF_BUFFER_SIZE (512 * 1024)

#include <errno.h>
#include <gum/gum.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_XLOCALE_H
# include <xlocale.h>
#endif

#undef memcpy
#undef sprintf
#undef snprintf
#undef vsnprintf

#if defined (HAVE_WINDOWS) || defined (HAVE_ASAN)

void
frida_run_atexit_handlers (void)
{
}

#else

#define FRIDA_SHIM_LOCK() gum_spinlock_acquire (&shim_lock)
#define FRIDA_SHIM_UNLOCK() gum_spinlock_release (&shim_lock)

typedef struct _FridaExitEntry FridaExitEntry;
typedef void (* FridaExitFunc) (gpointer user_data);

struct _FridaExitEntry
{
  FridaExitFunc func;
  gpointer user_data;
};

static FridaExitEntry * atexit_entries = NULL;
static guint atexit_count = 0;

static GumSpinlock shim_lock = GUM_SPINLOCK_INIT;

__attribute__ ((constructor)) static void
frida_init_memory (void)
{
  gum_internal_heap_ref ();
}

/*
 * Avoid destructors on i/macOS as modern toolchain versions now emit a
 * constructor per destructor, each calling __cxa_atexit().
 *
 * We want to make sure we release our heap as the very last thing we do,
 * so we shim __cxa_atexit() to make sure any destructors registered that
 * way will be run before we deallocate our internal heap.
 */

#ifndef HAVE_DARWIN

__attribute__ ((destructor)) static void
frida_deinit_memory (void)
{
  gum_internal_heap_unref ();
}

#endif

void
frida_run_atexit_handlers (void)
{
  gint i;

  for (i = (gint) atexit_count - 1; i >= 0; i--)
  {
    const FridaExitEntry * entry = &atexit_entries[i];

    entry->func (entry->user_data);
  }

  gum_free (atexit_entries);
  atexit_entries = 0;
  atexit_count = 0;
}

int
__cxa_atexit (void (* func) (void *), void * arg, void * dso_handle)
{
  FridaExitEntry * entry;

  FRIDA_SHIM_LOCK ();
  atexit_count++;
  atexit_entries = gum_realloc (atexit_entries, atexit_count * sizeof (FridaExitEntry));
  entry = &atexit_entries[atexit_count - 1];
  FRIDA_SHIM_UNLOCK ();

  entry->func = func;
  entry->user_data = arg;

  return 0;
}

#ifdef HAVE_DARWIN

int
atexit (void (* func) (void))
{
  __cxa_atexit ((FridaExitFunc) func, NULL, NULL);

  return 0;
}

#endif

void *
malloc (size_t size)
{
  return gum_malloc (size);
}

void *
calloc (size_t count, size_t size)
{
  return gum_calloc (count, size);
}

void *
realloc (void * ptr, size_t size)
{
  return gum_realloc (ptr, size);
}

int
posix_memalign (void ** memptr, size_t alignment, size_t size)
{
  gpointer result;

  result = gum_memalign (alignment, size);
  if (result == NULL)
    return ENOMEM;

  *memptr = result;
  return 0;
}

void
free (void * ptr)
{
  gum_free (ptr);
}

void *
memcpy (void * dst, const void * src, size_t n)
{
  return gum_memcpy (dst, src, n);
}

char *
strdup (const char * s)
{
  return g_strdup (s);
}

int
printf (const char * format, ...)
{
  int result;
  va_list args;
  gchar * message;

  va_start (args, format);
  result = gum_vasprintf (&message, format, args);
  va_end (args);

  fputs (message, stdout);

  g_free (message);

  return result;
}

int
fprintf (FILE * stream, const char * format, ...)
{
  int result;
  va_list args;
  gchar * message;

  va_start (args, format);
  result = gum_vasprintf (&message, format, args);
  va_end (args);

  fputs (message, stream);

  g_free (message);

  return result;
}

int
sprintf (char * string, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

int
snprintf (char * string, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
vprintf (const char * format, va_list args)
{
  int result;
  gchar * message;

  result = gum_vasprintf (&message, format, args);

  fputs (message, stdout);

  g_free (message);

  return result;
}

int
vfprintf (FILE * stream, const char * format, va_list args)
{
  int result;
  gchar * message;

  result = gum_vasprintf (&message, format, args);

  fputs (message, stream);

  g_free (message);

  return result;
}

int
vsnprintf (char * string, size_t size, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

int
__sprintf_chk (char * string, int flag, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
__snprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
__vsnprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

#ifdef HAVE_XLOCALE_H

int
sprintf_l (char * string, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

int
snprintf_l (char * string, size_t size, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
asprintf_l (char ** ret, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vasprintf (ret, format, args);
  va_end (args);

  return result;
}

#endif

#endif

#ifdef HAVE_DARWIN

/*
 * Get rid of the -lresolv dependency until we actually need it, i.e. if/when
 * we expose GLib's resolvers to JavaScript. This is however not needed for
 * our current Socket.connect() API, which is neat.
 */

#include <resolv.h>

int
res_9_init (void)
{
  g_assert_not_reached ();
  return -1;
}

int
res_9_ninit (res_9_state state)
{
  g_assert_not_reached ();
  return -1;
}

void
res_9_ndestroy (res_9_state state)
{
  g_assert_not_reached ();
}

int
res_9_nquery (res_9_state state, const char * dname, int klass, int type, u_char * answer, int anslen)
{
  g_assert_not_reached ();
  return -1;
}

int
res_9_dn_expand (const u_char * msg, const u_char * eomorig, const u_char * comp_dn, char * exp_dn, int length)
{
  g_assert_not_reached ();
  return -1;
}

#endif

#ifdef HAVE_LINUX

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

int dup3 (int old_fd, int new_fd, int flags);

int
dup (int old_fd)
{
  return syscall (__NR_dup, old_fd);
}

int
dup2 (int old_fd, int new_fd)
{
  if (new_fd == old_fd)
  {
    if (fcntl (new_fd, F_GETFD) == -1)
      return -1;
    return new_fd;
  }

  return dup3 (old_fd, new_fd, 0);
}

int
dup3 (int old_fd, int new_fd, int flags)
{
  return syscall (__NR_dup3, old_fd, new_fd, flags);
}

G_GNUC_INTERNAL long
_frida_set_errno (int n)
{
  errno = n;

  return -1;
}

#endif

#if defined (HAVE_DARWIN) && GLIB_SIZEOF_VOID_P == 8

# undef read
# undef write
# undef mmap
# undef munmap

ssize_t
read(int fildes, const void *buf, size_t nbyte)
{
  ssize_t result;

# ifdef HAVE_I386
  register          gint rdi asm ("rdi") = fildes;
  register gconstpointer rsi asm ("rsi") = buf;
  register         gsize rdx asm ("rdx") = nbyte;
  register         guint eax asm ("eax") = 0x2000003;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x16, 0x3\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" ((gsize) fildes),
        "r" (buf),
        "r" (nbyte)
      : "x0", "x1", "x2", "x16"
  );
# endif

  return result;
}

ssize_t
write(int fildes, const void *buf, size_t nbyte)
{
  ssize_t result;

# ifdef HAVE_I386
  register          gint rdi asm ("rdi") = fildes;
  register gconstpointer rsi asm ("rsi") = buf;
  register         gsize rdx asm ("rdx") = nbyte;
  register         guint eax asm ("eax") = 0x2000004;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x16, 0x4\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" ((gsize) fildes),
        "r" (buf),
        "r" (nbyte)
      : "x0", "x1", "x2", "x16"
  );
# endif

  return result;
}

void *
mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
  void * result;

# ifdef HAVE_I386
  register      gpointer rdi asm ("rdi") = addr;
  register         gsize rsi asm ("rsi") = len;
  register         gsize rdx asm ("rdx") = (gsize) prot;
  register         gsize r10 asm ("r10") = (gsize) flags;
  register         gsize  r8 asm ( "r8") = (gsize) fd;
  register         gsize  r9 asm ( "r9") = offset;
  register         guint eax asm ("eax") = 0x20000c5;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (r10),
        "r" (r8),
        "r" (r9),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 4\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x3, [sp, #16 * 1]\n\t"
      "stp x4, x5, [sp, #16 * 2]\n\t"
      "str x16, [sp, #16 * 3]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x3, %4\n\t"
      "mov x4, %5\n\t"
      "mov x5, %6\n\t"
      "mov x16, 0xc5\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x3, [sp, #16 * 1]\n\t"
      "ldp x4, x5, [sp, #16 * 2]\n\t"
      "ldr x16, [sp, #16 * 3]\n\t"
      "add sp, sp, #16 * 4\n\t"
      : "=r" (result)
      : "r" (addr),
        "r" (len),
        "r" ((gsize) prot),
        "r" ((gsize) flags),
        "r" ((gsize) fd),
        "r" (offset)
      : "x0", "x1", "x2", "x3", "x4", "x5", "x16"
  );
# endif

  return result;
}

int
munmap(void *addr, size_t len)
{
  int result;

# ifdef HAVE_I386
  register      gpointer rdi asm ("rdi") = addr;
  register         gsize rsi asm ("rsi") = len;
  register         guint eax asm ("eax") = 0x2000049;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "str x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x16, 0x49\n\t"
      "svc 0x80\n\t"
      "mov %w0, w0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldr x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" (addr),
        "r" (len)
      : "x0", "x1", "x16"
  );
# endif

  return result;
}

#endif

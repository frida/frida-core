#include "inject-context.h"

#include "syscall.c"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

typedef struct _FridaCollectLibcApiContext FridaCollectLibcApiContext;
typedef struct _FridaElfExportDetails FridaElfExportDetails;
typedef bool (* FridaFoundElfExportFunc) (const FridaElfExportDetails * details, void * user_data);

#define FRIDA_STRINGIFY(identifier) _FRIDA_STRINGIFY (identifier)
#define _FRIDA_STRINGIFY(identifier) #identifier

#define FRIDA_ELF_ST_TYPE ELF64_ST_TYPE
#define FRIDA_ELF_ST_BIND ELF64_ST_BIND

typedef Elf64_Ehdr FridaElfEhdr;
typedef Elf64_Phdr FridaElfPhdr;
typedef Elf64_Dyn FridaElfDyn;
typedef Elf64_Sym FridaElfSym;
typedef Elf64_Addr FridaElfAddr;
typedef Elf64_Word FridaElfWord;
typedef Elf64_Half FridaElfHalf;

struct _FridaCollectLibcApiContext
{
  int total_missing;
  FridaLibcApi * api;
};

struct _FridaElfExportDetails
{
  const char * name;
  void * address;
  uint8_t type;
  uint8_t bind;
};

static bool frida_collect_libc_export (const FridaElfExportDetails * details, void * user_data);

static bool frida_find_libc (char * buffer, size_t buffer_size, void ** base, const char ** path);
static void frida_enumerate_exports (FridaElfEhdr * ehdr, FridaFoundElfExportFunc func, void * user_data);
static FridaElfPhdr * frida_find_program_header_by_type (FridaElfEhdr * ehdr, FridaElfWord type);
static size_t frida_find_elf_region_upper_bound (FridaElfEhdr * ehdr, FridaElfAddr address);

static size_t frida_parse_size (const char * str);
static size_t frida_strlen (const char * str);
static bool frida_str_equals (const char * str, const char * other);
static bool frida_str_has_prefix (const char * str, const char * prefix);
static char * frida_strstr (const char * str, const char * needle);
static char * frida_strchr (const char * str, char needle);
static void frida_bzero (void * dst, size_t n);
static void * frida_memmove (void * dst, const void * src, size_t n);

static int frida_open (const char * pathname, int flags);
static int frida_close (int fd);
static ssize_t frida_read (int fd, void * buf, size_t count);
static ssize_t frida_write (int fd, const void * buf, size_t count);

__attribute__ ((unused)) static void frida_log_string (const char * str);
__attribute__ ((unused)) static void frida_log_pointer (void * ptr);
__attribute__ ((unused)) static void frida_log_size (size_t val);

size_t
frida_bootstrap (FridaBootstrapContext * ctx)
{
  char libc_buffer[2048];
  void * libc_base;
  const char * libc_path; /* FIXME: No longer used, should be removed. */
  FridaCollectLibcApiContext collect_ctx;

  if (!frida_find_libc (libc_buffer, sizeof (libc_buffer), &libc_base, &libc_path))
    return 1;

  collect_ctx.total_missing = 13;
  collect_ctx.api = ctx->libc;
  frida_bzero (collect_ctx.api, sizeof (FridaLibcApi));
  frida_enumerate_exports (libc_base, frida_collect_libc_export, &collect_ctx);
  if (collect_ctx.total_missing != 0)
    return 2;

  ctx->loader_base = ctx->libc->mmap (NULL, ctx->loader_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ctx->loader_base == MAP_FAILED)
    return 3;

  ctx->socket_endpoints[0] = -1;
  ctx->socket_endpoints[1] = -1;
  if (ctx->enable_socket_endpoints)
    ctx->libc->socketpair (AF_UNIX, SOCK_STREAM, 0, ctx->socket_endpoints);

  return 0;
}

static bool
frida_collect_libc_export (const FridaElfExportDetails * details,
                           void * user_data)
{
  FridaCollectLibcApiContext * ctx = user_data;
  FridaLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define FRIDA_TRY_COLLECT(e) \
    if (api->e == NULL && frida_str_equals (details->name, FRIDA_STRINGIFY (e))) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  FRIDA_TRY_COLLECT (printf)
  FRIDA_TRY_COLLECT (sprintf)

  FRIDA_TRY_COLLECT (mmap)
  FRIDA_TRY_COLLECT (munmap)
  FRIDA_TRY_COLLECT (socketpair)
  FRIDA_TRY_COLLECT (recvmsg)
  FRIDA_TRY_COLLECT (send)
  FRIDA_TRY_COLLECT (close)

  FRIDA_TRY_COLLECT (pthread_create)
  FRIDA_TRY_COLLECT (pthread_detach)

  FRIDA_TRY_COLLECT (dlopen)
  FRIDA_TRY_COLLECT (dlclose)
  FRIDA_TRY_COLLECT (dlsym)

beach:
  return ctx->total_missing > 0;
}

static bool
frida_find_libc (char * buffer, size_t buffer_size, void ** base, const char ** path)
{
  bool success = false;
  char proc_self_maps[] = "/proc/self/maps";
  int fd;
  char * libc_path_fragment, * cursor, * range_start;
  size_t fill_amount;
  int spaces_seen;

  *base = NULL;
  *path = NULL;

  fd = frida_open (proc_self_maps, O_RDONLY);
  if (fd == -1)
    goto beach;

  libc_path_fragment = NULL;
  fill_amount = 0;
  do
  {
    ssize_t n;

    do
      n = frida_read (fd, buffer + fill_amount, buffer_size - fill_amount - 1);
    while (n == -EINTR);
    if (n > 0)
    {
      fill_amount += n;
      buffer[fill_amount] = '\0';
    }
    if (fill_amount == 0)
      goto beach;

    cursor = buffer;
    while (true)
    {
      char * next_newline;

      next_newline = frida_strchr (cursor, '\n');
      if (next_newline == NULL)
      {
        size_t consumed = cursor - buffer;
        if (consumed != 0)
        {
          frida_memmove (buffer, buffer + consumed, fill_amount - consumed + 1);
          fill_amount -= consumed;
        }
        else
        {
          fill_amount = 0;
        }
        break;
      }
      *next_newline = '\0';

      libc_path_fragment = frida_strstr (cursor, "libc.so");
      if (libc_path_fragment != NULL)
        break;

      cursor = next_newline + 1;
    }
  }
  while (libc_path_fragment == NULL);

  for (cursor = libc_path_fragment; cursor != buffer && *cursor != '\0'; cursor--)
    ;
  range_start = (cursor != buffer) ? cursor + 1 : cursor;
  *base = (void *) frida_parse_size (range_start);

  for (spaces_seen = 0, cursor = range_start; spaces_seen != 5; cursor++)
  {
    if (*cursor == ' ')
      spaces_seen++;
  }
  while (*cursor == ' ')
    cursor++;
  *path = cursor;
  while (*cursor != '\n')
    cursor++;
  *cursor = '\0';

  success = true;

beach:
  if (fd != -1)
    frida_close (fd);

  return success;
}

static void
frida_enumerate_exports (FridaElfEhdr * ehdr, FridaFoundElfExportFunc func, void * user_data)
{
  FridaElfAddr symbols_base, strings_base;
  size_t symbols_size, strings_size;
  FridaElfPhdr * dyn;
  size_t num_entries, i;
  size_t num_symbols;

  symbols_base = 0;
  strings_base = 0;
  symbols_size = 0;
  strings_size = 0;
  dyn = frida_find_program_header_by_type (ehdr, PT_DYNAMIC);
  num_entries = dyn->p_filesz / sizeof (FridaElfDyn);
  for (i = 0; i != num_entries; i++)
  {
    FridaElfDyn * entry = (void *) ehdr + dyn->p_vaddr + (i * sizeof (FridaElfDyn));

    switch (entry->d_tag)
    {
      case DT_SYMTAB:
        symbols_base = entry->d_un.d_ptr;
        break;
      case DT_STRTAB:
        strings_base = entry->d_un.d_ptr;
        break;
      case DT_STRSZ:
        strings_size = entry->d_un.d_ptr;
        break;
      default:
        break;
    }
  }
  if (symbols_base == 0 || strings_base == 0 || strings_size == 0)
    return;
  symbols_size = frida_find_elf_region_upper_bound (ehdr, symbols_base - (FridaElfAddr) ehdr);
  if (symbols_size == 0)
    return;
  num_symbols = symbols_size / sizeof (FridaElfSym);

  for (i = 0; i != num_symbols; i++)
  {
    FridaElfSym * sym;
    bool probably_reached_end;
    FridaElfExportDetails d;

    sym = (void *) symbols_base + (i * sizeof (FridaElfSym));

    probably_reached_end = sym->st_name >= strings_size;
    if (probably_reached_end)
      break;

    if (sym->st_shndx == SHN_UNDEF)
      continue;

    d.type = FRIDA_ELF_ST_TYPE (sym->st_info);
    if (!(d.type == STT_FUNC || d.type == STT_OBJECT))
      continue;

    d.bind = FRIDA_ELF_ST_BIND (sym->st_info);
    if (!(d.bind == STB_GLOBAL || d.bind == STB_WEAK))
      continue;

    d.name = (char *) strings_base + sym->st_name;
    d.address = (void *) ehdr + sym->st_value;

    if (!func (&d, user_data))
      return;
  }
}

static FridaElfPhdr *
frida_find_program_header_by_type (FridaElfEhdr * ehdr, FridaElfWord type)
{
  FridaElfHalf i;

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    FridaElfPhdr * phdr = (void *) ehdr + ehdr->e_phoff + (i * ehdr->e_phentsize);
    if (phdr->p_type == type)
      return phdr;
  }

  return NULL;
}

static size_t
frida_find_elf_region_upper_bound (FridaElfEhdr * ehdr, FridaElfAddr address)
{
  FridaElfHalf i;

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    FridaElfPhdr * phdr = (void *) ehdr + ehdr->e_phoff + (i * ehdr->e_phentsize);
    FridaElfAddr start = phdr->p_vaddr;
    FridaElfAddr end = start + phdr->p_memsz;

    if (phdr->p_type == PT_LOAD && address >= start && address < end)
      return end - address;
  }

  return 0;
}

static size_t
frida_parse_size (const char * str)
{
  size_t result = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    char ch = *cursor;

    if (ch >= '0' && ch <= '9')
      result = (result * 16) + (ch - '0');
    else if (ch >= 'a' && ch <= 'f')
      result = (result * 16) + (10 + (ch - 'a'));
    else
      break;
  }

  return result;
}

static size_t
frida_strlen (const char * str)
{
  size_t n = 0;
  while (*str++ != '\0')
    n++;
  return n;
}

/* TODO: Avoid duplicating these here and in src/fruity/helpers */

static bool
frida_str_equals (const char * str, const char * other)
{
  char a, b;

  do
  {
    a = *str;
    b = *other;
    if (a != b)
      return false;
    str++;
    other++;
  }
  while (a != '\0');

  return true;
}

static bool
frida_str_has_prefix (const char * str, const char * prefix)
{
  char c;

  while ((c = *prefix++) != '\0')
  {
    if (*str++ != c)
      return false;
  }

  return true;
}

static char *
frida_strstr (const char * str, const char * needle)
{
  char first, c;

  first = needle[0];

  while ((c = *str) != '\0')
  {
    if (c == first && frida_str_has_prefix (str, needle))
      return (char *) str;
    str++;
  }

  return NULL;
}

static char *
frida_strchr (const char * str, char needle)
{
  const char * cursor;
  char c;

  for (cursor = (char *) str; (c = *cursor) != '\0'; cursor++)
  {
    if (c == needle)
      return (char *) cursor;
  }

  return NULL;
}

static void
frida_bzero (void * dst, size_t n)
{
  size_t offset;

  for (offset = 0; offset != n; offset++)
    ((uint8_t *) dst)[offset] = 0;
}

static void *
frida_memmove (void * dst, const void * src, size_t n)
{
  uint8_t * dst_u8 = dst;
  const uint8_t * src_u8 = src;
  size_t i;

  if (dst_u8 < src_u8)
  {
    for (i = 0; i != n; i++)
      dst_u8[i] = src_u8[i];
  }
  else if (dst_u8 > src_u8)
  {
    for (i = n; i != 0; i--)
      dst_u8[i - 1] = src_u8[i - 1];
  }

  return dst;
}

static int
frida_open (const char * pathname, int flags)
{
  return frida_syscall_2 (SYS_open, (size_t) pathname, flags);
}

static int
frida_close (int fd)
{
  return frida_syscall_1 (SYS_close, fd);
}

static ssize_t
frida_read (int fd, void * buf, size_t count)
{
  return frida_syscall_3 (SYS_read, fd, (size_t) buf, count);
}

static ssize_t
frida_write (int fd, const void * buf, size_t count)
{
  return frida_syscall_3 (SYS_write, fd, (size_t) buf, count);
}

static void
frida_log_string (const char * str)
{
  const char newline = '\n';

  frida_write (STDOUT_FILENO, str, frida_strlen (str));
  frida_write (STDOUT_FILENO, &newline, sizeof (newline));
}

static void
frida_log_pointer (void * ptr)
{
  frida_log_size ((size_t) ptr);
}

static void
frida_log_size (size_t val)
{
  char output_buf[2 + 16 + 1] = "0x";
  char * output_cursor;
  int shift;
  char nibble_to_hex[] = "0123456789abcdef";

  output_cursor = output_buf + 2;
  for (shift = (sizeof (void *) * 8) - 4; shift != -4; shift -= 4, output_cursor++)
  {
    *output_cursor = nibble_to_hex[(val >> shift) & 0xf];
  }
  *output_cursor++ = '\n';

  frida_write (STDOUT_FILENO, output_buf, output_cursor - output_buf);
}

#ifdef BUILDING_TEST_PROGRAM

#include <stdio.h>
#include <strings.h>

int
main (void)
{
  FridaLibcApi libc;
  FridaBootstrapContext ctx;
  size_t result;

  bzero (&libc, sizeof (libc));

  bzero (&ctx, sizeof (ctx));
  ctx.loader_size = 4096;
  ctx.enable_socket_endpoints = true;
  ctx.libc = &libc;

  result = frida_bootstrap (&ctx);

  printf ("result: %zu\n", result);
  printf ("loader_base: %p\n", ctx.loader_base);

  return 0;
}

#endif

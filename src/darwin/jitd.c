#include "jitd.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef HAVE_MACOS
# include <mach/mach_vm.h>
#else
# include <frida_mach_vm.h>
#endif

#define FRIDA_CS_MAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define FRIDA_CS_MAGIC_CODE_DIRECTORY 0xfade0c02
#define FRIDA_CS_MAGIC_REQUIREMENTS 0xfade0c01

#define FRIDA_CS_HASH_SHA1 1
#define FRIDA_CS_HASH_SHA1_SIZE 20

#define GUM_OFFSET_NONE -1

typedef struct _FridaJitdRequest FridaJitdRequest;
typedef struct _FridaMachOLayout FridaMachOLayout;
typedef struct _FridaCSSuperBlob FridaCSSuperBlob;
typedef struct _FridaCSBlobIndex FridaCSBlobIndex;
typedef struct _FridaCSDirectory FridaCSDirectory;
typedef struct _FridaCSRequirements FridaCSRequirements;

typedef uint32_t FridaAmfiSelector;
typedef guint FridaSandboxFilterType;

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

struct _FridaJitdRequest
{
  union __RequestUnion__frida_jitd_subsystem body;
  mach_msg_trailer_t trailer;
};

struct _FridaMachOLayout
{
  gsize total_vm_size;

  gsize header_file_size;
  gsize header_vm_size;

  gsize text_file_offset;
  gsize text_file_size;
  gsize text_vm_size;

  gsize linkedit_vm_size;

  gsize code_signature_file_offset;
  gsize code_signature_file_size;
  gsize code_signature_page_size;
  gsize code_signature_size;
  gsize code_signature_hash_count;
  gsize code_signature_hash_size;
};

struct _FridaCSBlobIndex
{
  guint32 type;
  guint32 offset;
};

struct _FridaCSSuperBlob
{
  guint32 magic;
  guint32 length;
  guint32 count;
  FridaCSBlobIndex index[];
};

struct _FridaCSDirectory
{
  guint32 magic;
  guint32 length;
  guint32 version;
  guint32 flags;
  guint32 hash_offset;
  guint32 ident_offset;
  guint32 num_special_slots;
  guint32 num_code_slots;
  guint32 code_limit;
  guint8 hash_size;
  guint8 hash_type;
  guint8 reserved_1;
  guint8 page_size;
  guint32 reserved_2;
};

struct _FridaCSRequirements
{
  guint32 magic;
  guint32 length;
  guint32 count;
};

enum _FridaAmfiSelector
{
  FRIDA_AMFI_LOAD_TRUST_CACHE                             = 2,
  FRIDA_AMFI_PURGE_CACHED_VALIDATION_RESULTS              = 4,
  FRIDA_AMFI_LOAD_COMPILATION_SERVICE_CODE_DIRECTORY_HASH = 5,
  FRIDA_AMFI_IS_CDHASH_IN_TRUST_CACHE                     = 6,
  FRIDA_AMFI_LOAD_TRUST_CACHE_WITH_MANIFEST               = 7,
  FRIDA_AMFI_VALIDATE_SIGNATURE                           = 8,
  FRIDA_AMFI_SET_DENYLIST                                 = 9,
};

enum _FridaSandboxFilterType
{
  FRIDA_SANDBOX_FILTER_PATH = 1,
};

extern kern_return_t bootstrap_register (mach_port_t bp, const char * service_name, mach_port_t sp);

extern char * sandbox_extension_issue_file (const char * permission, const char * path, int flags);

extern CFMutableDictionaryRef IOServiceMatching (const char * name);
extern io_service_t IOServiceGetMatchingService (mach_port_t master_port, CFDictionaryRef matching);
extern kern_return_t IOServiceOpen (io_service_t service, task_port_t owning_task, uint32_t type, io_connect_t * connect);
extern kern_return_t IOConnectCallMethod (mach_port_t connection, uint32_t selector, const uint64_t * input, uint32_t input_count,
    const void * input_struct, size_t input_struct_count, uint64_t * output, uint32_t * output_count,
    void * output_struct, size_t * output_struct_count);

extern const mach_port_t kIOMasterPortDefault;

static void frida_compute_macho_layout (gsize text_file_size, gsize text_vm_size, FridaMachOLayout * layout);
static void frida_put_macho_headers (const gchar * dylib_path, const FridaMachOLayout * layout, gpointer output, gsize * output_size);
static void frida_put_code_signature (gconstpointer header, gconstpointer text, const FridaMachOLayout * layout, gpointer output,
    gpointer code_directory_hash);

static gint frida_file_open_tmp (const gchar * tmpl, gchar ** name_used);
static void frida_file_write_all (gint fd, gssize offset, gconstpointer data, gsize size);
static gboolean frida_file_check_sandbox_allows (const gchar * path, const gchar * operation);

#define frida_jitd_mark frida_jitd_do_mark
#include "jitd-server.c"

static io_connect_t amfi_connection;

int
main (int argc, char * argv[])
{
  kern_return_t kr;
  mach_port_t listening_port;
  io_service_t amfi_service;

  glib_init ();

  kr = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &listening_port);
  g_assert (kr == KERN_SUCCESS);

  kr = bootstrap_register (bootstrap_port, FRIDA_JITD_SERVICE_NAME, listening_port);
  if (kr != KERN_SUCCESS)
    goto checkin_error;

  amfi_service = IOServiceGetMatchingService (kIOMasterPortDefault, IOServiceMatching ("AppleMobileFileIntegrity"));
  if (!MACH_PORT_VALID (amfi_service))
    goto amfi_not_found;

  kr = IOServiceOpen (amfi_service, mach_task_self (), 0, &amfi_connection);
  if (kr != KERN_SUCCESS)
    goto amfi_open_failure;

  while (TRUE)
  {
    FridaJitdRequest request;
    union __ReplyUnion__frida_jitd_subsystem reply;
    mach_msg_header_t * header_in, * header_out;
    boolean_t handled;

    bzero (&request, sizeof (request));

    header_in = (mach_msg_header_t *) &request;
    header_in->msgh_size = sizeof (request);
    header_in->msgh_local_port = listening_port;

    kr = mach_msg_receive (header_in);
    if (kr != KERN_SUCCESS)
      break;

    header_out = (mach_msg_header_t *) &reply;

    handled = frida_jitd_server (header_in, header_out);
    if (handled)
      mach_msg_send (header_out);

    mach_msg_destroy (header_in);
  }

  return 0;

checkin_error:
  {
    fputs ("Unable to check in with launchd: are we running standalone?\n", stderr);
    return 1;
  }
amfi_not_found:
  {
    fputs ("Unable to find AMFI: missing entitlement?\n", stderr);
    return 2;
  }
amfi_open_failure:
  {
    fputs ("Unable to open AMFI: missing entitlement?\n", stderr);
    return 3;
  }
}

kern_return_t
frida_jitd_do_mark (mach_port_t server, vm_map_t task, mach_vm_address_t source_address, mach_vm_size_t source_size,
    mach_vm_address_t * target_address)
{
  kern_return_t kr;
  gsize page_size, vm_size;
  FridaMachOLayout layout;
  gint fd = -1;
  gchar * dylib_path = NULL;
  guint8 * dylib_header = NULL;
  gsize dylib_header_size;
  gpointer code = NULL;
  mach_vm_size_t n;
  guint8 * code_signature = NULL;
  guint8 code_directory_hash[20];
  fsignatures_t sigs;
  gint res;
  gpointer mapped_code = MAP_FAILED;
  int remap_flags;
  vm_prot_t cur_protection, max_protection;

  page_size = getpagesize ();
  vm_size = (source_size + page_size - 1) & ~(page_size - 1);
  frida_compute_macho_layout (source_size, vm_size, &layout);

  errno = 0;
  fd = frida_file_open_tmp ("frida-XXXXXX.dylib", &dylib_path);
  g_printerr ("frida_file_open_tmp() => fd=%d errno=%d\n", fd, errno);
  if (fd == -1)
    goto filesystem_failure;

  dylib_header = g_malloc0 (layout.header_file_size);
  frida_put_macho_headers (dylib_path, &layout, dylib_header, &dylib_header_size);

  mach_vm_address_t code_address = 0;
  kr = mach_vm_allocate (mach_task_self (), &code_address, vm_size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS)
    goto beach;
  kr = mach_vm_read_overwrite (task, source_address, source_size, code_address, &n);
  if (kr != KERN_SUCCESS)
    goto beach;
  code = GSIZE_TO_POINTER (code_address);

  code_signature = g_malloc0 (layout.code_signature_file_size);
  frida_put_code_signature (dylib_header, code, &layout, code_signature, code_directory_hash);

  frida_file_write_all (fd, GUM_OFFSET_NONE, dylib_header, dylib_header_size);
  frida_file_write_all (fd, layout.text_file_offset, code, layout.text_vm_size);
  frida_file_write_all (fd, layout.code_signature_file_offset, code_signature, layout.code_signature_file_size);

  close (fd);
  fd = open (dylib_path, O_RDONLY);
  g_printerr ("ok let's try this\n");

  kr = IOConnectCallMethod (amfi_connection, FRIDA_AMFI_LOAD_COMPILATION_SERVICE_CODE_DIRECTORY_HASH, NULL, 0,
      code_directory_hash, sizeof (code_directory_hash), NULL, 0, NULL, 0);
  if (kr != KERN_SUCCESS)
    goto beach;

  sigs.fs_file_start = 0;
  sigs.fs_blob_start = GSIZE_TO_POINTER (layout.code_signature_file_offset);
  sigs.fs_blob_size = layout.code_signature_file_size;

  res = fcntl (fd, F_ADDFILESIGS, &sigs);
  if (res != 0)
    goto codesign_failure;

  gchar message[512] = { 0, };
  struct fchecklv info;
  info.lv_file_start = 0;
  info.lv_error_message_size = sizeof (message);
  info.lv_error_message = message;
  res = fcntl (fd, F_CHECK_LV, &info);
  g_printerr ("F_CHECK_LV => res=%d message=\"%s\"\n", res, message);

  mach_vm_address_t load_address = 0;
  kr = mach_vm_allocate (mach_task_self (), &load_address, layout.total_vm_size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS)
    goto beach;

  gpointer mapped_header;
  mapped_header = mmap (GSIZE_TO_POINTER (load_address), layout.header_file_size, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, 0);
  if (mapped_header == MAP_FAILED)
    goto mmap_failure;

  gpointer mapped_linkedit;
  mapped_linkedit = mmap (GSIZE_TO_POINTER (load_address + layout.header_vm_size + layout.text_vm_size), layout.linkedit_vm_size,
      PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, layout.code_signature_file_offset);
  if (mapped_linkedit == MAP_FAILED)
    goto mmap_failure;

  mapped_code = mmap (GSIZE_TO_POINTER (load_address + layout.header_vm_size), layout.text_file_size, PROT_READ | PROT_EXEC,
      MAP_FIXED | MAP_PRIVATE, fd, layout.text_file_offset);
  if (mapped_code == MAP_FAILED)
    goto mmap_failure;

#if 0
  kr = mach_vm_protect (mach_task_self (), (mach_vm_address_t) mapped_code, layout.text_vm_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
  g_printerr ("mach_vm_protect() kr1=%d\n", kr);

  if (kr != KERN_SUCCESS)
  {
    mach_vm_address_t address = (mach_vm_address_t) mapped_code;

    kr = mach_vm_protect (mach_task_self (), address, vm_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    g_printerr ("mach_vm_protect() kr2=%d\n", kr);

    kr = mach_vm_protect (mach_task_self (), address, vm_size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY);
    g_printerr ("mach_vm_protect() kr3=%d!\n", kr);
  }
#endif

#if 0
  kr = mach_vm_protect (mach_task_self (), (mach_vm_address_t) mapped_code, vm_size, TRUE, VM_PROT_READ | VM_PROT_EXECUTE);
  g_printerr ("mach_vm_protect() ayA kr=%d\n", kr);
  if (kr != KERN_SUCCESS)
  {
    kr = mach_vm_protect (mach_task_self (), (mach_vm_address_t) mapped_code, vm_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    g_printerr ("mach_vm_protect() B kr=%d\n", kr);
  }

  if (kr != KERN_SUCCESS)
  {
    kr = mach_vm_protect (mach_task_self (), (mach_vm_address_t) mapped_code, vm_size, TRUE, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY);
    g_printerr ("mach_vm_protect() C kr=%d\n", kr);
  }
  if (kr != KERN_SUCCESS)
  {
    kr = mach_vm_protect (mach_task_self (), (mach_vm_address_t) mapped_code, vm_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY);
    g_printerr ("mach_vm_protect() D kr=%d\n", kr);
  }
  if (kr != KERN_SUCCESS)
  {
    void (* foo) (void) = ptrauth_sign_unauthenticated (mapped_code, ptrauth_key_asia, NULL);
    foo ();
    goto beach;
  }
#endif

  {
    void (* foo) (void) = ptrauth_sign_unauthenticated (mapped_code, ptrauth_key_asia, NULL);
    g_printerr ("here we go again...!\n");
    foo ();
  }

  if (*target_address == 0)
  {
    remap_flags = VM_FLAGS_ANYWHERE;
  }
  else
  {
    remap_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;

    kr = mach_vm_deallocate (task, *target_address, vm_size);
    if (kr != KERN_SUCCESS)
      goto beach;
  }

  kr = mach_vm_remap (task, target_address, vm_size, 0, remap_flags, mach_task_self (), (mach_vm_address_t) mapped_code, FALSE,
      &cur_protection, &max_protection, VM_INHERIT_SHARE);
  if (kr != KERN_SUCCESS)
    goto beach;

  g_printerr ("mach_vm_remap() b00m => kr=%d\n", kr);

#if 0
  kr = mach_vm_protect (task, *target_address, vm_size, TRUE, VM_PROT_READ | VM_PROT_EXECUTE);
  g_printerr ("mach_vm_protect() w/ set maximum kr=%d\n", kr);
#endif

  goto beach;

filesystem_failure:
codesign_failure:
mmap_failure:
  {
    kr = KERN_FAILURE;
    goto beach;
  }
beach:
  {
    if (mapped_code != MAP_FAILED)
      munmap (mapped_code, vm_size);

    if (dylib_path != NULL)
      unlink (dylib_path);

    g_free (code_signature);
    g_free (code);
    g_free (dylib_header);
    g_free (dylib_path);

    if (fd != -1)
      close (fd);

    return kr;
  }
}

static void
frida_compute_macho_layout (gsize text_file_size, gsize text_vm_size, FridaMachOLayout * layout)
{
  gsize page_size, cs_page_size, cs_hash_count, cs_hash_size;
  gsize cs_size, cs_file_size;

  page_size = getpagesize ();

  layout->header_file_size = page_size;
  layout->header_vm_size = page_size;

  layout->text_file_offset = layout->header_file_size;
  //layout->text_file_size = text_file_size;
  layout->text_file_size = text_vm_size;
  layout->text_vm_size = text_vm_size;

  cs_page_size = 4096;
  cs_hash_count = (layout->text_file_offset + layout->text_file_size) / cs_page_size;
  cs_hash_size = FRIDA_CS_HASH_SHA1_SIZE;

  cs_size = 125 + (cs_hash_count * cs_hash_size);
  cs_file_size = cs_size;
  if (cs_file_size % 4 != 0)
    cs_file_size += 4 - (cs_file_size % 4);

  layout->code_signature_file_offset = layout->text_file_offset + layout->text_file_size;
  layout->code_signature_file_size = cs_file_size;
  layout->code_signature_page_size = cs_page_size;
  layout->code_signature_size = cs_size;
  layout->code_signature_hash_count = cs_hash_count;
  layout->code_signature_hash_size = cs_hash_size;

  layout->linkedit_vm_size = (cs_file_size + page_size - 1) & ~(page_size - 1);

  layout->total_vm_size = layout->header_vm_size + layout->text_vm_size + layout->linkedit_vm_size;
}

static void
frida_put_macho_headers (const gchar * dylib_path, const FridaMachOLayout * layout, gpointer output, gsize * output_size)
{
  gsize dylib_path_size, page_size;
  struct mach_header_64 * header = output;
  struct segment_command_64 * seg, * text_segment, * linkedit_segment;
  struct section_64 * sect;
  struct dylib_command * dl;
  struct linkedit_data_command * sig;

  dylib_path_size = strlen (dylib_path);
  page_size = getpagesize ();

  header->magic = MH_MAGIC_64;
  header->cputype = CPU_TYPE_ARM64;
  header->cpusubtype = CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI | CPU_SUBTYPE_LITTLE_ENDIAN;
  header->filetype = MH_DYLIB;
  header->ncmds = 5;
  header->flags = MH_DYLDLINK | MH_PIE;

  seg = (struct segment_command_64 *) (header + 1);
  seg->cmd = LC_SEGMENT_64;
  seg->cmdsize = sizeof (struct segment_command_64);
  strcpy (seg->segname, SEG_PAGEZERO);
  seg->vmaddr = 0;
  seg->vmsize = page_size;
  seg->fileoff = 0;
  seg->filesize = 0;
  seg->maxprot = VM_PROT_NONE;
  seg->initprot = VM_PROT_NONE;
  seg->nsects = 0;
  seg->flags = 0;

  seg++;
  seg->cmd = LC_SEGMENT_64;
  seg->cmdsize = sizeof (struct segment_command_64) + sizeof (struct section_64);
  strcpy (seg->segname, SEG_TEXT);
  seg->vmaddr = layout->text_file_offset;
  seg->vmsize = layout->text_vm_size;
  seg->fileoff = layout->text_file_offset;
  seg->filesize = layout->text_file_size;
  seg->maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
  seg->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
  seg->nsects = 1;
  seg->flags = 0;
  sect = (struct section_64 *) (seg + 1);
  strcpy (sect->sectname, SECT_TEXT);
  strcpy (sect->segname, SEG_TEXT);
  sect->addr = layout->text_file_offset;
  sect->size = layout->text_vm_size;
  sect->offset = layout->text_file_offset;
  sect->align = 4;
  sect->reloff = 0;
  sect->nreloc = 0;
  sect->flags = S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
  text_segment = seg;

  seg = (struct segment_command_64 *) (sect + 1);
  seg->cmd = LC_SEGMENT_64;
  seg->cmdsize = sizeof (struct segment_command_64);
  strcpy (seg->segname, SEG_LINKEDIT);
  seg->vmaddr = text_segment->vmaddr + text_segment->vmsize;
  seg->vmsize = layout->linkedit_vm_size;
  seg->fileoff = layout->code_signature_file_offset;
  seg->filesize = layout->code_signature_file_size;
  seg->maxprot = VM_PROT_READ;
  seg->initprot = VM_PROT_READ;
  seg->nsects = 0;
  seg->flags = 0;
  linkedit_segment = seg;

  dl = (struct dylib_command *) (seg + 1);
  dl->cmd = LC_ID_DYLIB;
  dl->cmdsize = sizeof (struct dylib_command) + dylib_path_size;
  if ((dl->cmdsize % 8) != 0)
    dl->cmdsize += 8 - (dl->cmdsize % 8);
  dl->dylib.name.offset = sizeof (struct dylib_command);
  dl->dylib.timestamp = 0;
  dl->dylib.current_version = 0;
  dl->dylib.compatibility_version = 0;
  memcpy ((gchar *) (dl + 1), dylib_path, dylib_path_size);

  sig = (struct linkedit_data_command *) (((guint8 *) dl) + dl->cmdsize);
  sig->cmd = LC_CODE_SIGNATURE;
  sig->cmdsize = sizeof (struct linkedit_data_command);
  sig->dataoff = layout->code_signature_file_offset;
  sig->datasize = layout->code_signature_file_size;

  header->sizeofcmds = ((guint8 *) (sig + 1)) - ((guint8 *) (header + 1));

  *output_size = sizeof (struct mach_header_64) + header->sizeofcmds;
}

static void
frida_put_code_signature (gconstpointer header, gconstpointer text, const FridaMachOLayout * layout, gpointer output,
    gpointer code_directory_hash)
{
  FridaCSSuperBlob * sb;
  FridaCSBlobIndex * bi;
  FridaCSDirectory * dir;
  gsize dir_size;
  guint8 * ident, * hashes;
  gsize cs_hashes_size, cs_page_size;
  FridaCSRequirements * req;
  gsize i;

  cs_hashes_size = layout->code_signature_hash_count * layout->code_signature_hash_size;

  sb = output;
  sb->magic = GUINT32_TO_BE (FRIDA_CS_MAGIC_EMBEDDED_SIGNATURE);
  sb->length = GUINT32_TO_BE (layout->code_signature_size);
  sb->count = GUINT32_TO_BE (2);

  bi = &sb->index[0];
  bi->type = GUINT32_TO_BE (0);
  bi->offset = GUINT32_TO_BE (28);

  bi = &sb->index[1];
  bi->type = GUINT32_TO_BE (2);
  bi->offset = GUINT32_TO_BE (113 + cs_hashes_size);

  dir = (FridaCSDirectory *) (bi + 1);

  ident = ((guint8 *) dir) + 44;
  hashes = ident + 41;

  dir->magic = GUINT32_TO_BE (FRIDA_CS_MAGIC_CODE_DIRECTORY);
  dir_size = 85 + cs_hashes_size;
  dir->length = GUINT32_TO_BE (dir_size);
  dir->version = GUINT32_TO_BE (0x00020001);
  dir->flags = GUINT32_TO_BE (0);
  dir->hash_offset = GUINT32_TO_BE (hashes - (guint8 *) dir);
  dir->ident_offset = GUINT32_TO_BE (ident - (guint8 *) dir);
  dir->num_special_slots = GUINT32_TO_BE (2);
  dir->num_code_slots = GUINT32_TO_BE (layout->code_signature_hash_count);
  dir->code_limit = GUINT32_TO_BE (layout->text_file_offset + layout->text_file_size);
  dir->hash_size = layout->code_signature_hash_size;
  dir->hash_type = FRIDA_CS_HASH_SHA1;
  dir->page_size = log2 (layout->code_signature_page_size);

  req = (FridaCSRequirements *) (hashes + cs_hashes_size);
  req->magic = GUINT32_TO_BE (FRIDA_CS_MAGIC_REQUIREMENTS);
  req->length = GUINT32_TO_BE (12);
  req->count = GUINT32_TO_BE (0);

  CC_SHA1 (req, 12, ident + 1);

  cs_page_size = layout->code_signature_page_size;

  for (i = 0; i != layout->header_file_size / cs_page_size; i++)
  {
    CC_SHA1 (header + (i * cs_page_size), cs_page_size, hashes);
    hashes += 20;
  }

  for (i = 0; i != layout->text_file_size / cs_page_size; i++)
  {
    CC_SHA1 (text + (i * cs_page_size), cs_page_size, hashes);
    hashes += 20;
  }

  CC_SHA1 (dir, dir_size, code_directory_hash);
}

static gint
frida_file_open_tmp (const gchar * tmpl, gchar ** name_used)
{
  gchar * path;
  gint res;

  path = g_build_filename ("/var/mobile", tmpl, NULL);
  res = g_mkstemp (path);

  if (!frida_file_check_sandbox_allows (path, "file-map-executable"))
  {
    char * token = sandbox_extension_issue_file ("file-map-executable", path, 0);
    g_printerr ("oh no, sandbox does not allow it for %s, token=%s!!\n", path, token);
    g_abort ();
  }

  if (res != -1)
  {
    *name_used = path;
  }
  else
  {
    *name_used = NULL;
    g_free (path);
  }

  return res;
}

static void
frida_file_write_all (gint fd, gssize offset, gconstpointer data, gsize size)
{
  gssize written;

  if (offset != GUM_OFFSET_NONE)
    lseek (fd, offset, SEEK_SET);

  written = 0;
  do
  {
    gint res;

    res = write (fd, data + written, size - written);
    if (res == -1)
    {
      if (errno == EINTR)
        continue;
      else
        return;
    }

    written += res;
  }
  while (written != size);
}

static gboolean
frida_file_check_sandbox_allows (const gchar * path, const gchar * operation)
{
  static gsize initialized = FALSE;
  static gint (* check) (pid_t pid, const gchar * operation, FridaSandboxFilterType type, ...) = NULL;
  static FridaSandboxFilterType no_report = 0;

  if (g_once_init_enter (&initialized))
  {
    void * sandbox;

    sandbox = dlopen ("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOLOAD | RTLD_LAZY);
    if (sandbox != NULL)
    {
      FridaSandboxFilterType * no_report_ptr;

      no_report_ptr = dlsym (sandbox, "SANDBOX_CHECK_NO_REPORT");
      if (no_report_ptr != NULL)
      {
        no_report = *no_report_ptr;

        check = dlsym (sandbox, "sandbox_check");
      }

      dlclose (sandbox);
    }

    g_once_init_leave (&initialized, TRUE);
  }

  if (check == NULL)
  {
    g_printerr ("check=NULL\n");
    return TRUE;
  }

  g_printerr ("calling check()\n");
  return !check (getpid (), operation, FRIDA_SANDBOX_FILTER_PATH | no_report,
      path);
}

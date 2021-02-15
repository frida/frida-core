#include "jitd.h"

#include <CommonCrypto/CommonDigest.h>
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

struct _FridaJitdRequest
{
  union __RequestUnion__frida_jitd_subsystem body;
  mach_msg_trailer_t trailer;
};

struct _FridaMachOLayout
{
  gsize header_file_size;

  gsize text_file_offset;
  gsize text_file_size;
  gsize text_size;

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

extern kern_return_t bootstrap_register (mach_port_t bp, const char * service_name, mach_port_t sp);

static void frida_compute_macho_layout (gsize text_file_size, gsize text_vm_size, FridaMachOLayout * layout);
static void frida_put_macho_headers (const gchar * dylib_path, const FridaMachOLayout * layout, gpointer output, gsize * output_size);
static void frida_put_code_signature (gconstpointer header, gconstpointer text, const FridaMachOLayout * layout, gpointer output);

static gint frida_file_open_tmp (const gchar * tmpl, gchar ** name_used);
static void frida_file_write_all (gint fd, gssize offset, gconstpointer data, gsize size);

#define frida_jitd_mark frida_jitd_do_mark
#include "jitd-server.c"

int
main (int argc, char * argv[])
{
  kern_return_t kr;
  mach_port_t listening_port;

  glib_init ();

  kr = mach_port_allocate (mach_task_self (), MACH_PORT_RIGHT_RECEIVE, &listening_port);
  g_assert (kr == KERN_SUCCESS);

  kr = bootstrap_register (bootstrap_port, FRIDA_JITD_SERVICE_NAME, listening_port);
  if (kr != KERN_SUCCESS)
    goto checkin_error;

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
}

kern_return_t
frida_jitd_do_mark (mach_port_t server, vm_map_t task, mach_vm_address_t source_address, mach_vm_size_t source_size,
    mach_vm_address_t * target_address)
{
  kern_return_t kr;
  gpointer code;
  mach_vm_size_t n;
  gint fd = -1;
  gchar * dylib_path = NULL;
  gsize page_size, vm_size;
  FridaMachOLayout layout;
  guint8 * dylib_header = NULL;
  gsize dylib_header_size;
  guint8 * code_signature = NULL;
  fsignatures_t sigs;
  gint res;
  gpointer mapped_code = MAP_FAILED;
  gboolean target_allocated = FALSE;
  vm_prot_t cur_protection, max_protection;

  code = g_malloc (source_size);
  kr = mach_vm_read_overwrite (task, source_address, source_size, (mach_vm_address_t) code, &n);
  if (kr != KERN_SUCCESS)
    goto beach;

  page_size = getpagesize ();
  vm_size = (source_size + page_size - 1) & ~(page_size - 1);
  frida_compute_macho_layout (source_size, vm_size, &layout);

  fd = frida_file_open_tmp ("frida-XXXXXX.dylib", &dylib_path);
  if (fd == -1)
    goto filesystem_failure;

  dylib_header = g_malloc0 (layout.header_file_size);
  frida_put_macho_headers (dylib_path, &layout, dylib_header, &dylib_header_size);

  code_signature = g_malloc0 (layout.code_signature_file_size);
  frida_put_code_signature (dylib_header, code, &layout, code_signature);

  frida_file_write_all (fd, GUM_OFFSET_NONE, dylib_header, dylib_header_size);
  frida_file_write_all (fd, layout.text_file_offset, code, layout.text_size);
  frida_file_write_all (fd, layout.code_signature_file_offset, code_signature, layout.code_signature_file_size);

  sigs.fs_file_start = 0;
  sigs.fs_blob_start = GSIZE_TO_POINTER (layout.code_signature_file_offset);
  sigs.fs_blob_size = layout.code_signature_file_size;

  res = fcntl (fd, F_ADDFILESIGS, &sigs);
  if (res != 0)
    goto codesign_failure;

  mapped_code = mmap (NULL, vm_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, page_size);
  if (mapped_code == MAP_FAILED)
    goto mmap_failure;

  if (*target_address == 0)
  {
    kr = mach_vm_allocate (task, target_address, vm_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
      goto beach;
    target_allocated = TRUE;
  }

  kr = mach_vm_remap (task, target_address, vm_size, 0, VM_FLAGS_OVERWRITE, mach_task_self (), (mach_vm_address_t) mapped_code, TRUE,
      &cur_protection, &max_protection, VM_INHERIT_COPY);

  goto beach;

filesystem_failure:
  {
    kr = KERN_FAILURE;
    goto beach;
  }
codesign_failure:
  {
    kr = KERN_FAILURE;
    goto beach;
  }
mmap_failure:
  {
    kr = KERN_FAILURE;
    goto beach;
  }
beach:
  {
    if (target_allocated)
      mach_vm_deallocate (task, *target_address, vm_size);

    if (mapped_code != MAP_FAILED)
      munmap (mapped_code, vm_size);

    if (dylib_path != NULL)
      unlink (dylib_path);

    g_free (code_signature);
    g_free (dylib_header);
    g_free (dylib_path);

    if (fd != -1)
      close (fd);

    g_free (code);

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

  layout->text_file_offset = layout->header_file_size;
  layout->text_file_size = text_file_size;
  layout->text_size = text_vm_size;

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
}

static void
frida_put_macho_headers (const gchar * dylib_path, const FridaMachOLayout * layout, gpointer output, gsize * output_size)
{
  gsize dylib_path_size;
  struct mach_header_64 * header = output;
  struct segment_command_64 * seg, * text_segment, * linkedit_segment;
  struct section_64 * sect;
  struct dylib_command * dl;
  struct linkedit_data_command * sig;

  dylib_path_size = strlen (dylib_path);

  header->magic = MH_MAGIC_64;
  header->cputype = CPU_TYPE_ARM64;
  header->cpusubtype = CPU_SUBTYPE_LITTLE_ENDIAN;
  header->filetype = MH_DYLIB;
  header->ncmds = 5;
  header->flags = MH_DYLDLINK | MH_PIE;

  seg = (struct segment_command_64 *) (header + 1);
  seg->cmd = LC_SEGMENT_64;
  seg->cmdsize = sizeof (struct segment_command_64);
  strcpy (seg->segname, SEG_PAGEZERO);
  seg->vmaddr = 0;
  seg->vmsize = getpagesize ();
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
  seg->vmsize = layout->text_file_size;
  seg->fileoff = layout->text_file_offset;
  seg->filesize = layout->text_file_size;
  seg->maxprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
  seg->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
  seg->nsects = 1;
  seg->flags = 0;
  sect = (struct section_64 *) (seg + 1);
  strcpy (sect->sectname, SECT_TEXT);
  strcpy (sect->segname, SEG_TEXT);
  sect->addr = layout->text_file_offset;
  sect->size = layout->text_size;
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
  seg->vmsize = 4096;
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
frida_put_code_signature (gconstpointer header, gconstpointer text, const FridaMachOLayout * layout, gpointer output)
{
  FridaCSSuperBlob * sb;
  FridaCSBlobIndex * bi;
  FridaCSDirectory * dir;
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
  dir->length = GUINT32_TO_BE (85 + cs_hashes_size);
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
}

static gint
frida_file_open_tmp (const gchar * tmpl, gchar ** name_used)
{
  gchar * path;
  gint res;

  path = g_build_filename (g_get_tmp_dir (), tmpl, NULL);
  res = g_mkstemp (path);
  if (res == -1)
  {
    g_free (path);
    path = g_build_filename ("/Library/Caches", tmpl, NULL);
    res = g_mkstemp (path);
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

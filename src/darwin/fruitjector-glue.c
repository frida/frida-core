#include "frida-core.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>

static void update_mach_uuid_32 (struct mach_header * mach_header);
static void update_mach_uuid_64 (struct mach_header_64 * mach_header);
static void update_uuid (struct uuid_command * uc);

GInputStream *
_frida_agent_resource_clone_dylib (GInputStream * dylib)
{
  GSeekable * seekable = G_SEEKABLE (dylib);
  goffset previous_offset, size;
  gpointer data;
  gsize read = 0;
  struct fat_header * fat_header;

  previous_offset = g_seekable_tell (seekable);
  g_seekable_seek (seekable, 0, G_SEEK_END, NULL, NULL);
  size = g_seekable_tell (seekable);
  g_seekable_seek (seekable, 0, G_SEEK_SET, NULL, NULL);

  data = g_malloc (size);
  g_input_stream_read_all (dylib, data, size, &read, NULL, NULL);
  g_assert_cmpint (read, ==, size);

  fat_header = data;
  switch (fat_header->magic)
  {
    case FAT_CIGAM:
    {
      uint32_t count, i;

      count = OSSwapInt32 (fat_header->nfat_arch);
      for (i = 0; i != count; i++)
      {
        struct fat_arch * fat_arch = ((struct fat_arch *) (fat_header + 1)) + i;
        struct mach_header * mach_header =
            data + OSSwapInt32 (fat_arch->offset);
        switch (mach_header->magic)
        {
          case MH_MAGIC:
            update_mach_uuid_32 (mach_header);
            break;
          case MH_MAGIC_64:
            update_mach_uuid_64 ((struct mach_header_64 *) mach_header);
            break;
          default:
            g_assert_not_reached ();
            break;
        }
      }

      break;
    }
    case MH_MAGIC:
      update_mach_uuid_32 ((struct mach_header *) data);
      break;
    case MH_MAGIC_64:
      update_mach_uuid_64 ((struct mach_header_64 *) data);
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  g_seekable_seek (seekable, previous_offset, G_SEEK_SET, NULL, NULL);

  return g_memory_input_stream_new_from_data (data, size, g_free);
}

static void
update_mach_uuid_32 (struct mach_header * mach_header)
{
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (mach_header + 1);
  for (cmd_index = 0; cmd_index != mach_header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_UUID)
    {
      struct uuid_command * uc = (struct uuid_command *) p;
      update_uuid (uc);
      return;
    }

    p += lc->cmdsize;
  }
}

static void
update_mach_uuid_64 (struct mach_header_64 * mach_header)
{
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (mach_header + 1);
  for (cmd_index = 0; cmd_index != mach_header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_UUID)
    {
      struct uuid_command * uc = (struct uuid_command *) p;
      update_uuid (uc);
      return;
    }

    p += lc->cmdsize;
  }
}

static void
update_uuid (struct uuid_command * uc)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (uc->uuid); i++)
    uc->uuid[i] = g_random_int_range (0, 255);
}

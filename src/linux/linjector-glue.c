#include "frida-core.h"

GInputStream *
_frida_agent_resource_clone_so (GInputStream * so)
{
  GSeekable * seekable = G_SEEKABLE (so);
  goffset previous_offset, size;
  gpointer data;
  gsize read = 0;

  previous_offset = g_seekable_tell (seekable);
  g_seekable_seek (seekable, 0, G_SEEK_END, NULL, NULL);
  size = g_seekable_tell (seekable);
  g_seekable_seek (seekable, 0, G_SEEK_SET, NULL, NULL);

  data = g_malloc (size);
  g_input_stream_read_all (so, data, size, &read, NULL, NULL);
  g_assert (read == size);

  /* TODO: update .so identity */

  g_seekable_seek (seekable, previous_offset, G_SEEK_SET, NULL, NULL);

  return g_memory_input_stream_new_from_data (data, size, g_free);
}

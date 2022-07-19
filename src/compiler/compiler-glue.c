#include "frida-core.h"

#include "frida-data-compiler.h"

#include <mz.h>
#include <mz_strm.h>
#include <mz_zip.h>
#include <mz_zip_rw.h>

void
_frida_compiler_foreach_agent_zip_entry (FridaCompilerEachAgentZipEntryFunc func, gpointer func_target)
{
  FridaDataCompilerBlob blob;
  void * reader;

  frida_data_compiler_get_agent_zip_blob (&blob);

  mz_zip_reader_create (&reader);
  mz_zip_reader_open_buffer (reader, (uint8_t *) blob.data, blob.data_length1, FALSE);

  mz_zip_reader_goto_first_entry (reader);
  do
  {
    mz_zip_file * info = NULL;
    gchar * contents;

    mz_zip_reader_entry_get_info (reader, &info);

    if (mz_zip_reader_entry_is_dir (reader) == MZ_OK)
    {
      contents = NULL;
    }
    else
    {
      const gsize size = info->uncompressed_size;

      contents = g_malloc (size + 1);
      contents[size] = '\0';

      mz_zip_reader_entry_open (reader);
      mz_zip_reader_entry_read (reader, contents, size);
      mz_zip_reader_entry_close (reader);
    }

    func (info->filename, contents, func_target);
  }
  while (mz_zip_reader_goto_next_entry (reader) == MZ_OK);

  mz_zip_reader_close (reader);
  mz_zip_reader_delete (&reader);
}

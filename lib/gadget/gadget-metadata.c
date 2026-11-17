#include "frida-gadget-metadata.h"

#include <glib.h>

#if defined (HAVE_WINDOWS)

# ifdef _MSC_VER
#  pragma section (".package", read)
__declspec (allocate (".package"))
# else
__attribute__ ((used, section (".package")))
# endif
const gchar frida_gadget_metadata[] = FRIDA_GADGET_METADATA;

# ifdef _MSC_VER
#  ifdef _M_IX86
#   pragma comment (linker, "/INCLUDE:_frida_gadget_metadata")
#  else
#   pragma comment (linker, "/INCLUDE:frida_gadget_metadata")
#  endif
# endif

#elif defined (HAVE_DARWIN)

__attribute__ ((used, section ("__TEXT,__package,regular,no_dead_strip")))
static const gchar frida_gadget_metadata[] = FRIDA_GADGET_METADATA;

#else

#define FRIDA_NOTE_TYPE_PACKAGE_METADATA 0xcafe1a7e
#define FRIDA_NOTE_ALIGN(n) (((n) + 3) & ~3)

__attribute__ ((used, aligned (4), section (".note.package")))
static const struct
{
  guint32 name_size;
  guint32 desc_size;
  guint32 type;
  gchar name[4];
  gchar desc[FRIDA_NOTE_ALIGN (sizeof (FRIDA_GADGET_METADATA))];
} frida_gadget_metadata_note =
{
  sizeof ("FDO"),
  sizeof (FRIDA_GADGET_METADATA),
  FRIDA_NOTE_TYPE_PACKAGE_METADATA,
  "FDO",
  FRIDA_GADGET_METADATA,
};

#endif

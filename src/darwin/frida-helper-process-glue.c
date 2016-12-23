#include "frida-core.h"

#include <gum/gumdarwin.h>

gboolean
_frida_darwin_helper_process_is_mmap_available (void)
{
  return FALSE;
}

guint
_frida_darwin_helper_process_task_for_pid (guint pid, GError ** error)
{
  mach_port_t task;
  kern_return_t kr;

  kr = task_for_pid (mach_task_self (), pid, &task);
  if (kr != KERN_SUCCESS)
    goto handle_error;

  return task;

handle_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u from the current user account",
        pid);
    return 0;
  }
}

void
_frida_darwin_helper_process_mmap (guint task, GBytes * blob, FridaMappedLibraryBlob * result, GError ** error)
{
  gconstpointer data;
  gsize size, aligned_size;
  mach_vm_address_t remote_address;
  vm_prot_t cur_protection, max_protection;
  kern_return_t kr;

  data = g_bytes_get_data (blob, &size);

  remote_address = 0;
  aligned_size = (size + 16384 - 1) & ~(16384 - 1);

  kr = mach_vm_remap (task, &remote_address, aligned_size, 0, VM_FLAGS_ANYWHERE,
      mach_task_self (), GPOINTER_TO_SIZE (data), TRUE, &cur_protection, &max_protection,
      VM_INHERIT_SHARE);
  if (kr != KERN_SUCCESS)
    goto handle_error;

  kr = mach_vm_protect (task, GPOINTER_TO_SIZE (data), aligned_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  if (kr != KERN_SUCCESS)
    goto handle_error;

  frida_mapped_library_blob_init (result, remote_address, size);

  return;

handle_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to mmap (%s)",
        mach_error_string (kr));
  }
}

void
_frida_darwin_helper_process_deallocate_port (guint port)
{
  mach_port_deallocate (mach_task_self (), port);
}

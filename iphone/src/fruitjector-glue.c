#include "zid-core.h"

#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>

#define CHECK_MACH_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_mach_error; \
  }
#define CHECK_DL_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto handle_dl_error; \
  }

static guint8 code[] =
{
  0x09, 0x20, 0xa0, 0xe3,
  0x10, 0x10, 0x8f, 0xe2,
  0x01, 0x00, 0xa0, 0xe3,
  0x04, 0x30, 0x8f, 0xe2,
  0x00, 0x30, 0x93, 0xe5,
  0x33, 0xff, 0x2f, 0xe1,

  0x37, 0x13, 0x00, 0x00,
  0x48, 0x65, 0x79, 0x20, 0x6e, 0x30, 0x30, 0x62, 0x0a, 0x00,
};

void
zid_fruitjector_do_inject (ZidFruitjector * self, gint pid,
    const char * dylib_path, GError ** error)
{
  const gchar * failed_operation;
  mach_port_name_t task = 0;
  kern_return_t ret;
  void * syslib_handle = NULL;
  void * dlopen_addr, * dlclose_addr, * dlsym_addr;
  vm_address_t code_address = (vm_address_t) NULL;
  vm_address_t stack_address = (vm_address_t) NULL;
  arm_thread_state_t state;
  thread_act_t thread;

  memset (&state, 0, sizeof (state));

  ret = task_for_pid (mach_task_self (), pid, &task);
  CHECK_MACH_RESULT (ret, ==, 0, "task_for_pid");

  syslib_handle = dlopen ("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_GLOBAL);
  CHECK_DL_RESULT (syslib_handle, !=, NULL, "dlopen");

  dlopen_addr = dlsym (syslib_handle, "write"); //"dlopen");
  CHECK_DL_RESULT (dlopen_addr, !=, NULL, "dlsym(\"dlopen\")");

  dlclose_addr = dlsym (syslib_handle, "dlclose");
  CHECK_DL_RESULT (dlclose_addr, !=, NULL, "dlsym(\"dlclose\")");

  dlsym_addr = dlsym (syslib_handle, "dlsym");
  CHECK_DL_RESULT (dlsym_addr, !=, NULL, "dlsym(\"dlsym\")");

  *((gpointer *) (code + 24)) = dlopen_addr;

  ret = vm_allocate (task, &code_address, 4096, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");

  ret = vm_write (task, code_address, (vm_offset_t) code, sizeof (code));
  CHECK_MACH_RESULT (ret, ==, 0, "vm_write");

  ret = vm_protect (task, code_address, 4096, FALSE,
      VM_PROT_READ | VM_PROT_EXECUTE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_protect");

  ret = vm_allocate (task, &stack_address, 8 * 1024, TRUE);
  CHECK_MACH_RESULT (ret, ==, 0, "vm_allocate");

  g_print ("ok, remote code is at %p, stack is at %p\n",
      (void *) code_address, (void *) stack_address);

  state.__sp = (uint32_t) stack_address + 4 * 1024;
  state.__lr = 0xcafebabe;
  state.__pc = code_address;
  state.__cpsr = 0;

  ret = thread_create_running (task, ARM_THREAD_STATE,
      (thread_state_t) &state, ARM_THREAD_STATE_COUNT, &thread);
  CHECK_MACH_RESULT (ret, ==, 0, "thread_create_running");

  goto beach;

  /* ERRORS */
handle_mach_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %d", failed_operation, errno);
    goto beach;
  }
handle_dl_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "%s failed: %s", failed_operation, dlerror ());
    goto beach;
  }

  /* UNWIND */
beach:
  {
    if (syslib_handle != NULL)
      dlclose (syslib_handle);
    return;
  }
}


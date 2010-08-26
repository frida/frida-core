#include "zid-core.h"

#include <mach/mach.h>

void
zid_fruitjector_do_inject (ZidFruitjector * self, gint pid,
    const char * dylib_path, GError ** error)
{
  mach_port_name_t task = 0;
  kern_return_t ret;
  arm_thread_state_t state;
  thread_act_t thread;

  ret = task_for_pid (mach_task_self (), pid, &task);
  g_assert_cmpint (ret, ==, 0);

  ret = thread_create_running (task, ARM_THREAD_STATE,
      (thread_state_t) &state, ARM_THREAD_STATE_COUNT, &thread);
  g_assert_cmpint (ret, ==, 0);
}


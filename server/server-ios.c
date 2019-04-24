#include "server-ios.h"

#include <unistd.h>

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

int memorystatus_control (uint32_t command, int32_t pid, uint32_t flags, void * buffer, size_t buffer_size);

void
_frida_server_ios_configure (void)
{
  memorystatus_control (MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid (), 256, NULL, 0);
}

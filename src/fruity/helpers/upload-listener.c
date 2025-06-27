#include "upload-api.h"

static uint64_t frida_query_debugger_mapping_enforced (const FridaUploadApi * api);

uint64_t
frida_listen (int rx_buffer_size, const FridaUploadApi * api)
{
  uint8_t error_code;
  int fd;
  struct sockaddr_in6 addr = {
    .sin6_family = AF_INET6,
    .sin6_addr = IN6ADDR_ANY_INIT,
    .sin6_port = 0,
  };
  socklen_t addr_len;
  int res;

  fd = api->socket (AF_INET6, SOCK_STREAM, 0);
  if (fd == -1)
    goto socket_failed;

  res = api->setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rx_buffer_size, sizeof (rx_buffer_size));
  if (res == -1)
    goto setsockopt_failed;

  addr_len = sizeof (addr);

  res = api->bind (fd, (const struct sockaddr *) &addr, addr_len);
  if (res == -1)
    goto bind_failed;

  res = api->getsockname (fd, (struct sockaddr *) &addr, &addr_len);
  if (res == -1)
    goto getsockname_failed;

  res = api->listen (fd, 1);
  if (res == -1)
    goto listen_failed;

  return (frida_query_debugger_mapping_enforced (api) << 56) | ((uint64_t) fd << 16) | ntohs (addr.sin6_port);

socket_failed:
  {
    error_code = 1;
    goto failure;
  }
setsockopt_failed:
  {
    error_code = 2;
    goto failure;
  }
bind_failed:
  {
    error_code = 3;
    goto failure;
  }
getsockname_failed:
  {
    error_code = 4;
    goto failure;
  }
listen_failed:
  {
    error_code = 5;
    goto failure;
  }
failure:
  {
    if (fd != -1)
      api->close (fd);

    return ((uint64_t) error_code << 57);
  }
}

static uint64_t
frida_query_debugger_mapping_enforced (const FridaUploadApi * api)
{
  uint64_t is_enforced;
  mach_port_t task;
  int page_size;
  mach_vm_address_t start;
  vm_address_t addr;
  vm_prot_t cur_prot, max_prot;

  task = api->_mach_task_self ();
  page_size = api->getpagesize ();

  api->mach_vm_allocate (task, &start, page_size, VM_FLAGS_ANYWHERE);
  *(uint32_t *) start = 1337;
  api->mprotect ((void *) start, page_size, PROT_READ | PROT_EXEC);

  addr = 0;
  api->vm_remap (task, &addr, page_size, 0, VM_FLAGS_ANYWHERE, task, start, FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE);

  is_enforced = (cur_prot & (VM_PROT_READ | VM_PROT_EXECUTE)) != (VM_PROT_READ | VM_PROT_EXECUTE);

  api->mach_vm_deallocate (task, addr, page_size);
  api->mach_vm_deallocate (task, start, page_size);

  return is_enforced;
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <stdio.h>

int
main (void)
{
  const FridaUploadApi api = FRIDA_UPLOAD_API_INIT;
  uint64_t result;
  uint8_t error_code;
  uint32_t fd;
  uint16_t port;

  result = frida_listen (FRIDA_RX_BUFFER_SIZE, &api);

  error_code = (result >> 56) & 0xff;
  fd         = (result >> 16) & 0xffffffff;
  port       =  result        & 0xffff;

  printf ("error_code=%u fd=%u port=%u\n", error_code, fd, port);

  assert (error_code == 0);
  assert (fd != 0);
  assert (port != 0);

  return error_code;
}

#endif

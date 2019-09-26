#include "upload-api.h"

#include <stdbool.h>

typedef uint8_t FridaUploadCommandType;

typedef void (* FridaConstructorFunc) (int argc, const char * argv[], const char * env[], const char * apple[], int * result);

enum _FridaUploadCommandType
{
  FRIDA_UPLOAD_COMMAND_WRITE = 1,
  FRIDA_UPLOAD_COMMAND_PROTECT,
  FRIDA_UPLOAD_COMMAND_CONSTRUCT
};

#define FRIDA_TEMP_FAILURE_RETRY(expression) \
  ({ \
    ssize_t __result; \
    \
    do __result = expression; \
    while (__result == -1 && *(api->get_errno_storage ()) == EINTR); \
    \
    __result; \
  })

static bool frida_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const FridaUploadApi * api);

int64_t
frida_receive (int listener_fd, uint64_t session_id_top, uint64_t session_id_bottom, const char * apple[], const FridaUploadApi * api)
{
  int result = 0;
  bool expecting_client;
  int res;
  struct sockaddr_in addr;
  socklen_t addr_len;
  int client_fd;

  expecting_client = true;

  do
  {
    uint64_t client_sid[2];

    addr_len = sizeof (addr);

    res = FRIDA_TEMP_FAILURE_RETRY (api->accept (listener_fd, (struct sockaddr *) &addr, &addr_len));
    if (res == -1)
      goto beach;
    client_fd = res;

    #define FRIDA_READ_VALUE(v) \
        if (!frida_read_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    FRIDA_READ_VALUE (client_sid);
    if (client_sid[0] != session_id_top || client_sid[1] != session_id_bottom)
      goto next_client;

    expecting_client = false;

    while (true)
    {
      bool success = false;
      FridaUploadCommandType command_type;

      FRIDA_READ_VALUE (command_type);

      switch (command_type)
      {
        case FRIDA_UPLOAD_COMMAND_WRITE:
        {
          uint64_t address;
          uint32_t size;
          size_t n;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (size);

          success = frida_read_chunk (client_fd, (void *) address, size, &n, api);

          api->sys_icache_invalidate ((void *) address, n);
          api->sys_dcache_flush ((void *) address, n);

          break;
        }
        case FRIDA_UPLOAD_COMMAND_PROTECT:
        {
          uint64_t address;
          uint32_t size;
          int32_t prot;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (size);
          FRIDA_READ_VALUE (prot);

          success = api->mprotect ((void *) address, size, prot) == 0;

          break;
        }
        case FRIDA_UPLOAD_COMMAND_CONSTRUCT:
        {
          uint64_t address;
          uint32_t count;
          FridaConstructorFunc * constructors;
          uint32_t i;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (count);

          constructors = (FridaConstructorFunc *) address;

          for (i = 0; i != count; i++)
          {
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructors[i] (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
      }

      if (!success)
        goto next_client;
    }

next_client:
    api->close (client_fd);
  }
  while (expecting_client);

beach:
  api->close (listener_fd);

  return result;
}

static bool
frida_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const FridaUploadApi * api)
{
  void * cursor = buffer;
  size_t remaining = length;

  if (bytes_read != NULL)
    *bytes_read = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = FRIDA_TEMP_FAILURE_RETRY (api->read (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_read != NULL)
      *bytes_read += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <pthread.h>
#include <stdio.h>

# undef BUILDING_TEST_PROGRAM
# include "upload-listener.c"
# define BUILDING_TEST_PROGRAM

typedef struct _FridaTestState FridaTestState;

struct _FridaTestState
{
  uint16_t port;

  uint64_t session_id_top;
  uint64_t session_id_bottom;

  uint8_t target_a[4];
  uint8_t target_b[2];

  const FridaUploadApi * api;
};

static void * frida_emulate_client (void * user_data);
static bool frida_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const FridaUploadApi * api);

int
main (void)
{
  const FridaUploadApi api = FRIDA_UPLOAD_API_INIT;
  uint64_t result;
  uint8_t error_code;
  uint32_t listener_fd;
  uint16_t port;
  pthread_t client_thread;
  FridaTestState state;
  const char * apple[] = { NULL };

  result = frida_listen (FRIDA_RX_BUFFER_SIZE, &api);

  error_code  = (result >> 56) & 0xff;
  listener_fd = (result >> 16) & 0xffffffff;
  port        =  result        & 0xffff;

  printf ("listen() => error_code=%u fd=%u port=%u\n", error_code, listener_fd, port);

  assert (error_code == 0);

  state.port = port;

  state.session_id_top = 1;
  state.session_id_bottom = 2;

  state.target_a[0] = 0;
  state.target_a[1] = 0;
  state.target_a[2] = 3;
  state.target_a[3] = 4;
  state.target_b[0] = 0;
  state.target_b[1] = 6;

  state.api = &api;

  pthread_create (&client_thread, NULL, frida_emulate_client, &state);

  frida_receive (listener_fd, 1, 2, apple, &api);

  pthread_join (client_thread, NULL);

  assert (state.target_a[0] == 1);
  assert (state.target_a[1] == 2);
  assert (state.target_a[2] == 3);
  assert (state.target_a[3] == 4);
  assert (state.target_b[0] == 5);
  assert (state.target_b[1] == 6);

  return 0;
}

static void *
frida_emulate_client (void * user_data)
{
  FridaTestState * state = user_data;
  const FridaUploadApi * api = state->api;
  struct sockaddr_in addr;
  int fd;
  int res;
  bool success;
  const FridaUploadCommandType write_command_type = FRIDA_UPLOAD_COMMAND_WRITE;
  uint64_t address;
  uint32_t size;
  uint8_t val_a[2], val_b;

  fd = api->socket (AF_INET, SOCK_STREAM, 0);
  assert (fd != -1);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons (state->port);

  res = FRIDA_TEMP_FAILURE_RETRY (connect (fd, (const struct sockaddr *) &addr, sizeof (addr)));
  assert (res != -1);

  #define FRIDA_WRITE_VALUE(v) \
      success = frida_write_chunk (fd, &(v), sizeof (v), NULL, api); \
      assert (success)

  FRIDA_WRITE_VALUE (state->session_id_top);
  FRIDA_WRITE_VALUE (state->session_id_bottom);

  FRIDA_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_a;
  FRIDA_WRITE_VALUE (address);
  size = 2;
  FRIDA_WRITE_VALUE (size);
  val_a[0] = 1;
  val_a[1] = 2;
  FRIDA_WRITE_VALUE (val_a);

  FRIDA_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_b;
  FRIDA_WRITE_VALUE (address);
  size = 1;
  FRIDA_WRITE_VALUE (size);
  val_b = 5;
  FRIDA_WRITE_VALUE (val_b);

  api->close (fd);

  return NULL;
}

static bool
frida_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const FridaUploadApi * api)
{
  const void * cursor = buffer;
  size_t remaining = length;

  if (bytes_written != NULL)
    *bytes_written = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = FRIDA_TEMP_FAILURE_RETRY (write (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_written != NULL)
      *bytes_written += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

#endif

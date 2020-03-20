#include "upload-api.h"

#include <ptrauth.h>
#include <stdbool.h>

#define FRIDA_INT2_MASK  0x00000003U
#define FRIDA_INT11_MASK 0x000007ffU
#define FRIDA_INT16_MASK 0x0000ffffU
#define FRIDA_INT32_MASK 0xffffffffU

typedef uint8_t FridaUploadCommandType;
typedef uint8_t FridaDarwinThreadedItemType;

typedef void (* FridaConstructorFunc) (int argc, const char * argv[], const char * env[], const char * apple[], int * result);

enum _FridaUploadCommandType
{
  FRIDA_UPLOAD_COMMAND_WRITE = 1,
  FRIDA_UPLOAD_COMMAND_APPLY_THREADED,
  FRIDA_UPLOAD_COMMAND_PROTECT,
  FRIDA_UPLOAD_COMMAND_CONSTRUCT
};

enum _FridaDarwinThreadedItemType
{
  FRIDA_DARWIN_THREADED_REBASE,
  FRIDA_DARWIN_THREADED_BIND
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
        case FRIDA_UPLOAD_COMMAND_APPLY_THREADED:
        {
          uint64_t preferred_base_address, slide;
          uint16_t num_symbols, num_regions, i;

          FRIDA_READ_VALUE (preferred_base_address);
          FRIDA_READ_VALUE (slide);

          FRIDA_READ_VALUE (num_symbols);
          uint64_t symbols[num_symbols];
          if (!frida_read_chunk (client_fd, symbols, num_symbols * sizeof (uint64_t), NULL, api))
            goto next_client;

          FRIDA_READ_VALUE (num_regions);
          uint64_t regions[num_regions];
          if (!frida_read_chunk (client_fd, regions, num_regions * sizeof (uint64_t), NULL, api))
            goto next_client;

          for (i = 0; i != num_regions; i++)
          {
            uint64_t * slot = (uint64_t *) regions[i];
            uint16_t delta;

            do
            {
              uint64_t value;
              bool is_authenticated;
              FridaDarwinThreadedItemType type;
              uint8_t key;
              bool has_address_diversity;
              uint16_t diversity;
              uint64_t bound_value;

              value = *slot;

              is_authenticated      = (value >> 63) & 1;
              type                  = (value >> 62) & 1;
              delta                 = (value >> 51) & FRIDA_INT11_MASK;
              key                   = (value >> 49) & FRIDA_INT2_MASK;
              has_address_diversity = (value >> 48) & 1;
              diversity             = (value >> 32) & FRIDA_INT16_MASK;

              if (type == FRIDA_DARWIN_THREADED_BIND)
              {
                uint16_t bind_ordinal;

                bind_ordinal = value & FRIDA_INT16_MASK;

                bound_value = symbols[bind_ordinal];
              }
              else if (type == FRIDA_DARWIN_THREADED_REBASE)
              {
                uint64_t rebase_address;

                if (is_authenticated)
                {
                  rebase_address = value & FRIDA_INT32_MASK;
                }
                else
                {
                  uint64_t top_8_bits, bottom_43_bits, sign_bits;
                  bool sign_bit_set;

                  top_8_bits = (value << 13) & 0xff00000000000000UL;
                  bottom_43_bits = value     & 0x000007ffffffffffUL;

                  sign_bit_set = (value >> 42) & 1;
                  if (sign_bit_set)
                    sign_bits = 0x00fff80000000000UL;
                  else
                    sign_bits = 0;

                  rebase_address = top_8_bits | sign_bits | bottom_43_bits;
                }

                bound_value = rebase_address;

                if (is_authenticated)
                  bound_value += preferred_base_address;

                bound_value += slide;
              }

              if (is_authenticated)
              {
                void * p = (void *) bound_value;
                uintptr_t d = diversity;

                if (has_address_diversity)
                  d = ptrauth_blend_discriminator (slot, d);

                switch (key)
                {
                  case ptrauth_key_asia:
                    p = ptrauth_sign_unauthenticated (p, ptrauth_key_asia, d);
                    break;
                  case ptrauth_key_asib:
                    p = ptrauth_sign_unauthenticated (p, ptrauth_key_asib, d);
                    break;
                  case ptrauth_key_asda:
                    p = ptrauth_sign_unauthenticated (p, ptrauth_key_asda, d);
                    break;
                  case ptrauth_key_asdb:
                    p = ptrauth_sign_unauthenticated (p, ptrauth_key_asdb, d);
                    break;
                }

                *slot = (uint64_t) p;
              }
              else
              {
                *slot = bound_value;
              }

              slot += delta;
            }
            while (delta != 0);
          }

          success = true;

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

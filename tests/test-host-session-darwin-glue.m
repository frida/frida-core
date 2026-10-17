#import <Foundation/Foundation.h>

#include <assert.h>
#include <glib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_MACOS
# include <libproc.h>
#endif

static id frida_parse_plist (const uint8_t * data, int length, char ** error_message);

uint8_t *
frida_host_session_test_fruity_plist_to_binary_using_apple_implementation (const uint8_t * data, int length, char ** error_message,
    int * output_length)
{
  @autoreleasepool
  {
    uint8_t * result;
    id plist;
    NSData * bplist;
    size_t len;

    *error_message = NULL;
    *output_length = 0;

    plist = frida_parse_plist (data, length, error_message);
    if (plist == nil)
      return NULL;

    bplist = [NSPropertyListSerialization dataWithPropertyList:plist
                                                        format:NSPropertyListBinaryFormat_v1_0
                                                       options:0
                                                         error:nil];

    len = [bplist length];
    result = malloc (len);
    memcpy (result, [bplist bytes], len);
    *output_length = (int) len;

    return result;
  }
}

char *
frida_host_session_test_fruity_plist_to_xml_using_apple_implementation (const uint8_t * data, int length, char ** error_message)
{
  @autoreleasepool
  {
    id plist;
    NSData * xml;

    *error_message = NULL;

    plist = frida_parse_plist (data, length, error_message);
    if (plist == nil)
      return NULL;

    xml = [NSPropertyListSerialization dataWithPropertyList:plist
                                                     format:NSPropertyListXMLFormat_v1_0
                                                    options:0
                                                      error:nil];

    return strndup ([xml bytes], [xml length]);
  }
}

static id
frida_parse_plist (const uint8_t * data, int length, char ** error_message)
{
  id plist;
  NSData * input;
  NSPropertyListFormat format;
  NSError * error = nil;

  input = [NSData dataWithBytes:data length:(NSUInteger) length];

  plist = [NSPropertyListSerialization propertyListWithData:input
                                                    options:NSPropertyListImmutable
                                                     format:&format
                                                      error:&error];
  if (error != nil)
    *error_message = strdup ([[error localizedDescription] UTF8String]);

  return plist;
}

#ifdef HAVE_MACOS

guint
frida_host_session_test_darwin_parent_pid_of (guint pid)
{
  struct proc_bsdinfo info;

  if (proc_pidinfo (pid, PROC_PIDTBSDINFO, 0, &info, sizeof (info)) != sizeof (info))
    return 0;

  return info.pbi_ppid;
}

gboolean
frida_host_session_test_darwin_holds_both_ends_of_a_socketpair (guint pid)
{
  gboolean result = FALSE;
  int size, n, i, j;
  struct proc_fdinfo * fds;
  uint64_t * sockets, * peers;
  int num_sockets = 0;

  size = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, NULL, 0);
  g_assert_cmpint (size, >, 0);
  fds = g_malloc (size);
  n = proc_pidinfo (pid, PROC_PIDLISTFDS, 0, fds, size) / PROC_PIDLISTFD_SIZE;

  sockets = g_new (uint64_t, n);
  peers = g_new (uint64_t, n);
  for (i = 0; i != n; i++)
  {
    struct socket_fdinfo si;

    if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET)
      continue;
    if (proc_pidfdinfo (pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof (si)) != sizeof (si))
      continue;
    if (si.psi.soi_kind != SOCKINFO_UN)
      continue;

    sockets[num_sockets] = si.psi.soi_so;
    peers[num_sockets] = si.psi.soi_proto.pri_un.unsi_conn_so;
    num_sockets++;
  }

  for (i = 0; i != num_sockets && !result; i++)
  {
    for (j = 0; j != num_sockets; j++)
    {
      if (peers[i] == sockets[j])
      {
        result = TRUE;
        break;
      }
    }
  }

  g_free (peers);
  g_free (sockets);
  g_free (fds);

  return result;
}

#endif

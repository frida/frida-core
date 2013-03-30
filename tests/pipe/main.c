#include <zed-pipe.h>

int
main (int argc, char * argv[])
{
  ZedPipeTransport * transport = NULL;
  const gchar * address;
  ZedPipe * pipe;
  gchar c;
  GError * error = NULL;
  gssize ret;

  g_thread_init_with_errorcheck_mutexes (NULL);
  g_type_init ();

  if (argc == 1)
  {
    transport = zed_pipe_transport_new_with_pid (0, NULL);
    address = zed_pipe_transport_get_local_address (transport);
    g_print ("listening on '%s'\n", zed_pipe_transport_get_remote_address (transport));
  }
  else
  {
    address = argv[1];
  }

  pipe = zed_pipe_new (address, &error);
  if (error != NULL)
  {
    g_printerr ("zed_pipe_new failed: %s\n", error->message);
  }
  else
  {
    if (transport != NULL)
    {
      while (TRUE)
      {
        ret = g_input_stream_read (g_io_stream_get_input_stream (G_IO_STREAM (pipe)), &c, sizeof (c), NULL, &error);
        if (error != NULL)
        {
          g_printerr ("g_input_stream_read failed: %s\n", error->message);
          break;
        }
        g_print ("read: %c\n", c);
      }
    }
    else
    {
      while (TRUE)
      {
        c = 'A' + g_random_int_range (0, 26);
        ret = g_output_stream_write (g_io_stream_get_output_stream (G_IO_STREAM (pipe)), &c, sizeof (c), NULL, &error);
        if (error != NULL)
        {
          g_printerr ("g_output_stream_write failed: %s\n", error->message);
          break;
        }
        g_print ("wrote: %c\n", c);
        g_usleep (G_USEC_PER_SEC);
      }
    }

    g_object_unref (pipe);
  }

  if (transport != NULL)
    g_object_unref (transport);

  return 0;
}

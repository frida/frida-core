#ifndef __FRIDA_PIPE_IMPL_H__
#define __FRIDA_PIPE_IMPL_H__

#include <gio/gio.h>

#define FRIDA_TYPE_PIPE_INPUT_STREAM (frida_pipe_input_stream_get_type ())
#define FRIDA_TYPE_PIPE_OUTPUT_STREAM (frida_pipe_output_stream_get_type ())

G_DECLARE_FINAL_TYPE (FridaPipeInputStream, frida_pipe_input_stream, FRIDA, PIPE_INPUT_STREAM, GInputStream)
G_DECLARE_FINAL_TYPE (FridaPipeOutputStream, frida_pipe_output_stream, FRIDA, PIPE_OUTPUT_STREAM, GOutputStream)

 void frida_pipe_transport_set_temp_directory (const gchar * path);

void * _frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error);
void _frida_pipe_transport_destroy_backend (void * backend);

void * _frida_pipe_create_backend (const gchar * address, GError ** error);
void _frida_pipe_destroy_backend (void * backend);
gboolean _frida_pipe_close_backend (void * backend, GError ** error);

GInputStream * _frida_pipe_make_input_stream (void * backend);
GOutputStream * _frida_pipe_make_output_stream (void * backend);

#endif

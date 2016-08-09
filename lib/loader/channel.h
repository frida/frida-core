#ifndef __FRIDA_CHANNEL_H__
#define __FRIDA_CHANNEL_H__

#include <stdbool.h>

typedef struct _FridaChannel FridaChannel;

FridaChannel * frida_channel_open (const char * frida_data_dir);
void frida_channel_close (FridaChannel * self);

bool frida_channel_send_string (FridaChannel * self, const char * str);
char * frida_channel_recv_string (FridaChannel * self);

#endif

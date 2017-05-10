#ifndef __FRIDA_AGENT_GLUE_H__
#define __FRIDA_AGENT_GLUE_H__

#include <gumjs/gumscriptbackend.h>

void frida_agent_environment_init (void);
void frida_agent_environment_deinit (void);
GumScriptBackend * frida_agent_environment_obtain_script_backend (gboolean jit_enabled);

void frida_agent_on_pending_garbage (void * data);

#endif

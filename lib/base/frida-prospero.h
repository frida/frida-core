#ifndef __FRIDA_PROSPERO_H__
#define __FRIDA_PROSPERO_H__

#ifdef HAVE_PROSPERO

#include <gum/gum.h>

G_BEGIN_DECLS

#define FRIDA_PROSPERO_AGENT_ARGS_SYMBOL "frida_prospero_agent_args"
#define FRIDA_PROSPERO_HELLO_BYTE 0xff

typedef struct _FridaProsperoAgentArgs FridaProsperoAgentArgs;

struct _FridaProsperoAgentArgs
{
  GumAddress agent_parameters;
  gint fifo_fd;
  gint agent_ctrlfd;
  GumMemoryRange mapped_range;
};

typedef struct _FridaProsperoAppLaunchContext FridaProsperoAppLaunchContext;

struct _FridaProsperoAppLaunchContext
{
  guint32 size;
  guint32 user_id;
  guint32 app_opt;
  guint64 crash_report;
  guint32 check_flag;
};

extern int sceUserServiceInitialize (void * params);
extern int sceUserServiceGetForegroundUser (guint32 * user_id);
extern int sceSystemServiceLaunchApp (const gchar * title_id, gchar ** argv, FridaProsperoAppLaunchContext * ctx);

G_END_DECLS

#endif

#endif

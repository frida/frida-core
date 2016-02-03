#include "frida-inject.h"

#ifdef HAVE_ANDROID
# include "frida-selinux.h"
#endif

#include <gio/gio.h>

#if defined (HAVE_DARWIN)
# include <CoreFoundation/CoreFoundation.h>

typedef gint32 CFLogLevel;

enum _CFLogLevel
{
  kCFLogLevelEmergency = 0,
  kCFLogLevelAlert     = 1,
  kCFLogLevelCritical  = 2,
  kCFLogLevelError     = 3,
  kCFLogLevelWarning   = 4,
  kCFLogLevelNotice    = 5,
  kCFLogLevelInfo      = 6,
  kCFLogLevelDebug     = 7
};

void CFLog (CFLogLevel level, CFStringRef format, ...);

#elif defined (HAVE_ANDROID)
# include <android/log.h>
#else
# include <stdio.h>
#endif

#ifdef HAVE_IOS
# define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

int memorystatus_control (uint32_t command, int32_t pid, uint32_t flags, void * buffer, size_t buffer_size);
#endif

static void frida_inject_on_assert_failure (const gchar * log_domain, const gchar * file, gint line, const gchar * func, const gchar * message, gpointer user_data) G_GNUC_NORETURN;
static void frida_inject_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data);

void
frida_inject_environment_init (void)
{
  gio_init ();

#ifdef HAVE_ANDROID
  frida_selinux_patch_policy ();
#endif
}


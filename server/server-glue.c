#include "server-glue.h"

#include "frida-core.h"
#ifdef HAVE_IOS
# include "server-ios.h"
#endif
#ifdef HAVE_ANDROID
# include "frida-selinux.h"
#endif

#ifdef HAVE_WINDOWS
# include <winsock2.h>
#else
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif
#include <stdlib.h>

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

static void frida_server_on_assert_failure (const gchar * log_domain, const gchar * file, gint line, const gchar * func, const gchar * message, gpointer user_data) G_GNUC_NORETURN;
static void frida_server_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data);

static gboolean frida_verbose_logging_enabled = FALSE;

void
frida_server_environment_init (void)
{
  frida_init_with_runtime (FRIDA_RUNTIME_GLIB);

  g_assertion_set_handler (frida_server_on_assert_failure, NULL);
  g_log_set_default_handler (frida_server_on_log_message, NULL);
}

void
frida_server_environment_set_verbose_logging_enabled (gboolean enabled)
{
  frida_verbose_logging_enabled = enabled;
}

void
frida_server_environment_configure (void)
{
#ifdef HAVE_IOS
  _frida_server_ios_configure ();
#endif

#ifdef HAVE_ANDROID
  frida_selinux_patch_policy ();
#endif
}

void
frida_server_tcp_enable_nodelay (GSocket * socket)
{
  g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);
}

static void
frida_server_on_assert_failure (const gchar * log_domain, const gchar * file, gint line, const gchar * func, const gchar * message, gpointer user_data)
{
  gchar * full_message;

  while (g_str_has_prefix (file, ".." G_DIR_SEPARATOR_S))
    file += 3;
  if (message == NULL)
    message = "code should not be reached";

  full_message = g_strdup_printf ("%s:%d:%s%s %s", file, line, func, (func[0] != '\0') ? ":" : "", message);
  frida_server_on_log_message (log_domain, G_LOG_LEVEL_ERROR, full_message, user_data);
  g_free (full_message);

  abort ();
}

static void
frida_server_on_log_message (const gchar * log_domain, GLogLevelFlags log_level, const gchar * message, gpointer user_data)
{
  if (!frida_verbose_logging_enabled && (log_level & G_LOG_LEVEL_MASK) >= G_LOG_LEVEL_DEBUG)
    return;

#if defined (HAVE_DARWIN)
  CFLogLevel cf_log_level;
  CFStringRef message_str;

  (void) user_data;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
      cf_log_level = kCFLogLevelError;
      break;
    case G_LOG_LEVEL_CRITICAL:
      cf_log_level = kCFLogLevelCritical;
      break;
    case G_LOG_LEVEL_WARNING:
      cf_log_level = kCFLogLevelWarning;
      break;
    case G_LOG_LEVEL_MESSAGE:
      cf_log_level = kCFLogLevelNotice;
      break;
    case G_LOG_LEVEL_INFO:
      cf_log_level = kCFLogLevelInfo;
      break;
    case G_LOG_LEVEL_DEBUG:
      cf_log_level = kCFLogLevelDebug;
      break;
    default:
      g_assert_not_reached ();
  }

  message_str = CFStringCreateWithCString (NULL, message, kCFStringEncodingUTF8);
  if (log_domain != NULL)
  {
    CFStringRef log_domain_str;

    log_domain_str = CFStringCreateWithCString (NULL, log_domain, kCFStringEncodingUTF8);
    CFLog (cf_log_level, CFSTR ("%@: %@"), log_domain_str, message_str);
    CFRelease (log_domain_str);
  }
  else
  {
    CFLog (cf_log_level, CFSTR ("%@"), message_str);
  }
  CFRelease (message_str);
#elif defined (HAVE_ANDROID)
  int priority;

  (void) user_data;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
    case G_LOG_LEVEL_CRITICAL:
    case G_LOG_LEVEL_WARNING:
      priority = ANDROID_LOG_FATAL;
      break;
    case G_LOG_LEVEL_MESSAGE:
    case G_LOG_LEVEL_INFO:
      priority = ANDROID_LOG_INFO;
      break;
    case G_LOG_LEVEL_DEBUG:
      priority = ANDROID_LOG_DEBUG;
      break;
    default:
      g_assert_not_reached ();
  }

  __android_log_write (priority, log_domain, message);
#else
  FILE * file = NULL;
  const gchar * severity = NULL;

  (void) user_data;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
      file = stderr;
      severity = "ERROR";
      break;
    case G_LOG_LEVEL_CRITICAL:
      file = stderr;
      severity = "CRITICAL";
      break;
    case G_LOG_LEVEL_WARNING:
      file = stderr;
      severity = "WARNING";
      break;
    case G_LOG_LEVEL_MESSAGE:
      file = stderr;
      severity = "MESSAGE";
      break;
    case G_LOG_LEVEL_INFO:
      file = stdout;
      severity = "INFO";
      break;
    case G_LOG_LEVEL_DEBUG:
      file = stdout;
      severity = "DEBUG";
      break;
    default:
      g_assert_not_reached ();
  }

  fprintf (file, "[%s %s] %s\n", log_domain, severity, message);
  fflush (file);
#endif
}


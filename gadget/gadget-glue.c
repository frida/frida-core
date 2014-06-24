#include "frida-gadget.h"

#include "frida-interfaces.h"

#ifdef HAVE_ANDROID

#include <jni.h>
#include <unistd.h>
#include <android/log.h>

JNIEXPORT jint
JNI_OnLoad (JavaVM * vm, void * reserved)
{
  frida_gadget_load ();

  return JNI_VERSION_1_6;
}

JNIEXPORT void
JNI_OnUnload (JavaVM * vm, void * reserved)
{
  frida_gadget_unload ();
}

void
frida_gadget_log_error (const gchar * message)
{
  __android_log_write (ANDROID_LOG_ERROR, "re.frida.Gadget", message);
}

#else

#ifdef G_OS_WIN32
# include <process.h>
#else
# include <unistd.h>
#endif

void
frida_gadget_log_error (const gchar * message)
{
  g_printerr ("[Frida Gadget] %s\n", message);
}

#endif

void
frida_gadget_get_process_info (FridaHostProcessInfo * result)
{
  guint pid;
  gchar * name;
  FridaImageData no_icon;

  pid = getpid ();
#ifdef HAVE_LINUX
  {
    gchar * cmdline;
    g_file_get_contents ("/proc/self/cmdline", &cmdline, NULL, NULL);
    name = g_path_get_basename (cmdline);
    g_free (cmdline);
  }
#else
  /* TODO: implement for other platforms */
  name = g_strdup ("Gadget Host");
#endif
  frida_image_data_init (&no_icon, 0, 0, 0, "");

  frida_host_process_info_init (result, pid, name, &no_icon, &no_icon);

  frida_image_data_destroy (&no_icon);
  g_free (name);
}

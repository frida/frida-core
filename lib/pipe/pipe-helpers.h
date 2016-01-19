#ifndef __FRIDA_WINDOWS_PIPE_HELPERS_H__
#define __FRIDA_WINDOWS_PIPE_HELPERS_H__

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

LPCWSTR frida_pipe_get_sddl_string_for_pipe (void);

#endif

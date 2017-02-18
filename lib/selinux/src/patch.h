#ifndef __FRIDA_PATCH_H__
#define __FRIDA_PATCH_H__

#include <glib.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL void frida_selinux_apply_policy_patch (void);
G_GNUC_INTERNAL void legacy_frida_selinux_apply_policy_patch (void);

G_END_DECLS

#endif

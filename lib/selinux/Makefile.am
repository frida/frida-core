if OS_ANDROID
noinst_LTLIBRARIES = \
	libfrida-selinux.la \
	libselinux.la \
	libsepol.la

libfrida_selinux_la_SOURCES = \
	src/policy.c \
	$(NULL)
libfrida_selinux_la_LIBADD = \
	libselinux.la \
	libsepol.la
libfrida_selinux_la_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/include

libselinux_la_SOURCES = \
	include/selinux/android.h \
	include/selinux/avc.h \
	include/selinux/context.h \
	include/selinux/label.h \
	include/selinux/selinux.h \
	##src/selinux/android.c \
	src/selinux/avc.c \
	src/selinux/avc_internal.c \
	src/selinux/avc_internal.h \
	src/selinux/avc_sidtab.c \
	src/selinux/avc_sidtab.h \
	src/selinux/booleans.c \
	src/selinux/callbacks.c \
	src/selinux/callbacks.h \
	src/selinux/canonicalize_context.c \
	src/selinux/checkAccess.c \
	src/selinux/check_context.c \
	src/selinux/compute_av.c \
	src/selinux/compute_create.c \
	src/selinux/context.c \
	src/selinux/context_internal.h \
	src/selinux/deny_unknown.c \
	src/selinux/disable.c \
	src/selinux/dso.h \
	src/selinux/enabled.c \
	src/selinux/fgetfilecon.c \
	src/selinux/freecon.c \
	src/selinux/fsetfilecon.c \
	src/selinux/get_initial_context.c \
	src/selinux/getenforce.c \
	src/selinux/getfilecon.c \
	src/selinux/getpeercon.c \
	src/selinux/init.c \
	src/selinux/label.c \
	src/selinux/label_android_property.c \
	##src/selinux/label_file.c \
	src/selinux/label_internal.h \
	src/selinux/lgetfilecon.c \
	src/selinux/load_policy.c \
	src/selinux/lsetfilecon.c \
	src/selinux/mapping.c \
	src/selinux/mapping.h \
	src/selinux/policy.h \
	src/selinux/policyvers.c \
	src/selinux/procattr.c \
	src/selinux/selinux_internal.h \
	src/selinux/selinux_netlink.h \
	src/selinux/sestatus.c \
	src/selinux/setenforce.c \
	src/selinux/setfilecon.c \
	src/selinux/stringrep.c \
	src/selinux/xattr.c \
	src/selinux/xattr.h \
	$(NULL)
libselinux_la_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/include

libsepol_la_SOURCES = \
	include/sepol/boolean_record.h \
	include/sepol/booleans.h \
	include/sepol/context.h \
	include/sepol/context_record.h \
	include/sepol/debug.h \
	include/sepol/errcodes.h \
	include/sepol/handle.h \
	include/sepol/iface_record.h \
	include/sepol/interfaces.h \
	include/sepol/module.h \
	include/sepol/module_to_cil.h \
	include/sepol/node_record.h \
	include/sepol/nodes.h \
	include/sepol/policydb.h \
	include/sepol/policydb/avrule_block.h \
	include/sepol/policydb/avtab.h \
	include/sepol/policydb/conditional.h \
	include/sepol/policydb/constraint.h \
	include/sepol/policydb/context.h \
	include/sepol/policydb/ebitmap.h \
	include/sepol/policydb/expand.h \
	include/sepol/policydb/flask.h \
	include/sepol/policydb/flask_types.h \
	include/sepol/policydb/hashtab.h \
	include/sepol/policydb/hierarchy.h \
	include/sepol/policydb/link.h \
	include/sepol/policydb/mls_types.h \
	include/sepol/policydb/module.h \
	include/sepol/policydb/polcaps.h \
	include/sepol/policydb/policydb.h \
	include/sepol/policydb/services.h \
	include/sepol/policydb/sidtab.h \
	include/sepol/policydb/symtab.h \
	include/sepol/policydb/util.h \
	include/sepol/port_record.h \
	include/sepol/ports.h \
	include/sepol/roles.h \
	include/sepol/sepol.h \
	include/sepol/user_record.h \
	include/sepol/users.h \
	src/sepol/assertion.c \
	src/sepol/avrule_block.c \
	src/sepol/avtab.c \
	src/sepol/boolean_record.c \
	src/sepol/booleans.c \
	src/sepol/conditional.c \
	src/sepol/constraint.c \
	src/sepol/context.c \
	src/sepol/context_record.c \
	src/sepol/debug.c \
	src/sepol/ebitmap.c \
	src/sepol/expand.c \
	src/sepol/genbools.c \
	src/sepol/genusers.c \
	src/sepol/handle.c \
	src/sepol/hashtab.c \
	src/sepol/hierarchy.c \
	src/sepol/iface_record.c \
	src/sepol/interfaces.c \
	src/sepol/link.c \
	src/sepol/mls.c \
	src/sepol/module.c \
	src/sepol/module_to_cil.c \
	src/sepol/node_record.c \
	src/sepol/nodes.c \
	src/sepol/polcaps.c \
	src/sepol/policydb.c \
	src/sepol/policydb_convert.c \
	src/sepol/policydb_public.c \
	src/sepol/port_record.c \
	src/sepol/ports.c \
	src/sepol/roles.c \
	src/sepol/services.c \
	src/sepol/sidtab.c \
	src/sepol/symtab.c \
	src/sepol/user_record.c \
	src/sepol/users.c \
	src/sepol/util.c \
	src/sepol/write.c \
	$(NULL)
libsepol_la_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/src/sepol \
	-I $(srcdir)/include
endif

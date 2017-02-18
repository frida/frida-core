if OS_ANDROID
noinst_LTLIBRARIES = \
	libfrida-selinux.la \
	libfrida-selinux-modern.la \
	libfrida-selinux-legacy.la \
	libselinux.la \
	libsepol-modern.la \
	libsepol-legacy.la

libfrida_selinux_la_SOURCES = \
	src/dispatch.c \
	$(NULL)
libfrida_selinux_la_LIBADD = \
	libselinux.la \
	libfrida-selinux-modern.la \
	libfrida-selinux-legacy.la
libfrida_selinux_la_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/include
libfrida_selinux_la_DEPENDENCIES = \
	libselinux.la \
	libfrida-selinux-modern.la \
	libfrida-selinux-legacy.stamp

libfrida_selinux_modern_la_SOURCES = \
	src/patch.c \
	src/patch.h \
	$(NULL)
libfrida_selinux_modern_la_LIBADD = \
	libsepol-modern.la
libfrida_selinux_modern_la_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-DFRIDA_SELINUX_MODERN \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/include \
	-I $(srcdir)/src/sepol-modern/include

libfrida_selinux_legacy_la_SOURCES = \
	src/patch.c \
	src/patch.h \
	$(NULL)
libfrida_selinux_legacy_la_LIBADD = \
	libsepol-legacy.la
libfrida_selinux_legacy_la_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-DFRIDA_SELINUX_LEGACY \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/include \
	-I $(srcdir)/src/sepol-legacy/include

libfrida-selinux-legacy.stamp: libfrida-selinux-legacy.la
	$(AM_V_GEN)$(NM) .libs/libfrida-selinux-legacy.a \
		| awk '{ if ($$0 ~ / D|T /) print $$3 " legacy_" $$3; }' \
		> libfrida-selinux-legacy.mappings
	$(AM_V_GEN)$(OBJCOPY) --redefine-syms libfrida-selinux-legacy.mappings .libs/libfrida-selinux-legacy.a
	@touch $@

libselinux_la_SOURCES = \
	include/selinux/android.h \
	include/selinux/avc.h \
	include/selinux/context.h \
	include/selinux/label.h \
	include/selinux/selinux.h \
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

libsepol_modern_la_SOURCES = \
	src/sepol-modern/include/sepol/boolean_record.h \
	src/sepol-modern/include/sepol/booleans.h \
	src/sepol-modern/include/sepol/context.h \
	src/sepol-modern/include/sepol/context_record.h \
	src/sepol-modern/include/sepol/debug.h \
	src/sepol-modern/include/sepol/errcodes.h \
	src/sepol-modern/include/sepol/handle.h \
	src/sepol-modern/include/sepol/iface_record.h \
	src/sepol-modern/include/sepol/interfaces.h \
	src/sepol-modern/include/sepol/module.h \
	src/sepol-modern/include/sepol/module_to_cil.h \
	src/sepol-modern/include/sepol/node_record.h \
	src/sepol-modern/include/sepol/nodes.h \
	src/sepol-modern/include/sepol/policydb.h \
	src/sepol-modern/include/sepol/policydb/avrule_block.h \
	src/sepol-modern/include/sepol/policydb/avtab.h \
	src/sepol-modern/include/sepol/policydb/conditional.h \
	src/sepol-modern/include/sepol/policydb/constraint.h \
	src/sepol-modern/include/sepol/policydb/context.h \
	src/sepol-modern/include/sepol/policydb/ebitmap.h \
	src/sepol-modern/include/sepol/policydb/expand.h \
	src/sepol-modern/include/sepol/policydb/flask.h \
	src/sepol-modern/include/sepol/policydb/flask_types.h \
	src/sepol-modern/include/sepol/policydb/hashtab.h \
	src/sepol-modern/include/sepol/policydb/hierarchy.h \
	src/sepol-modern/include/sepol/policydb/link.h \
	src/sepol-modern/include/sepol/policydb/mls_types.h \
	src/sepol-modern/include/sepol/policydb/module.h \
	src/sepol-modern/include/sepol/policydb/polcaps.h \
	src/sepol-modern/include/sepol/policydb/policydb.h \
	src/sepol-modern/include/sepol/policydb/services.h \
	src/sepol-modern/include/sepol/policydb/sidtab.h \
	src/sepol-modern/include/sepol/policydb/symtab.h \
	src/sepol-modern/include/sepol/policydb/util.h \
	src/sepol-modern/include/sepol/port_record.h \
	src/sepol-modern/include/sepol/ports.h \
	src/sepol-modern/include/sepol/roles.h \
	src/sepol-modern/include/sepol/sepol.h \
	src/sepol-modern/include/sepol/user_record.h \
	src/sepol-modern/include/sepol/users.h \
	src/sepol-modern/assertion.c \
	src/sepol-modern/avrule_block.c \
	src/sepol-modern/avtab.c \
	src/sepol-modern/boolean_record.c \
	src/sepol-modern/booleans.c \
	src/sepol-modern/conditional.c \
	src/sepol-modern/constraint.c \
	src/sepol-modern/context.c \
	src/sepol-modern/context_record.c \
	src/sepol-modern/debug.c \
	src/sepol-modern/ebitmap.c \
	src/sepol-modern/expand.c \
	src/sepol-modern/handle.c \
	src/sepol-modern/hashtab.c \
	src/sepol-modern/hierarchy.c \
	src/sepol-modern/iface_record.c \
	src/sepol-modern/interfaces.c \
	src/sepol-modern/link.c \
	src/sepol-modern/mls.c \
	src/sepol-modern/module.c \
	src/sepol-modern/module_to_cil.c \
	src/sepol-modern/node_record.c \
	src/sepol-modern/nodes.c \
	src/sepol-modern/polcaps.c \
	src/sepol-modern/policydb.c \
	src/sepol-modern/policydb_convert.c \
	src/sepol-modern/policydb_public.c \
	src/sepol-modern/port_record.c \
	src/sepol-modern/ports.c \
	src/sepol-modern/roles.c \
	src/sepol-modern/services.c \
	src/sepol-modern/sidtab.c \
	src/sepol-modern/symtab.c \
	src/sepol-modern/user_record.c \
	src/sepol-modern/users.c \
	src/sepol-modern/util.c \
	src/sepol-modern/write.c \
	$(NULL)
libsepol_modern_la_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/src/sepol-modern \
	-I $(srcdir)/src/sepol-modern/include

libsepol_legacy_la_SOURCES = \
	src/sepol-legacy/include/sepol/boolean_record.h \
	src/sepol-legacy/include/sepol/booleans.h \
	src/sepol-legacy/include/sepol/context.h \
	src/sepol-legacy/include/sepol/context_record.h \
	src/sepol-legacy/include/sepol/debug.h \
	src/sepol-legacy/include/sepol/errcodes.h \
	src/sepol-legacy/include/sepol/handle.h \
	src/sepol-legacy/include/sepol/iface_record.h \
	src/sepol-legacy/include/sepol/interfaces.h \
	src/sepol-legacy/include/sepol/module.h \
	src/sepol-legacy/include/sepol/module_to_cil.h \
	src/sepol-legacy/include/sepol/node_record.h \
	src/sepol-legacy/include/sepol/nodes.h \
	src/sepol-legacy/include/sepol/policydb.h \
	src/sepol-legacy/include/sepol/policydb/avrule_block.h \
	src/sepol-legacy/include/sepol/policydb/avtab.h \
	src/sepol-legacy/include/sepol/policydb/conditional.h \
	src/sepol-legacy/include/sepol/policydb/constraint.h \
	src/sepol-legacy/include/sepol/policydb/context.h \
	src/sepol-legacy/include/sepol/policydb/ebitmap.h \
	src/sepol-legacy/include/sepol/policydb/expand.h \
	src/sepol-legacy/include/sepol/policydb/flask.h \
	src/sepol-legacy/include/sepol/policydb/flask_types.h \
	src/sepol-legacy/include/sepol/policydb/hashtab.h \
	src/sepol-legacy/include/sepol/policydb/hierarchy.h \
	src/sepol-legacy/include/sepol/policydb/link.h \
	src/sepol-legacy/include/sepol/policydb/mls_types.h \
	src/sepol-legacy/include/sepol/policydb/module.h \
	src/sepol-legacy/include/sepol/policydb/polcaps.h \
	src/sepol-legacy/include/sepol/policydb/policydb.h \
	src/sepol-legacy/include/sepol/policydb/services.h \
	src/sepol-legacy/include/sepol/policydb/sidtab.h \
	src/sepol-legacy/include/sepol/policydb/symtab.h \
	src/sepol-legacy/include/sepol/policydb/util.h \
	src/sepol-legacy/include/sepol/port_record.h \
	src/sepol-legacy/include/sepol/ports.h \
	src/sepol-legacy/include/sepol/roles.h \
	src/sepol-legacy/include/sepol/sepol.h \
	src/sepol-legacy/include/sepol/user_record.h \
	src/sepol-legacy/include/sepol/users.h \
	src/sepol-legacy/assertion.c \
	src/sepol-legacy/avrule_block.c \
	src/sepol-legacy/avtab.c \
	src/sepol-legacy/boolean_record.c \
	src/sepol-legacy/booleans.c \
	src/sepol-legacy/conditional.c \
	src/sepol-legacy/constraint.c \
	src/sepol-legacy/context.c \
	src/sepol-legacy/context_record.c \
	src/sepol-legacy/debug.c \
	src/sepol-legacy/ebitmap.c \
	src/sepol-legacy/expand.c \
	src/sepol-legacy/handle.c \
	src/sepol-legacy/hashtab.c \
	src/sepol-legacy/hierarchy.c \
	src/sepol-legacy/iface_record.c \
	src/sepol-legacy/interfaces.c \
	src/sepol-legacy/link.c \
	src/sepol-legacy/mls.c \
	src/sepol-legacy/module.c \
	src/sepol-legacy/module_to_cil.c \
	src/sepol-legacy/node_record.c \
	src/sepol-legacy/nodes.c \
	src/sepol-legacy/polcaps.c \
	src/sepol-legacy/policydb.c \
	src/sepol-legacy/policydb_convert.c \
	src/sepol-legacy/policydb_public.c \
	src/sepol-legacy/port_record.c \
	src/sepol-legacy/ports.c \
	src/sepol-legacy/roles.c \
	src/sepol-legacy/services.c \
	src/sepol-legacy/sidtab.c \
	src/sepol-legacy/symtab.c \
	src/sepol-legacy/user_record.c \
	src/sepol-legacy/users.c \
	src/sepol-legacy/util.c \
	src/sepol-legacy/write.c \
	$(NULL)
libsepol_legacy_la_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/src/sepol-legacy \
	-I $(srcdir)/src/sepol-legacy/include
endif

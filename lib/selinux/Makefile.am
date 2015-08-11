if OS_LINUX
noinst_LTLIBRARIES = \
	libfrida-selinux.la

libfrida_selinux_la_SOURCES = \
	include/selinux/android.h \
	include/selinux/avc.h \
	include/selinux/context.h \
	include/selinux/label.h \
	include/selinux/selinux.h \
	##src/android.c \
	src/avc.c \
	src/avc_internal.c \
	src/avc_internal.h \
	src/avc_sidtab.c \
	src/avc_sidtab.h \
	src/booleans.c \
	src/callbacks.c \
	src/callbacks.h \
	src/canonicalize_context.c \
	src/checkAccess.c \
	src/check_context.c \
	src/compute_av.c \
	src/compute_create.c \
	src/context.c \
	src/context_internal.h \
	src/deny_unknown.c \
	src/disable.c \
	src/dso.h \
	src/enabled.c \
	src/fgetfilecon.c \
	src/freecon.c \
	src/fsetfilecon.c \
	src/get_initial_context.c \
	src/getenforce.c \
	src/getfilecon.c \
	src/getpeercon.c \
	src/init.c \
	src/label.c \
	src/label_android_property.c \
	##src/label_file.c \
	src/label_internal.h \
	src/lgetfilecon.c \
	src/load_policy.c \
	src/lsetfilecon.c \
	src/mapping.c \
	src/mapping.h \
	src/policy.h \
	src/policyvers.c \
	src/procattr.c \
	src/selinux_internal.h \
	src/selinux_netlink.h \
	src/sestatus.c \
	src/setenforce.c \
	src/setfilecon.c \
	src/stringrep.c \
	src/xattr.c \
	src/xattr.h

AM_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(srcdir)/include
endif

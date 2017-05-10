noinst_LTLIBRARIES = \
	libfrida-pipe.la

libfrida_pipe_la_SOURCES = pipe.vala
if OS_DARWIN
libfrida_pipe_la_SOURCES += pipe-mach.c
else
libfrida_pipe_la_SOURCES += pipe-posix.c
endif
if OS_ANDROID
libfrida_pipe_la_LIBADD = \
	$(top_builddir)/lib/selinux/libfrida-selinux.la
endif
libfrida_pipe_la_VALAFLAGS = \
	--library=frida-pipe \
	--header=frida-pipe.h \
	--pkg glib-2.0 \
	--pkg gio-2.0

AM_CPPFLAGS = \
	-DG_LOG_DOMAIN=\"Frida\" \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(top_builddir)/lib/interfaces \
	-I $(top_srcdir)/lib/selinux/include

noinst_LTLIBRARIES = \
	libfrida-pipe-autogen.la \
	libfrida-pipe.la

if OS_DARWIN
libfrida_pipe_la_SOURCES = pipe-mach.c
else
libfrida_pipe_la_SOURCES = pipe-posix.c
endif
if OS_LINUX
# FIXME: We disable warnings because of vintage GCC versions not supporting
# temporary suppressions.
libfrida_pipe_la_CFLAGS = \
	-w
endif
libfrida_pipe_la_LIBADD = \
	$(FRIDA_LIBS)
libfrida_pipe_la_DEPENDENCIES = \
	$(builddir)/libfrida-pipe-autogen.la

libfrida_pipe_autogen_la_SOURCES = \
	pipe.vala
libfrida_pipe_autogen_la_CFLAGS = \
	-w
libfrida_pipe_autogen_la_VALAFLAGS = \
	--library=frida-pipe \
	--header=frida-pipe.h \
	@FRIDA_PACKAGES@

AM_CPPFLAGS = \
	-include config.h \
	$(FRIDA_CFLAGS) \
	-I $(top_builddir)/lib/interfaces

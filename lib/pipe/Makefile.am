noinst_LTLIBRARIES = \
	libfrida-pipe.la \
	libfrida-pipe-glue.la

libfrida_pipe_la_SOURCES = \
	pipe.vala
libfrida_pipe_la_CFLAGS = \
	-w
libfrida_pipe_la_LIBADD = \
	$(builddir)/libfrida-pipe-glue.la \
	$(FRIDA_LIBS)
libfrida_pipe_la_VALAFLAGS = \
	--library=frida-pipe \
	--header=frida-pipe.h \
	@FRIDA_PACKAGES@

if OS_DARWIN
libfrida_pipe_glue_la_SOURCES = pipe-mach.c
else
libfrida_pipe_glue_la_SOURCES = pipe-posix.c
endif

AM_CPPFLAGS = \
	$(FRIDA_CFLAGS) \
	-I $(top_builddir)/lib/interfaces

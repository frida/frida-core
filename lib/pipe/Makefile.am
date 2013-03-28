noinst_LTLIBRARIES = libzed-pipe.la libzed-pipe-glue.la

libzed_pipe_la_SOURCES = \
	pipe.vala
libzed_pipe_la_CFLAGS = \
	-w
libzed_pipe_la_LIBADD = \
	$(builddir)/libzed-pipe-glue.la \
	$(ZED_LIBS)
libzed_pipe_la_VALAFLAGS = \
	--library=zed-pipe \
	--header=zed-pipe.h \
	@ZED_PACKAGES@

if OS_DARWIN
libzed_pipe_glue_la_SOURCES = pipe-mach.c
else
libzed_pipe_glue_la_SOURCES = pipe-unix.c
endif

AM_CPPFLAGS = \
	$(ZED_CFLAGS) \
	-I $(top_builddir)/lib/interfaces

noinst_PROGRAMS = pipe-test

pipe_test_SOURCES = main.c
pipe_test_LDADD = $(top_builddir)/lib/pipe/libfrida-pipe.la

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_builddir)/lib/pipe \
	$(FRIDA_CFLAGS)

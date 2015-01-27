noinst_PROGRAMS = mapper-test

mapper_test_SOURCES = main.c
mapper_test_LDADD = $(FRIDA_LIBS)
mapper_test_LDFLAGS = $(FRIDA_LDFLAGS)

AM_CPPFLAGS = \
	-include config.h \
	-I $(top_srcdir)/src/darwin \
	$(FRIDA_CFLAGS)

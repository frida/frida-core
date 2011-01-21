CLEANFILES = \
	zed-data-ui.c \
	zed-data-ui.h \
	zed-data-ui.vapi \
	zed-data-images.c \
	zed-data-images.h \
	zed-data-images.vapi \
	zed-data-mx.c \
	zed-data-mx.h \
	zed-data-mx.vapi

noinst_LTLIBRARIES = libzed-data.la

libzed_data_la_SOURCES = \
	$(builddir)/zed-data-ui.c \
	$(builddir)/zed-data-images.c \
	$(builddir)/zed-data-mx.c \
	$(NULL)

AM_CPPFLAGS = \
	$(ZED_CFLAGS)

zed-data-%.c:
	$(AM_V_GEN) \
		"$(top_builddir)/tools/resource-compiler" \
			-c "$(srcdir)/$*/$*.resources" \
			-o "$(builddir)/zed-data-$*"

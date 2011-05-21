CLEANFILES = \
	$(NULL)

noinst_LTLIBRARIES = libzed-data.la

libzed_data_la_SOURCES = \
	$(NULL)

AM_CPPFLAGS = \
	$(ZED_CFLAGS)

zed-data-%.c:
	$(AM_V_GEN) \
		"$(top_builddir)/tools/resource-compiler" \
			-c "$(srcdir)/$*/$*.resources" \
			-o "$(builddir)/zed-data-$*"

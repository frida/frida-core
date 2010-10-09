ui_data_files = \
	$(srcdir)/ui/agent-session.ui \
	$(srcdir)/ui/chat.ui \
	$(srcdir)/ui/host-session.ui \
	$(srcdir)/ui/login.ui \
	$(srcdir)/ui/workspace.ui
image_data_files = \
	$(srcdir)/images/browse-processes.png

BUILT_SOURCES = \
	zed-data-stamp
DISTCLEANFILES = \
	zed-data-stamp \
	zed-data-ui.c \
	zed-data-ui.h \
	zed-data-ui.vapi \
	zed-data-images.c \
	zed-data-images.h \
	zed-data-images.vapi

zed-data-stamp: $(ui_data_files) $(image_data_files)
	$(AM_V_GEN) \
		"$(top_builddir)/tools/resource-compiler" \
			--namespace="Zed.Data.Ui" \
			-o "$(builddir)/zed-data-ui" \
			$(ui_data_files) && \
		"$(top_builddir)/tools/resource-compiler" \
			--namespace="Zed.Data.Images" \
			-o "$(builddir)/zed-data-images" \
			$(image_data_files)
	@touch zed-data-stamp

noinst_LTLIBRARIES = libzed-data.la

libzed_data_la_SOURCES = \
	$(builddir)/zed-data-ui.c \
	$(builddir)/zed-data-images.c \
	$(NULL)

AM_CPPFLAGS = \
	$(ZED_CFLAGS)

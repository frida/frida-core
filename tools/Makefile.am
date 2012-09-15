noinst_PROGRAMS = resource-compiler

resource_compiler_SOURCES = \
	resource-compiler.vala
resource_compiler_CFLAGS = \
	-w
resource_compiler_LDADD = \
	$(ZED_LIBS)
resource_compiler_VALAFLAGS = \
	@ZED_PACKAGES@ \
	@ZED_VALAFLAGS@

AM_CPPFLAGS = \
	$(ZED_CFLAGS)

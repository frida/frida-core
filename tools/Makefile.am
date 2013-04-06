noinst_PROGRAMS = resource-compiler

resource_compiler_SOURCES = \
	resource-compiler.vala
resource_compiler_CFLAGS = \
	-w
resource_compiler_LDADD = \
	$(FRIDA_LIBS)
resource_compiler_VALAFLAGS = \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

AM_CPPFLAGS = \
	$(FRIDA_CFLAGS)

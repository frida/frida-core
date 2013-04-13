bin_PROGRAMS = frida-resource-compiler

frida_resource_compiler_SOURCES = \
	resource-compiler.vala
frida_resource_compiler_CFLAGS = \
	-w
frida_resource_compiler_LDADD = \
	$(FRIDA_LIBS)
frida_resource_compiler_VALAFLAGS = \
	@FRIDA_PACKAGES@ \
	@FRIDA_VALAFLAGS@

AM_CPPFLAGS = \
	$(FRIDA_CFLAGS)

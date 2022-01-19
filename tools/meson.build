extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'resource-compiler.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'resource-compiler.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif

resource_compiler = executable('frida-resource-compiler', 'resource-compiler.vala',
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: [native_glib_dep, native_gio_dep, native_gee_dep],
  native: true,
)

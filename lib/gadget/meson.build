gadget_sources = [
  'gadget.vala',
  'gadget-glue.c',
  'script-engine.vala',
]

if not enable_diet
  gadget_sources += ['dummy.cpp']
endif

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-gadget.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-gadget.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif

gadget = shared_library('frida-gadget', gadget_sources,
  name_prefix: '',
  c_args: frida_component_cflags,
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  vs_module_defs: 'frida-gadget.def',
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep, interfaces_dep, pipe_dep, tls_provider_dep],
  install: host_os_family != 'darwin',
)

if host_os_family == 'darwin'
  custom_target('frida-gadget-signed',
    input: gadget,
    output: 'FridaGadget.dylib',
    command: [
      files('sign.sh'),
      host_os,
      '@INPUT@',
      '@OUTPUT@',
      meson.get_cross_binary('strip', 'strip'),
      get_option('strip').to_string(),
    ],
    build_by_default: true,
    install: true,
    install_dir: get_option('libdir'),
  )
endif

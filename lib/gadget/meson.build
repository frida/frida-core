gadget_sources = [
  'gadget.vala',
  'gadget-glue.c',
]

force_cpp_linking = gumjs_dep.get_pkgconfig_variable('gumjs_v8') == 'enabled'
if force_cpp_linking
  gadget_sources += ['dummy.cpp']
endif

platform_deps = []

extra_link_args = []
extra_link_depends = []

if host_os_family != 'windows'
  platform_deps += [gio_unix_dep]
endif

if host_os_family == 'darwin'
  symlist = 'frida-gadget.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-gadget.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif

if host_os_family in ['linux', 'qnx']
  # For our libc shim to be effective.
  extra_link_args += ['-Wl,-Bsymbolic']
endif

raw_gadget = shared_library('frida-gadget', gadget_sources,
  name_prefix: '_',
  c_args: frida_component_cflags,
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  vs_module_defs: 'frida-gadget.def',
  override_options: ['b_asneeded=true'],
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep, interfaces_dep, tls_provider_dep, payload_dep] + platform_deps,
)

operations = [
  '--move', 'constructor', 'frida_init_memory', 'first',
  '--move', 'constructor', 'frida_on_load', 'last',
]
if host_os_family != 'darwin'
  operations += [
    '--move', 'destructor', 'frida_deinit_memory', 'first',
    '--move', 'destructor', 'frida_on_unload', 'last',
  ]
endif
if get_option('strip')
  operations += ['--strip', meson.get_cross_binary('strip', 'strip')]
endif

if host_machine.endian() == 'little'
  endian_option = ['--endian', 'little']
else
  endian_option = ['--endian', 'big']
endif

custom_target('frida-gadget',
  input: raw_gadget,
  output: 'frida-gadget' + shlib_suffix,
  command: [
    modulate,
    '@INPUT@',
    ] + operations + endian_option + [
    '--output', '@OUTPUT@',
    '--nm', meson.get_cross_binary('nm', 'nm'),
    '--objdump', meson.get_cross_binary('objdump', 'objdump'),
    '--otool', meson.get_cross_binary('otool', 'otool'),
    '--install-name-tool', meson.get_cross_binary('install_name_tool', 'install_name_tool'),
  ],
  build_by_default: true,
  install: true,
  install_dir: get_option('libdir'),
)

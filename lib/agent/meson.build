agent_sources = [
  'agent.vala',
  'agent-glue.c',
]

force_cpp_linking = gumjs_dep.get_pkgconfig_variable('gumjs_v8') == 'enabled'
if force_cpp_linking
  agent_sources += ['dummy.cpp']
endif

extra_vala_args = []
extra_link_args = []

if host_os_family != 'windows'
  extra_vala_args += ['--pkg=posix']
endif

if host_os_family == 'darwin'
  extra_link_args += ['-Wl,-exported_symbol,_frida_agent_main']
elif host_os_family != 'windows'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), 'frida-agent.version')]
endif

if host_os_family in ['linux', 'qnx']
  # For our libc shim to be effective.
  extra_link_args += ['-Wl,-Bsymbolic']
endif

raw_agent = shared_library('frida-agent', agent_sources,
  name_prefix: 'lib',
  c_args: frida_component_cflags,
  vala_args: extra_vala_args,
  link_args: extra_link_args,
  vs_module_defs: 'frida-agent.def',
  override_options: ['b_asneeded=true'],
  dependencies: [gio_dep, gee_dep, gum_dep, gumjs_dep, base_dep, pipe_dep, tls_provider_dep, payload_dep],
)

operations = ['--move', 'constructor', 'frida_init_memory', 'first']
if host_os_family != 'darwin'
  operations += ['--move', 'destructor', 'frida_deinit_memory', 'first']
endif

if host_machine.endian() == 'little'
  endian_option = ['--endian', 'little']
else
  endian_option = ['--endian', 'big']
endif

modulated_agent = custom_target('frida-agent-modulated',
  input: raw_agent,
  output: 'libfrida-agent-modulated' + shlib_suffix,
  command: [
    modulate,
    '@INPUT@',
    ] + operations + endian_option + [
    '--output', '@OUTPUT@',
    '--nm', meson.get_cross_binary('nm', 'nm'),
    '--readelf', meson.get_cross_binary('readelf', 'readelf'),
    '--otool', meson.get_cross_binary('otool', 'otool'),
  ],
)

if host_os_family == 'darwin'
  identity = 'FridaAgent'
else
  identity = agent_name
endif

agent = custom_target('frida-agent',
  input: modulated_agent,
  output: agent_name,
  command: [
    post_process_module,
    '@INPUT@',
    '@OUTPUT@',
    identity,
    host_os,
    meson.get_cross_binary('strip', 'strip'),
    get_option('strip').to_string(),
  ],
  build_by_default: true,
  install: get_option('assets') == 'installed',
  install_dir: asset_dir,
)

agent_dep = declare_dependency(link_with: agent)

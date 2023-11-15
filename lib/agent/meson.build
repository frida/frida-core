agent_sources = [
  'agent.vala',
  'agent-glue.c',
]

force_cpp_linking = have_v8
if force_cpp_linking
  agent_sources += ['dummy.cpp']
endif

extra_vala_args = []
extra_link_args = []

if host_os_family != 'windows'
  extra_vala_args += '--pkg=posix'
endif
if host_os_family == 'darwin'
  extra_vala_args += '--pkg=frida-gum-darwin-1.0'
endif

if host_os_family == 'darwin'
  extra_link_args += '-Wl,-exported_symbol,_frida_agent_main'
elif host_os_family != 'windows'
  symscript = 'frida-agent.version'
  extra_link_args += '-Wl,--version-script,' + (meson.current_source_dir() / symscript)
endif

if host_os_family in ['linux', 'qnx']
  # For our libc shim to be effective.
  extra_link_args += '-Wl,-Bsymbolic'
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
    '--nm', nm,
    '--readelf', readelf,
    '--otool', otool,
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
  ],
  build_by_default: true,
  install: get_option('assets') == 'installed',
  install_dir: asset_dir,
)

agent_dep = declare_dependency(link_with: agent)

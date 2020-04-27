agent_sources = [
  'agent.vala',
  'agent-glue.c',
]

force_cpp_linking = gumjs_dep.get_pkgconfig_variable('gumjs_v8') == 'enabled'
if force_cpp_linking
  agent_sources += ['dummy.cpp']
endif

extra_link_args = []
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
  name_prefix: '_',
  c_args: frida_component_cflags,
  link_args: extra_link_args,
  vs_module_defs: 'frida-agent.def',
  override_options: ['b_asneeded=true'],
  dependencies: [gio_dep, gee_dep, gum_dep, gumjs_dep, interfaces_dep, pipe_dep, tls_provider_dep, payload_dep],
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

agent = custom_target('frida-agent',
  input: raw_agent,
  output: 'frida-agent' + shlib_suffix,
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
)

agent_dep = declare_dependency(link_with: agent)

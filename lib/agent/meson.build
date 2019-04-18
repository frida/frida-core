agent_sources = [
  'agent.vala',
  'agent-glue.c',
  'script-engine.vala',
  'libc.c',
]

if host_os_family == 'linux'
  agent_sources += ['syscall-linux-@0@.S'.format(host_arch)]
endif

if not enable_diet
  agent_sources += ['allocator.cpp']
endif

extra_vala_args = []
if host_os_family != 'windows'
  extra_vala_args += ['--pkg=posix']
endif

extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += ['-Wl,-exported_symbol,_frida_agent_main', '-Wl,-dead_strip_dylibs']
elif host_os_family != 'windows'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), 'frida-agent.version')]
endif

agent = shared_library('frida-agent', agent_sources,
  name_prefix: '',
  c_args: frida_component_cflags,
  vala_args: extra_vala_args,
  link_args: extra_link_args,
  vs_module_defs: 'frida-agent.def',
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep, interfaces_dep, pipe_dep, tls_provider_dep],
)

agent_dep = declare_dependency(link_with: agent)

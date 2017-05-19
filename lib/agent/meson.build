agent_sources = [
  'agent.vala',
  'agent-glue.c',
  'script-engine.vala',
]

if not enable_diet
  agent_sources += ['dummy.cpp']
endif

extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += ['-Wl,-exported_symbol,_frida_agent_main']
elif host_os_family != 'windows'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), 'frida-agent.version')]
endif

agent = shared_library('frida-agent', agent_sources,
  name_prefix: '',
  link_args: extra_link_args,
  vs_module_defs: 'frida-agent.def',
  dependencies: [gio_dep, gee_dep, gum_dep, gumjs_dep, interfaces_dep, pipe_dep],
)

agent_dep = declare_dependency(link_with: agent)

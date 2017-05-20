loader_sources = [
  'loader.c',
  'channel-unix.c',
]

extra_link_args = []
if host_os_family == 'darwin'
  extra_link_args += ['-Wl,-exported_symbol,_frida_loader_main']
elif host_os_family != 'windows'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), 'frida-loader.version')]
endif

loader = shared_library('frida-loader', loader_sources,
  name_prefix: '',
  link_args: extra_link_args,
  vs_module_defs: 'frida-loader.def',
  dependencies: [gum_dep],
)

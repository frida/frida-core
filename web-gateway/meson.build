webgw_sources = [
  'web-gateway.vala',
]

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-web-gateway.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-web-gateway.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif

extra_deps = []
if tls_provider_dep.found()
  extra_deps += tls_provider_dep
endif

raw_webgw = executable('frida-web-gateway-raw', webgw_sources,
  vala_args: ['--pkg=posix'],
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: [core_dep] + extra_deps,
)

custom_target('frida-web-gateway',
  input: [
    raw_webgw,
    'frida-web-gateway.xcent',
  ],
  output: 'frida-web-gateway',
  command: [
    files('post-process.sh'),
    '@INPUT@',
    '@OUTPUT@',
    host_os,
    meson.get_cross_binary('strip', 'strip'),
    get_option('strip').to_string(),
  ],
  install: true,
  install_dir: get_option('bindir'),
)

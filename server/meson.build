server_sources = [
  'server.vala',
  'server-glue.c',
]

if host_os_family == 'darwin'
  server_sources += ['server-darwin.m']
endif
if host_os == 'ios'
  server_sources += [
    'server-ios.c',
  ]
endif

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-server.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-server.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif
if host_os == 'macos'
  server_plist = 'frida-server.plist'
  extra_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + join_paths(meson.current_source_dir(), server_plist)]
  extra_link_depends += [server_plist]
endif

executable('frida-server', server_sources,
  vala_args: ['--pkg=posix'],
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: [core_dep],
  install: true,
)

server_sources = [
  'server.vala',
  'server-glue.c',
]

system_vala_args = []

if host_os_family == 'darwin'
  server_sources += ['server-darwin.m']
endif

if host_os_family != 'windows'
  system_vala_args += ['--pkg=posix']
endif

server_name = 'frida-server'
if host_os_family == 'darwin'
  server_name = 'frida-server-unsigned'
endif

server_link_args = []
server_link_depends = []
if host_os == 'macos'
  server_plist = 'frida-server.plist'
  server_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + join_paths(meson.current_source_dir(), server_plist)]
  server_link_depends += [server_plist]
endif

server = executable(server_name, server_sources,
  vala_args: system_vala_args,
  link_args: server_link_args,
  link_depends: server_link_depends,
  dependencies: [core_dep],
  install: host_os_family != 'darwin',
)

if host_os_family == 'darwin'
  custom_target('frida-server-signed',
    input: [
      server,
      'frida-server.xcent',
    ],
    output: 'frida-server',
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
    install_dir: get_option('bindir'),
  )
endif

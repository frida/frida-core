pipe_sources = [
  'pipe.vala',
]

system_deps = []
vala_args = []

if host_os_family == 'windows'
  pipe_sources += [
    'pipe-windows.c',
    'pipe-sddl.c',
  ]
elif host_os_family == 'darwin'
  pipe_sources += ['pipe-darwin.c']
else
  pipe_sources += ['pipe-unix.c']

  system_deps += [gio_unix_dep]
  vala_args += ['--pkg=posix']
endif

if host_os == 'android'
  system_deps += [frida_selinux_dep]
endif

pipe = static_library('frida-pipe', pipe_sources,
  vala_args: vala_args,
  vala_header: 'frida-pipe.h',
  dependencies: [glib_dep, gobject_dep, gio_dep, gee_dep] + system_deps,
)

pipe_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: pipe,
)

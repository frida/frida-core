inject_sources = [
  'inject.vala',
  'inject-glue.c',
]

system_vala_args = []

if host_os_family != 'windows'
  system_vala_args += ['--pkg=posix']
endif

executable('frida-inject', inject_sources,
  vala_args: system_vala_args,
  dependencies: [json_glib_dep, core_dep],
  install: true,
)

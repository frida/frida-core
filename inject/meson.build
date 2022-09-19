inject_sources = [
  'inject.vala',
  'inject-glue.c',
]

system_vala_args = []

if host_os_family != 'windows'
  system_vala_args += ['--pkg=posix']
endif

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-inject.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-inject.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif

raw_inject = executable('frida-inject-raw', inject_sources,
  vala_args: system_vala_args,
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: [json_glib_dep, core_dep],
)

custom_target('frida-inject',
  input: [
    raw_inject,
    'frida-inject.xcent',
  ],
  output: 'frida-inject',
  command: [
    files('post-process.sh'),
    '@INPUT@',
    '@OUTPUT@',
    host_os,
    strip,
    get_option('strip').to_string(),
    codesign,
  ],
  install: true,
  install_dir: get_option('bindir'),
)

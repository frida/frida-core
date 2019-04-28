test_sources = [
  'test-system.vala',
  'test-injector.vala',
  'test-agent.vala',
  'test-agent-glue.c',
  'test-gadget.vala',
  'test-host-session.vala',
  'runner.vala',
  'runner-glue.c',
  'labrats.vala',
  'async-harness.vala',
  'process.vala',
  'process-resource-usage.c',
]

subdir('labrats')

system_vala_args = []

if host_os_family == 'windows'
  test_sources += ['process-windows.c']
else
  test_sources += ['process-unix.c']

  system_vala_args += ['--pkg=posix']
endif

frida_tests = static_library('frida-tests', test_sources + [labrats_stamp],
  vala_args: system_vala_args,
  dependencies: [gmodule_dep, json_glib_dep, core_dep],
)

runner_name = 'frida-tests'
if host_os_family == 'darwin'
  runner_name = 'frida-tests-unsigned'
endif

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-tests.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), symlist)]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-tests.version'
  extra_link_args += ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), symscript)]
  extra_link_depends += [symscript]
endif
if host_os == 'macos'
  runner_plist = 'frida-tests.plist'
  extra_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + join_paths(meson.current_source_dir(), runner_plist)]
  extra_link_depends += [runner_plist]
endif

runner = executable(runner_name, 'main.vala',
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  link_with: frida_tests,
  dependencies: [core_dep],
)

if host_os_family == 'darwin'
  custom_target('frida-tests-signed',
    input: [
      runner,
      'frida-tests.xcent',
    ],
    output: 'frida-tests',
    command: [
      files('sign.sh'),
      host_os,
      '@INPUT@',
      '@OUTPUT@',
    ],
    build_by_default: true,
  )
endif

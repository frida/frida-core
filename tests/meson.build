test_sources = [
  'test-system.vala',
  'test-host-session.vala',
  'runner.vala',
  'runner-glue.c',
  'labrats.vala',
  'async-harness.vala',
  'process.vala',
  'process-resource-usage.c',
]

if host_os_family == 'darwin'
  test_sources += 'test-host-session-darwin-glue.m'
endif

test_vala_args = []
test_depends = []

if agent_compat != ''
  test_vala_args += '--define=CROSS_ARCH'
endif

if build_gadget
  test_vala_args += '--define=HAVE_GADGET'
  test_sources += 'test-gadget.vala'
  test_depends += gadget
endif

subdir('labrats')

system_vala_args = []

if have_local_backend
  test_sources += [
    'test-injector.vala',
    'test-agent.vala',
    'test-agent-glue.c',
  ]
endif

if have_compiler_backend
  test_sources += 'test-compiler.vala'
endif

if host_os_family == 'windows'
  test_sources += ['process-windows.c']
else
  test_sources += ['process-unix.c']

  system_vala_args += ['--pkg=posix']
endif

frida_tests = static_library('frida-tests', test_sources,
  vala_args: [
    '--pkg=gmodule-2.0',
    test_vala_args,
    core_vala_args,
    system_vala_args,
  ],
  dependencies: [gmodule_dep, json_glib_dep, core_dep],
)

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-tests.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + meson.current_source_dir() / symlist]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-tests.version'
  extra_link_args += ['-Wl,--version-script,' + meson.current_source_dir() / symscript]
  extra_link_depends += [symscript]
endif
if host_os == 'macos'
  runner_plist = 'frida-tests.plist'
  extra_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + meson.current_source_dir() / runner_plist]
  extra_link_depends += [runner_plist]
endif

raw_runner = executable('frida-tests-raw', 'main.vala',
  vala_args: [core_vala_args, system_vala_args],
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  link_with: frida_tests,
  dependencies: [core_dep],
)

runner = custom_target('frida-tests',
  input: [raw_runner, 'frida-tests.xcent'],
  output: 'frida-tests' + exe_suffix,
  command: post_process + ['executable', 're.frida.CoreTests', '@INPUT1@'],
  build_by_default: true,
)

test('core', python,
  args: [files('run.py'), runner.full_path()],
  timeout: 120,
  depends: [runner, labrats, test_depends],
)

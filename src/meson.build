facade = files('frida.vala')

base_sources = [
  facade,
  'frida-glue.c',
  'debugger.vala',
  'host-session-service.vala',
  'agent-container.vala',
  'system.vala',
]

windows_sources = []
darwin_sources = []
linux_sources = []
qnx_sources = []

backend_vala_args = []
backend_libs = []
backend_deps = []

if host_os_family == 'windows'
  # TODO
endif

if host_os_family == 'darwin'
  darwin_sources = [
    'darwin/darwin-host-session.vala',
    'darwin/darwin-host-session-glue.m',
    'darwin/fruitjector.vala',
    'darwin/frida-helper-process.vala',
    'darwin/icon-helpers.m',
    'darwin/system-darwin.m',
  ]

  darwin_data = custom_target('frida-data-darwin',
    input: [
      'darwin/frida-darwin.resources',
      'darwin/agent/launchd.js',
      'darwin/agent/xpcproxy.js',
      'darwin/agent/reportcrash.js',
    ],
    output: [
      'frida-data-darwin.vapi',
      'frida-data-darwin.h',
      'frida-data-darwin.c',
      'frida-data-darwin-blob.S',
    ],
    command: [
      resource_compiler,
      '--toolchain=apple',
      '-c', '@INPUT0@',
      '-o', join_paths(meson.current_build_dir(), 'frida-data-darwin'),
      '@INPUT1@',
      '@INPUT2@',
      '@INPUT3@',
    ],
  )
  darwin_sources += [darwin_data]

  helper_backend_sources = [
    'darwin/frida-helper-backend.vala',
    'darwin/frida-helper-backend-glue.m',
    'darwin/policy-softener.vala',
    'darwin/port.vala',
    'darwin/port-glue.m',
  ]
  if host_os == 'ios'
    helper_backend_sources += ['darwin/springboard.m']
  endif
  helper_types_sources = ['darwin/frida-helper-types.vala']
  helper_backend = static_library('frida-helper-backend', helper_backend_sources + helper_types_sources,
    c_args: frida_component_cflags,
    vala_args: ['--pkg=frida-gum-darwin-1.0', '--pkg=posix'],
    dependencies: [gmodule_dep, gio_dep, gio_unix_dep, gee_dep, gum_dep, interfaces_dep, pipe_dep],
  )
  backend_libs += [helper_backend]

  helper_sources = [
    'darwin/frida-helper-service.vala',
    'darwin/frida-helper-service-glue.m',
  ]
  helper_link_args = []
  helper_link_depends = []
  if host_os == 'macos'
    helper_plist = 'darwin/frida-helper.plist'
    helper_link_args += ['-Wl,-sectcreate,__TEXT,__info_plist,' + join_paths(meson.current_source_dir(), helper_plist)]
    helper_link_depends += [helper_plist]
  endif
  helper = executable('frida-helper', helper_sources,
    vala_args: ['--pkg=posix'],
    link_args: helper_link_args + backend_libs_private,
    link_depends: helper_link_depends,
    link_with: helper_backend,
    dependencies: [gio_dep, gio_unix_dep, gee_dep, gum_dep, interfaces_dep, pipe_dep],
  )

  helper32 = get_option('with-32bit-helper')
  helper64 = get_option('with-64bit-helper')
  if helper32 == '' and helper64 == ''
    if host_is_64bit
      helper64 = helper
    else
      helper32 = helper
    endif
  endif
  helper_process_data = custom_target('frida-data-helper-process',
    input: [
      helper32,
      helper64,
      'darwin/frida-helper.xcent',
    ],
    output: [
      'frida-data-helper-process.vapi',
      'frida-data-helper-process.h',
      'frida-data-helper-process.c',
      'frida-data-helper-process-blob.S',
    ],
    command: [
      files('darwin/embed-helper.sh'),
      host_os,
      '@INPUT0@',
      '@INPUT1@',
      '@INPUT2@',
      meson.current_build_dir(),
      resource_compiler,
      meson.get_cross_binary('strip', 'strip'),
      get_option('strip').to_string(),
    ],
  )
  darwin_sources += [helper_process_data]

  backend_vala_args += ['--pkg=posix']
endif

if host_os_family == 'linux'
  linux_sources = [
    'linux/linux-host-session.vala',
    'linux/linjector.vala',
    'linux/linjector-glue.c',
    'linux/frida-helper-process.vala',
    'linux/supersu.vala',
    'linux/system-linux.c',
  ]

  if host_os == 'android'
    backend_vala_args += [frida_selinux_vala_args]
    backend_libs += [frida_selinux, frida_selinux_modern, frida_selinux_legacy, sepol_modern, sepol_legacy, selinux]
    backend_deps += [frida_selinux_dep]

    android_data = custom_target('frida-data-android',
      input: [
        'linux/frida-android.resources',
        'linux/agent/system-server.js',
      ],
      output: [
        'frida-data-android.vapi',
        'frida-data-android.h',
        'frida-data-android.c',
        'frida-data-android-blob.S',
      ],
      command: [
        resource_compiler,
        '--toolchain=gnu',
        '-c', '@INPUT0@',
        '-o', join_paths(meson.current_build_dir(), 'frida-data-android'),
        '@INPUT1@',
      ],
    )
    linux_sources += [android_data]
  endif

  helper_types_sources = ['linux/frida-helper-types.vala']
  linux_sources += helper_types_sources

  helper_service_sources = [
    'linux/frida-helper-service.vala',
    'linux/frida-helper-service-glue.c',
  ]
  helper_service_extra_deps = []
  if host_os == 'android'
    helper_service_extra_deps += [frida_selinux_dep]
  endif
  helper_service = static_library('frida-helper-service', helper_service_sources + helper_types_sources,
    c_args: frida_component_cflags,
    vala_args: ['--pkg=posix'],
    dependencies: [gio_dep, gio_unix_dep, gee_dep, gum_dep, interfaces_dep] + helper_service_extra_deps,
  )

  helper = executable('frida-helper', 'linux/frida-helper.vala',
    vala_args: ['--pkg=posix'],
    link_with: helper_service,
    dependencies: [gio_dep, gee_dep, gum_dep, interfaces_dep],
  )

  helper32 = get_option('with-32bit-helper')
  helper64 = get_option('with-64bit-helper')
  if helper32 == '' and helper64 == ''
    if host_is_64bit
      helper64 = helper
    else
      helper32 = helper
    endif
  endif
  helper_process_data = custom_target('frida-data-helper-process',
    input: [
      helper32,
      helper64,
    ],
    output: [
      'frida-data-helper-process.vapi',
      'frida-data-helper-process.h',
      'frida-data-helper-process.c',
      'frida-data-helper-process-blob.S',
    ],
    command: [
      files('linux/embed-helper.sh'),
      host_os,
      '@INPUT0@',
      '@INPUT1@',
      meson.current_build_dir(),
      resource_compiler,
      meson.get_cross_binary('strip', 'strip'),
      get_option('strip').to_string(),
    ],
  )
  linux_sources += [helper_process_data]

  backend_vala_args += ['--pkg=posix', '--pkg=frida-gum-linux-1.0']
endif

if host_os_family == 'qnx'
  qnx_sources = [
    'qnx/qnx-host-session.vala',
    'qnx/qinjector.vala',
    'qnx/qinjector-glue.c',
    'qnx/system-qnx.c',
  ]
endif

agent32 = get_option('with-32bit-agent')
agent64 = get_option('with-64bit-agent')
if agent32 == '' and agent64 == ''
  if host_is_64bit
    agent64 = agent
  else
    agent32 = agent
  endif
endif
agent_data = custom_target('frida-data-agent',
  input: [
    agent32,
    agent64,
    'agent.resources',
  ],
  output: [
    'frida-data-agent.vapi',
    'frida-data-agent.h',
    'frida-data-agent.c',
    'frida-data-agent-blob.S',
  ],
  command: [
    files('embed-agent.sh'),
    host_os,
    '@INPUT0@',
    '@INPUT1@',
    meson.current_build_dir(),
    resource_compiler,
    '@INPUT2@',
    meson.get_cross_binary('strip', 'strip'),
    get_option('strip').to_string(),
  ],
)

tcp_sources = [
  'tcp/tcp-host-session.vala',
]

fruity_sources = [
  'fruity/fruity-client.vala',
  'fruity/fruity-host-session.vala',
  'fruity/fruity-property-list.vala',
]
if host_os_family == 'windows'
  fruity_sources += ['fruity/fruity-host-session-windows.c']
elif host_os_family == 'darwin'
  fruity_sources += ['fruity/fruity-host-session-darwin.m']
else
  fruity_sources += ['fruity/fruity-host-session-unix.c']
endif

droidy_sources = [
  'droidy/droidy-host-session.vala',
  'droidy/droidy-client.vala',
]

local_sources = windows_sources + darwin_sources + linux_sources + qnx_sources + [agent_data]
remote_sources = tcp_sources + fruity_sources + droidy_sources

core_sources = base_sources + local_sources + remote_sources

if host_os_family != 'windows'
  backend_deps += [gio_unix_dep]
endif

internal_libs = [interfaces, pipe] + backend_libs
internal_deps = [interfaces_dep, pipe_dep]

core = library('frida-core', core_sources,
  c_args: frida_component_cflags,
  vala_args: backend_vala_args,
  link_args: backend_libs_private,
  link_with: backend_libs,
  dependencies: [glib_dep, gobject_dep, gmodule_dep, gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep] + backend_deps + internal_deps,
)

core_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_args: backend_libs_private,
  link_with: [core] + backend_libs,
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep] + backend_deps + internal_deps,
)

core_build_dir = meson.current_build_dir()
subdir('api')

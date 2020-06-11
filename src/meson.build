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
      'darwin/agent/osanalytics.js',
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
      '@INPUT4@',
    ],
  )
  darwin_sources += [darwin_data]

  helper_backend_sources = [
    'darwin/frida-helper-backend.vala',
    'darwin/frida-helper-backend-glue.m',
    'darwin/frida-helper-types.vala',
    'darwin/policy-softener.vala',
    'darwin/policy-softener-glue.c',
    'darwin/substitutedclient.c',
    'darwin/port.vala',
    'darwin/port-glue.m',
  ]
  if host_os == 'ios'
    helper_backend_sources += ['darwin/springboard.m']
  endif
  helper_backend = static_library('frida-helper-backend', helper_backend_sources,
    c_args: frida_component_cflags,
    vala_args: ['--pkg=frida-gum-darwin-1.0', '--pkg=posix'],
    dependencies: [gmodule_dep, gio_dep, gio_unix_dep, gee_dep, gum_dep, interfaces_dep, pipe_dep],
  )
  backend_libs += [helper_backend]

  helper_sources = [
    'darwin/frida-helper-service.vala',
    'darwin/frida-helper-service-glue.m',
  ]
  helper_symlist = 'darwin/frida-helper.symbols'
  helper_link_args = ['-Wl,-exported_symbols_list,' + join_paths(meson.current_source_dir(), helper_symlist)]
  helper_link_depends = [helper_symlist]
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
    override_options: ['b_asneeded=false'],
  )

  helper_modern = get_option('helper_modern')
  helper_legacy = get_option('helper_legacy')
  helper_inputs = ['darwin/frida-helper.xcent']
  if helper_modern == '' and helper_legacy == ''
    if host_is_64bit
      helper_modern = helper.full_path()
    else
      helper_legacy = helper.full_path()
    endif
    helper_inputs += helper
  endif
  helper_process_data = custom_target('frida-data-helper-process',
    input: helper_inputs,
    output: [
      'frida-data-helper-process.vapi',
      'frida-data-helper-process.h',
      'frida-data-helper-process.c',
      'frida-data-helper-process-blob.S',
    ],
    command: [
      files('darwin/embed-helper.sh'),
      host_os,
      helper_modern,
      helper_legacy,
      '@INPUT0@',
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

  helper_backend_sources = [
    'linux/frida-helper-backend.vala',
    'linux/frida-helper-backend-glue.c',
    'linux/frida-helper-types.vala',
  ]
  helper_backend_extra_deps = []
  if host_os == 'android'
    helper_backend_extra_deps += [frida_selinux_dep]
  endif
  helper_backend = static_library('frida-helper-backend', helper_backend_sources,
    c_args: frida_component_cflags,
    vala_args: ['--pkg=posix'],
    dependencies: [gio_dep, gio_unix_dep, gee_dep, gum_dep, interfaces_dep] + helper_backend_extra_deps,
  )
  backend_libs += [helper_backend]

  helper_sources = [
    'linux/frida-helper-service.vala',
  ]
  helper_symscript = 'linux/frida-helper.version'
  helper_link_args = ['-Wl,--version-script,' + join_paths(meson.current_source_dir(), helper_symscript)]
  helper_link_depends = [helper_symscript]
  helper = executable('frida-helper', helper_sources,
    vala_args: ['--pkg=posix'],
    link_args: helper_link_args,
    link_depends: helper_link_depends,
    link_with: helper_backend,
    dependencies: [gio_dep, gee_dep, gum_dep, interfaces_dep],
  )

  helper_modern = get_option('helper_modern')
  helper_legacy = get_option('helper_legacy')
  if host_is_64bit
    helper_modern = ''
  else
    helper_legacy = ''
  endif
  helper_process_data = custom_target('frida-data-helper-process',
    output: [
      'frida-data-helper-process.vapi',
      'frida-data-helper-process.h',
      'frida-data-helper-process.c',
      'frida-data-helper-process-blob.S',
    ],
    command: [
      files('linux/embed-helper.sh'),
      host_os,
      helper_modern,
      helper_legacy,
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

agent_modern = get_option('agent_modern')
agent_legacy = get_option('agent_legacy')
agent_inputs = ['agent.resources']
if agent_modern == '' and agent_legacy == ''
  if host_is_64bit
    agent_modern = agent.full_path()
  else
    agent_legacy = agent.full_path()
  endif
  agent_inputs += agent
endif
agent_data = custom_target('frida-data-agent',
  input: agent_inputs,
  output: [
    'frida-data-agent.vapi',
    'frida-data-agent.h',
    'frida-data-agent.c',
    'frida-data-agent-blob.S',
  ],
  command: [
    files('embed-agent.sh'),
    host_os,
    agent_modern,
    agent_legacy,
    meson.current_build_dir(),
    resource_compiler,
    '@INPUT0@',
    meson.get_cross_binary('strip', 'strip'),
    get_option('strip').to_string(),
  ],
)

socket_sources = [
  'socket/socket-host-session.vala',
]

fruity_sources = [
  'fruity/fruity-host-session.vala',
  'fruity/dtx.vala',
  'fruity/lockdown.vala',
  'fruity/installation-proxy.vala',
  'fruity/lldb.vala',
  'fruity/injector.vala',
  'fruity/usbmux.vala',
  'fruity/keyed-archive.vala',
  'fruity/plist.vala',
  'fruity/plist-service.vala',
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
remote_sources = socket_sources + fruity_sources + droidy_sources

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
  dependencies: [glib_dep, gobject_dep, gmodule_dep, gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep, tls_provider_dep] + backend_deps + internal_deps,
)

core_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_args: backend_libs_private,
  link_with: [core] + backend_libs,
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep] + backend_deps + internal_deps,
)

core_build_dir = meson.current_build_dir()
subdir('api')

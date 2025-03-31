base_sources = [
  'session.vala',
  'session-glue.c',
  'channel.vala',
  'service.vala',
  'stream.vala',
  'rpc.vala',
  'p2p.vala',
  'p2p-glue.c',
  'dbus.vala',
  'promise.vala',
  'socket.vala',
  'socket-glue.c',
  'buffer.vala',
  'value.vala',
]

extra_vala_args = []

if host_os == 'macos'
  base_sources += [
    'xpc.vala',
    'frida-darwin.c',
  ]
endif

if host_os_family == 'darwin'
  base_sources += 'corefoundation.vala'
endif

extra_deps = []
if host_os_family != 'windows'
  extra_vala_args += '--pkg=gio-unix-2.0'
  extra_deps += gio_unix_dep
endif

base_vala_args = [gum_vala_args, '--pkg=gio-2.0', '--pkg=json-glib-1.0']
if nice_dep.found()
  base_vala_args += '--pkg=nice'
endif
if host_os_family == 'darwin'
  base_vala_args += [
    '--pkg=corefoundation',
    '--pkg=darwin-gcd',
    '--pkg=darwin-xpc',
  ]
endif

base_gir_name = f'FridaBase-@api_version@.gir'

base = static_library('frida-base-' + api_version, base_sources,
  c_args: frida_component_cflags,
  vala_args: [base_vala_args, '--pkg=libsoup-3.0'] + extra_vala_args,
  vala_header: 'frida-base.h',
  vala_gir: base_gir_name,
  vala_vapi: f'frida-base-@api_version@.vapi',
  dependencies: [glib_dep, gobject_dep, gio_dep, libsoup_dep, nice_dep, usrsctp_dep, gee_dep, json_glib_dep, gum_dep, openssl_dep] + extra_deps,
  install: true,
  install_dir: [true, header_install_dir, true, false],
)

base_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: base,
  dependencies: [nice_dep, json_glib_dep, gum_dep],
)

base_build_dir = meson.current_build_dir()

pkg = import('pkgconfig')
pkg.generate(base,
  filebase: f'frida-base-@api_version@',
  name: 'Frida Base Library',
  version: frida_version,
  description: 'Basic building blocks',
)

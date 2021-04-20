base_sources = [
  'session.vala',
  'rpc.vala',
  'dbus.vala',
  'promise.vala',
  'socket.vala',
  'socket-glue.c',
]

extra_deps = []
if host_os_family != 'windows'
  extra_deps += [gio_unix_dep]
endif

base = static_library('frida-base', base_sources,
  c_args: frida_component_cflags,
  vala_header: 'frida-base.h',
  dependencies: [glib_dep, gobject_dep, gio_dep, gee_dep, json_glib_dep, gum_dep] + extra_deps,
)

base_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: base,
  dependencies: [json_glib_dep, gum_dep],
)

base_build_dir = meson.current_build_dir()

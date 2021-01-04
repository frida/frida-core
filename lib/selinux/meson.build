frida_selinux_incdir = include_directories('.')

install_headers('frida-selinux.h', subdir: 'frida-' + api_version)

frida_selinux = static_library('frida-selinux', 'patch.c',
  c_args: frida_component_cflags,
  include_directories: frida_selinux_incdir,
  dependencies: [glib_dep, libselinux_dep, libsepol_dep],
)

frida_selinux_dep = declare_dependency(
  link_with: frida_selinux,
)

frida_selinux_vala_args = ['--pkg=libselinux']

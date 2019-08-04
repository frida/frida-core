generate_api = files('generate.py')

core_vapi = join_paths(core_build_dir, 'frida-core.vapi')
core_header = join_paths(core_build_dir, 'frida-core.h')
interfaces_vapi = join_paths(interfaces_build_dir, 'frida-interfaces.vapi')
interfaces_header = join_paths(interfaces_build_dir, 'frida-interfaces.h')

custom_target('frida-core-header',
  input: [core, interfaces],
  output: ['frida-core.h'],
  command: [
    generate_api,
    '--output=header',
    api_version,
    facade,
    core_vapi, core_header,
    interfaces_vapi, interfaces_header,
    meson.current_build_dir(),
  ],
  install: true,
  install_dir: join_paths(get_option('includedir'), 'frida-' + api_version),
)

custom_target('frida-core-vapi',
  input: [core, interfaces],
  output: [
    'frida-core-@0@.vapi'.format(api_version),
    'frida-core-@0@.deps'.format(api_version)
  ],
  command: [
    generate_api,
    '--output=vapi',
    api_version,
    facade,
    core_vapi, core_header,
    interfaces_vapi, interfaces_header,
    meson.current_build_dir(),
  ],
  install: true,
  install_dir: join_paths(get_option('datadir'), 'vala', 'vapi'),
)

custom_target('frida-core-library',
  input: [core] + internal_libs,
  output: 'libfrida-core-@0@.a'.format(api_version),
  command: [
    files('merge.sh'),
    meson.get_cross_binary('ar', ''),
    meson.get_cross_binary('libtool', ''),
    meson.current_build_dir(),
    '@OUTPUT@',
    '@INPUT@'
  ],
  install: true,
  install_dir: get_option('libdir'),
)

pkg = import('pkgconfig')
pkg.generate(filebase: 'frida-core-' + api_version,
  name: 'Frida Core',
  version: meson.project_version(),
  description: 'Frida core library intended for static linking into bindings',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'json-glib-1.0'],
  requires_private: ['gmodule-2.0', 'gee-0.8', 'frida-gum-1.0', 'frida-gumjs-1.0'] + backend_deps_private,
  subdirs: 'frida-' + api_version,
  libraries: ['-L${libdir}', '-lfrida-core-' + api_version],
  libraries_private: backend_libs_private,
)

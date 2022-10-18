generate_api = files('generate.py')

core_vapi = join_paths(core_build_dir, 'frida-core.vapi')
core_header = join_paths(core_build_dir, 'frida-core.h')
base_vapi = join_paths(base_build_dir, f'frida-base-@api_version@.vapi')
base_header = join_paths(base_build_dir, 'frida-base.h')

custom_target('frida-core-header',
  input: [core, base],
  output: ['frida-core.h'],
  command: [
    generate_api,
    '--output=header',
    api_version,
    core_vapi, core_header,
    base_vapi, base_header,
    meson.current_build_dir(),
  ],
  install: true,
  install_dir: header_install_dir,
)

custom_target('frida-core-vapi',
  input: [core, base],
  output: [
    'frida-core-@0@.vapi'.format(api_version),
    'frida-core-@0@.deps'.format(api_version)
  ],
  command: [
    generate_api,
    '--output=vapi',
    api_version,
    core_vapi, core_header,
    base_vapi, base_header,
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
    ar,
    libtool,
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
  requires_private: ['gmodule-2.0', 'gee-0.8', libsoup_dep, 'frida-gum-1.0', 'frida-gumjs-inspector-1.0', 'libbrotlidec'] + backend_deps_private,
  subdirs: 'frida-' + api_version,
  libraries: ['-L${libdir}', '-lfrida-core-' + api_version],
  libraries_private: backend_libs_private,
)

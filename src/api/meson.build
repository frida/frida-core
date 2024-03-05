generate_api = [python, files('generate.py')]

core_vapi = join_paths(core_build_dir, 'frida-core.vapi')
core_header = join_paths(core_build_dir, 'frida-core.h')
base_vapi = join_paths(base_build_dir, f'frida-base-@api_version@.vapi')
base_header = join_paths(base_build_dir, 'frida-base.h')

core_public_h = custom_target('frida-core-header',
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

core_public_vapi = custom_target('frida-core-vapi',
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

core_public_lib = custom_target('frida-core-library',
  input: [core] + internal_libs,
  output: 'libfrida-core-@0@.a'.format(api_version),
  command: [
    python,
    files('merge.py'),
    lib,
    libtool,
    ar,
    meson.current_build_dir(),
    '@OUTPUT@',
    '@INPUT@'
  ],
  install: true,
  install_dir: get_option('libdir'),
)

fs = import('fs')

core_public_extra_headers = []
if host_os == 'android'
  core_public_extra_headers += fs.copyfile(frida_selinux_h)
endif

core_public_dep = declare_dependency(
  sources: [core_public_h, core_public_vapi] + core_public_extra_headers,
  include_directories: include_directories('.'),
  link_args: backend_libs_private,
  link_with: core_public_lib,
  dependencies: core_deps,
  variables: [
    'vapidir=' + meson.current_build_dir(),
  ],
)

if build_machine.system() == 'windows'
  uninstalled_incdir = fs.as_posix(meson.current_build_dir())
else
  uninstalled_incdir = meson.current_build_dir()
endif

pkg = import('pkgconfig')
pkg.generate(
  filebase: 'frida-core-' + api_version,
  name: 'Frida Core',
  version: meson.project_version(),
  description: 'Frida core library intended for static linking into bindings',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'json-glib-1.0'],
  requires_private: ['gmodule-2.0', 'gee-0.8', 'libsoup-3.0', 'frida-gum-1.0', 'frida-gumjs-inspector-1.0', 'libbrotlidec'] + backend_reqs_private,
  subdirs: 'frida-' + api_version,
  libraries: [core_public_lib],
  libraries_private: backend_libs_private,
  extra_cflags: ['-I${frida_includedir}'],
  variables: {
    'frida_includedir': '${includedir}',
    'frida_girdir': girdir,
  },
  uninstalled_variables: {
    'frida_includedir': uninstalled_incdir,
    'frida_girdir': uninstalled_girdir,
  },
)

meson.override_dependency('frida-core-' + api_version, core_public_dep)

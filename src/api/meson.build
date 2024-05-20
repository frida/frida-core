generate_api = [python, files('generate.py')]

generate_api_args = [
  api_version,
  core_build_dir / core_gir_name,
  core_build_dir / 'frida-core.vapi',
  core_build_dir / 'frida-core.h',
  base_build_dir / f'frida-base-@api_version@.vapi',
  base_build_dir / 'frida-base.h',
  meson.current_build_dir(),
]

core_public_h = custom_target('frida-core-header',
  input: [core, base],
  output: ['frida-core.h'],
  command: [
    generate_api,
    '--output=header',
    generate_api_args,
  ],
  install: true,
  install_dir: header_install_dir,
)

core_public_gir = custom_target('frida-core-gir',
  input: [core, base],
  output: [core_gir_name],
  command: [
    generate_api,
    '--output=gir',
    generate_api_args,
  ],
  install: true,
  install_dir: girdir,
)

core_public_vapi = custom_target('frida-core-vapi',
  input: [core, base],
  output: [
    f'frida-core-@api_version@.vapi',
    f'frida-core-@api_version@.deps',
  ],
  command: [
    generate_api,
    '--output=vapi',
    generate_api_args,
  ],
  install: true,
  install_dir: vapidir,
)

core_public_vapi_stamp =  custom_target('frida-core-vapi-stamp',
  input: core_public_vapi,
  output: f'frida-core-@api_version@.vapi.stamp',
  command: [
    generate_api,
    '--output=vapi-stamp',
    generate_api_args,
  ],
)

core_public_lib = custom_target('frida-core-library',
  input: [core] + internal_libs,
  output: f'libfrida-core-@api_version@.a',
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

if build_machine.system() == 'windows'
  uninstalled_incdir = fs.as_posix(meson.current_build_dir())
else
  uninstalled_incdir = meson.current_build_dir()
endif
uninstalled_vapidir = uninstalled_incdir

uninstalled_variables = {
  'frida_includedir': uninstalled_incdir,
  'frida_girdir': uninstalled_girdir,
  'frida_vapidir': uninstalled_vapidir,
}

installed_variables = {
  'frida_includedir': '${includedir}',
  'frida_girdir': girdir,
  'frida_vapidir': vapidir,
}

core_public_dep = declare_dependency(
  sources: [core_public_h, core_public_gir, core_public_vapi_stamp, core_public_extra_headers],
  include_directories: include_directories('.'),
  link_args: backend_libs_private,
  link_with: core_public_lib,
  dependencies: core_deps,
  variables: uninstalled_variables,
)

pkg = import('pkgconfig')
pkg.generate(
  filebase: f'frida-core-@api_version@',
  name: 'Frida Core Library',
  version: frida_version,
  description: 'Instrumentation toolkit for developers, reverse-engineers, and security researchers',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'json-glib-1.0'],
  requires_private: ['gmodule-2.0', 'gee-0.8', 'libsoup-3.0', 'frida-gum-1.0', 'frida-gumjs-inspector-1.0', 'libbrotlidec'] + backend_reqs_private,
  subdirs: f'frida-@api_version@',
  libraries: core_public_lib,
  libraries_private: backend_libs_private,
  extra_cflags: ['-I${frida_includedir}'],
  variables: installed_variables,
  uninstalled_variables: uninstalled_variables,
)

meson.override_dependency(f'frida-core-@api_version@', core_public_dep)

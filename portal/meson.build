portal_sources = [
  'portal.vala',
]

extra_link_args = []
extra_link_depends = []
if host_os_family == 'darwin'
  symlist = 'frida-portal.symbols'
  extra_link_args += ['-Wl,-exported_symbols_list,' + meson.current_source_dir() / symlist]
  extra_link_depends += [symlist]
elif host_os_family != 'windows'
  symscript = 'frida-portal.version'
  extra_link_args += ['-Wl,--version-script,' + meson.current_source_dir() / symscript]
  extra_link_depends += [symscript]
endif

extra_deps = []
if tls_provider_dep.found()
  extra_deps += tls_provider_dep
endif

raw_portal = executable('frida-portal-raw', portal_sources,
  vala_args: [core_vala_args, tls_provider_vala_args, '--pkg=posix'],
  link_args: extra_link_args,
  link_depends: extra_link_depends,
  dependencies: [core_dep] + extra_deps,
)

custom_target('frida-portal',
  input: [raw_portal, 'frida-portal.xcent'],
  output: 'frida-portal' + exe_suffix,
  command: post_process + ['executable', 're.frida.Portal', '@INPUT1@'],
  install: true,
  install_dir: get_option('bindir'),
)

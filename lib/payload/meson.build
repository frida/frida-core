payload_sources = [
  'process.vala',
  'process-glue.c',
  'script-engine.vala',
  'fork-monitor.vala',
  'spawn-monitor.vala',
  'spawn-monitor-glue.c',
  'thread-suspend-monitor.vala',
  'thread-suspend-monitor-glue.c',
  'exit-monitor.vala',
  'cloak.vala',
  'fd-guard.vala',
  'fdt-padder.vala',
  'libc-shim.c',
]

if host_os_family == 'linux'
  payload_sources += ['syscall-linux-@0@.S'.format(host_arch)]
endif

extra_vala_args = []
if host_os_family != 'windows'
  extra_vala_args += ['--pkg=posix']
endif
if host_os_family == 'linux'
  extra_vala_args += ['--pkg=linux']
endif

payload = static_library('frida-payload', payload_sources,
  c_args: frida_component_cflags,
  vala_args: extra_vala_args,
  vala_header: 'frida-payload.h',
  dependencies: [gio_dep, gee_dep, json_glib_dep, gum_dep, gumjs_dep, interfaces_dep],
)

payload_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: payload,
)

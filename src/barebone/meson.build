backend_sources += files(
  'barebone-host-session.vala',
  'script.vala',
  'machine.vala',
  'allocator.vala',
  'callback.vala',
  'memory-scanner.vala',
  'interceptor.vala',
  'rust-module.vala',
  'arch-x86' / 'machine.vala',
  'arch-x86_64' / 'machine.vala',
  'arch-arm' / 'machine.vala',
  'arch-arm64' / 'machine.vala',
  'arch-unknown' / 'machine.vala',
)
barebone_script_runtime = custom_target('frida-barebone-script-runtime',
  input: [
    'package.json',
    'package-lock.json',
    'script-runtime' / 'console.ts',
    'script-runtime' / 'entrypoint.ts',
    'script-runtime' / 'gdb.ts',
    'script-runtime' / 'hexdump.ts',
    'script-runtime' / 'message-dispatcher.ts',
    'script-runtime' / 'primitives.ts',
  ],
  output: [
    'script-runtime.js',
  ],
  command: [
    python,
    compile_js_agent,
    '@OUTPUT@',
    '@PRIVATE_DIR@',
    npm,
    '@INPUT@',
  ],
)
backend_sources += custom_target('frida-data-barebone',
  input: [
    'barebone.resources',
    barebone_script_runtime,
    'helpers/memory-scanner-arm64.elf',
  ],
  output: [
    'frida-data-barebone.vapi',
    'frida-data-barebone.h',
    'frida-data-barebone.c',
    'frida-data-barebone-blob' + resource_blob_extension,
  ],
  command: [
    resource_compiler_cmd_array,
    '-c', '@INPUT0@',
    '-o', meson.current_build_dir() / 'frida-data-barebone',
    '@INPUT1@',
    '@INPUT2@',
  ],
)

backend_vala_args += gum_vala_args
backend_vala_args_private += '--pkg=quickjs'
backend_deps += quickjs_dep

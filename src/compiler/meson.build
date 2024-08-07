compiler_sources = files(
  'compiler.vala',
)

if have_compiler_backend
  compiler_mksnapshot = generate_compiler_snapshot ? v8_mksnapshot : ''

  compiler_agent = custom_target('frida-compiler-agent',
    input: [
      'agent-entrypoint.js',
      'agent-core.ts',
      'agent-warmup.js',
      'package.json',
      'package-lock.json',
      'tsconfig.json',
      'rollup.config.agent-core.ts',
      'rollup.config.typescript.ts',
    ],
    output: [
      'agent.js',
      'snapshot.bin',
    ],
    command: [
      python,
      files('generate-agent.py'),
      meson.current_build_dir(),
      '@PRIVATE_DIR@',
      meson.current_source_dir(),
      npm,
      compiler_mksnapshot,
      host_os_family,
      host_arch_gumjs,
      host_cpu_mode,
    ],
  )
  compiler_data = custom_target('frida-data-compiler',
    input: [
      'compiler.resources.' + frida_profile,
      compiler_agent,
    ],
    output: [
      'frida-data-compiler.vapi',
      'frida-data-compiler.h',
      'frida-data-compiler.c',
      'frida-data-compiler-blob' + resource_blob_extension,
      'frida-data-compiler-agent.js.br',
      'frida-data-compiler-snapshot.bin.br',
    ],
    command: [
      resource_compiler_cmd_array,
      '-c', '@INPUT0@',
      '-o', meson.current_build_dir() / 'frida-data-compiler',
      '@INPUT1@',
      '@INPUT2@',
    ],
  )
  compiler_sources += compiler_data

  backend_vala_args_private += '--pkg=libbrotlidec'
  backend_deps_private += brotlidec_dep
endif

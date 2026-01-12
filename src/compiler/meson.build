compiler_sources = files(
  'compiler.vala',
  'backend-glue.c',
)

if have_compiler_backend
  output_suffix = compiler_backend_static_compilation ? '' : '-raw'
  compiler_backend = custom_target('frida-compiler-backend',
    input: [
      'go.mod',
      'go.sum',
      'backend.go',
      'backend.version',
      'tscompiler.go',
      'tsconfig.go',
      'shims.go',
      'package.json',
      'package-lock.json',
    ],
    output: [
      'frida-compiler-backend' + output_suffix + (compiler_backend_static_compilation ? '.a' : shlib_suffix),
      'frida-compiler-backend' + output_suffix + '.h',
    ],
    command: [
      python,
      files('build-backend.py'),
      go_config,
      meson.current_build_dir(),
      '@PRIVATE_DIR@',
      go,
      npm,
      '@INPUT@',
    ],
  )
  if compiler_backend_static_compilation
    backend_libs += compiler_backend[0]
  else
    filename = 'frida-compiler-backend' + shlib_suffix
    identity = (host_os_family == 'darwin') ? 'FridaCompilerBackend' : filename
    compiler_backend_shlib = custom_target('frida-compiler-backend-shlib',
      input: compiler_backend[0],
      output: filename,
      command: post_process + ['shared-library', identity, 'elf-cleaner:off'],
    )

    compiler_data = custom_target('frida-data-compiler',
      input: [
        'compiler.resources',
        compiler_backend_shlib,
      ],
      output: [
        'frida-data-compiler.vapi',
        'frida-data-compiler.h',
        'frida-data-compiler.c',
        'frida-data-compiler-blob' + resource_blob_extension,
      ],
      command: [
        resource_compiler_cmd_array,
        '-c', '@INPUT0@',
        '-o', meson.current_build_dir() / 'frida-data-compiler',
        '@INPUT1@',
      ],
    )
    backend_sources += compiler_data
  endif
endif

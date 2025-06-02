compiler_sources = files(
  'compiler.vala',
  'backend-glue.c',
)

if have_compiler_backend
  compiler_backend = custom_target('frida-compiler-backend',
    input: [
      'go.mod',
      'go.sum',
      'backend.go',
      'tscompiler.go',
      'tsconfig.go',
      'shims.go',
      'package.json',
      'package-lock.json',
    ],
    output: [
      'frida-compiler-backend.a',
      'frida-compiler-backend.h',
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
  backend_libs += compiler_backend[0]
endif

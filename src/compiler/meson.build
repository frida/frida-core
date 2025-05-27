compiler_sources = files(
  'compiler.vala',
)

if have_compiler_backend
  compiler_backend = custom_target('frida-compiler-backend',
    input: [
      'backend.go',
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
      meson.current_build_dir(),
      '@PRIVATE_DIR@',
      go,
      npm,
      '@INPUT@',
    ],
  )
  backend_libs += compiler_backend[0]
endif

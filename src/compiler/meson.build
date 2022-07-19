compiler_sources = files(
  'compiler.vala',
  'compiler-glue.c',
)

compiler_agent = custom_target('frida-compiler-agent',
  input: [
    'agent.ts',
    'package.json',
    'package-lock.json',
    'tsconfig.json',
  ],
  output: 'agent.zip',
  command: [
    find_program('generate-agent.py'),
    meson.current_source_dir(),
    meson.current_build_dir(),
  ],
)
if host_os_family == 'darwin'
  toolchain = 'apple'
else
  toolchain = 'gnu'
endif
compiler_data = custom_target('frida-data-compiler',
  input: [
    'compiler.resources',
    compiler_agent,
  ],
  output: [
    'frida-data-compiler.vapi',
    'frida-data-compiler.h',
    'frida-data-compiler.c',
    'frida-data-compiler-blob.S',
  ],
  command: [
    resource_compiler,
    '--toolchain=' + toolchain,
    '-c', '@INPUT0@',
    '-o', join_paths(meson.current_build_dir(), 'frida-data-compiler'),
    '@INPUT1@',
  ],
)
compiler_sources += compiler_data

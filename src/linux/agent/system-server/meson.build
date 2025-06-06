system_server_js = custom_target('system-server.js',
  input: [
    'package.json',
    'package-lock.json',
    'build.js',
    'index.js',
  ],
  output: [
    'system-server.js',
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

labrat_files = []

if host_os == 'macos'
  labrat_files += [
    'sleeper-macos',
    'sleeper-macos32',
    'stdio-writer-macos',
    'stdio-writer-macos32',
    'forker-macos',
    'forker-macos32',
    'spawner-macos',
    'simple-agent-macos.dylib',
    'resident-agent-macos.dylib',
  ]
endif

if host_os == 'linux'
  labrat_files += [
    'sleeper-linux-' + host_abi,
    'forker-linux-' + host_abi,
    'spawner-linux-' + host_abi,
    'simple-agent-linux-' + host_abi + '.so',
    'resident-agent-linux-' + host_abi + '.so',
  ]
endif

if host_os == 'ios'
  labrat_files += [
    'sleeper-ios',
    'sleeper-ios32',
    'sleeper-ios64',
    'stdio-writer-ios',
    'stdio-writer-ios32',
    'stdio-writer-ios64',
    'forker-ios',
    'forker-ios32',
    'forker-ios64',
    'spawner-ios',
    'simple-agent-ios.dylib',
    'resident-agent-ios.dylib',
  ]
endif

if host_os == 'android'
  labrat_files += [
    'sleeper-android-' + host_abi,
    'forker-android-' + host_abi,
    'spawner-android-' + host_abi,
    'simple-agent-android-' + host_abi + '.so',
    'resident-agent-android-' + host_abi + '.so',
  ]
endif

if host_os == 'qnx'
  labrat_files += [
    'sleeper-qnx-arm',
    'forker-qnx-arm',
    'spawner-qnx-arm',
    'simple-agent-qnx-arm.so',
  ]
endif

labrats = custom_target('labrats',
  input: labrat_files,
  output: labrat_files,
  command: ['cp', '@INPUT@', '@OUTDIR@'],
)
labrats_stamp = custom_target('labrats-stamp',
  input: [labrats],
  output: '.stamp',
  command: ['touch', '@OUTPUT@'],
)

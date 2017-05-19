labrat_files = []

if host_os == 'macos'
  labrat_files += [
    'sleeper-macos',
    'sleeper-macos32',
    'stdio-writer-macos',
    'stdio-writer-macos32',
    'simple-agent-macos.dylib',
    'resident-agent-macos.dylib',
  ]
endif

if host_os == 'ios'
  labrat_files += [
    'sleeper-ios',
    'sleeper-ios32',
    'stdio-writer-ios',
    'stdio-writer-ios32',
    'simple-agent-ios.dylib',
    'resident-agent-ios.dylib',
  ]
endif

if host_os == 'android'
  labrat_files += [
    'sleeper-android-' + host_machine.cpu_family(),
    'simple-agent-android-' + host_machine.cpu_family() + '.so',
    'resident-agent-android-' + host_machine.cpu_family() + '.so',
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

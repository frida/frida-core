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
  if host_machine.cpu_family() == 'arm'
    if host_machine.cpu().endswith('hf')
      host_arch = 'armhf'
    else
      host_arch = 'arm'
    endif
  elif host_machine.cpu_family() == 'mips'
    if host_machine.endian() == 'little'
      host_arch = 'mipsel'
    else
      host_arch = 'mips'
    endif
  else
    host_arch = host_machine.cpu_family()
  endif

  labrat_files += [
    'sleeper-linux-' + host_arch,
    'forker-linux-' + host_arch,
    'spawner-linux-' + host_arch,
    'simple-agent-linux-' + host_arch + '.so',
  ]

  if host_arch == 'x86' or host_arch == 'x86_64'
    labrat_files += [
      'resident-agent-linux-' + host_arch + '.so',
    ]
  endif
endif

if host_os == 'ios'
  labrat_files += [
    'sleeper-ios',
    'sleeper-ios32',
    'stdio-writer-ios',
    'stdio-writer-ios32',
    'forker-ios',
    'forker-ios32',
    'spawner-ios',
    'simple-agent-ios.dylib',
    'resident-agent-ios.dylib',
  ]
endif

if host_os == 'android'
  labrat_files += [
    'sleeper-android-' + host_machine.cpu_family(),
    'forker-android-' + host_machine.cpu_family(),
    'spawner-android-' + host_machine.cpu_family(),
    'simple-agent-android-' + host_machine.cpu_family() + '.so',
    'resident-agent-android-' + host_machine.cpu_family() + '.so',
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

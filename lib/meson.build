if host_os == 'android'
  subdir('selinux')
endif
subdir('base')
subdir('pipe')
subdir('payload')
if have_local_backend
  subdir('agent')
endif
if build_gadget
  subdir('gadget')
endif

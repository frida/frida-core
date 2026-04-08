if host_os == 'android'
  subdir('selinux')
endif
subdir('base')
subdir('netif')
subdir('pipe')
if have_in_tree_payloads
  subdir('payload')
  if have_local_backend
    subdir('agent')
  endif
  if build_gadget
    subdir('gadget')
  endif
endif

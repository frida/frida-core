if host_os == 'android'
  subdir('selinux')
endif
subdir('base')
subdir('netif')
subdir('pipe')
subdir('payload')
if have_local_backend and not have_shared_glib
  subdir('agent')
endif
if build_gadget and not have_shared_glib
  subdir('gadget')
endif

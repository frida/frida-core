project('frida-core', 'vala', 'c', 'cpp', version: '1.0.0')

host_os_family = ''
host_os = host_machine.system()
host_is_64bit = host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'arm64'

if not meson.is_cross_build()
  target_conditionals_prefix = '#include <TargetConditionals.h>'

  is_macos_src = target_conditionals_prefix + '''
  #if !TARGET_OS_OSX
  # error Not macOS
  #endif
  '''
  if cc.compiles(is_macos_src, name: 'compiling for macOS')
    host_os = 'macos'
  endif

  is_ios_src = target_conditionals_prefix + '''
  #if !TARGET_OS_IOS
  # error Not iOS
  #endif
  '''
  if cc.compiles(is_ios_src, name: 'compiling for iOS')
    host_os = 'ios'
  endif

  if cc.has_header('android/api-level.h')
    host_os = 'android'
  endif
endif

os_families = [
  ['windows', 'windows'],
  ['macos', 'darwin'],
  ['linux', 'linux'],
  ['ios', 'darwin'],
  ['android', 'linux'],
  ['qnx', 'qnx'],
]
foreach f : os_families
  if f.get(0) == host_os
    host_os_family = f.get(1)
  endif
endforeach

if host_os_family == ''
  error('Unsupported OS')
endif

c_languages = ['c', 'cpp']
if host_os_family == 'darwin'
  c_languages += ['objc', 'objcpp']
  add_languages('objc', 'objcpp')
endif

api_version = '1.0'

cc = meson.get_compiler('c')

cdata = configuration_data()

cdata.set('HAVE_' + host_os_family.to_upper(), 1)
if host_os != host_os_family
  cdata.set('HAVE_' + host_os.to_upper(), 1)
endif

cpu_defines = [
  ['x86', 'HAVE_I386'],
  ['x86_64', 'HAVE_I386'],
  ['arm', 'HAVE_ARM'],
  ['arm64', 'HAVE_ARM64'],
  ['mips', 'HAVE_MIPS'],
]
foreach d : cpu_defines
  if d.get(0) == host_machine.cpu_family()
    cdata.set(d.get(1), 1)
  endif
endforeach

headers = [
  'sys/user.h',
  'sys/xattr.h',
]
foreach h : headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

glibc_src = '''
#include <features.h>

#if defined (__GLIBC__) && !defined (__UCLIBC__)
#else
# error Not glibc
#endif
'''
if cc.compiles(glibc_src, name: 'compiling for glibc')
  cdata.set('HAVE_GLIBC', 1)
endif

uclibc_src = '''
#include <features.h>

#if !defined (__UCLIBC__)
# error Not uClibc
#endif
'''
if cc.compiles(uclibc_src, name: 'compiling for uClibc')
  cdata.set('HAVE_UCLIBC', 1)
endif

glib_dep = dependency('glib-2.0', version: '>=2.53')
gobject_dep = dependency('gobject-2.0')
gmodule_dep = dependency('gmodule-2.0')
gio_dep = dependency('gio-2.0')
gee_dep = dependency('gee-0.8')
json_glib_dep = dependency('json-glib-1.0')
gum_dep = dependency('frida-gum-1.0')
gumjs_dep = dependency('frida-gumjs-1.0')

if host_os_family != 'windows'
  gio_unix_dep = dependency('gio-unix-2.0')
endif

backend_libs_private = []
if host_os_family == 'darwin'
  backend_libs_private += ['-Wl,-framework,Foundation', '-lbsm']
endif
if host_os == 'macos'
  backend_libs_private += ['-Wl,-framework,AppKit']
endif
if host_os == 'ios'
  backend_libs_private += ['-Wl,-framework,CoreGraphics', '-Wl,-framework,UIKit']
endif

resource_compiler = find_program('frida-resource-compiler')

need_loader = host_os == 'android'

enable_diet_value = get_option('enable_diet')
if enable_diet_value == 'auto'
  enable_diet = host_os == 'ios'
else
  enable_diet = enable_diet_value == 'yes'
endif

enable_mapper_value = get_option('enable_mapper')
if enable_mapper_value == 'auto'
  enable_mapper = host_os_family == 'darwin'
else
  enable_mapper = enable_mapper_value == 'yes'
endif
if enable_mapper
  cdata.set('HAVE_MAPPER', 1)
endif

configure_file(input: 'config.h.in',
  output: 'config.h',
  configuration: cdata)

add_project_arguments(
  '-include', 'config.h',
  '-DG_LOG_DOMAIN="Frida"',
  language: c_languages)

vala_flags = ['--define=' + host_os_family.to_upper()]
if host_os != host_os_family
  vala_flags += ['--define=' + host_os.to_upper()]
endif
add_project_arguments(vala_flags, language: ['vala'])

subdir('tools')
subdir('lib')
subdir('src')
subdir('server')
subdir('inject')
subdir('tests')

project('frida-core', 'vala', 'c', 'cpp',
  version: '1.0.0',
  default_options: ['c_std=gnu99', 'cpp_std=c++11'],
)

api_version = '1.0'

host_os_family = host_machine.system()
host_os = host_os_family
host_is_64bit = host_machine.cpu_family().endswith('64')
if host_machine.cpu_family() == 'arm'
  host_arch = 'arm'
  if host_machine.cpu().endswith('hf')
    host_abi = 'armhf'
  else
    host_abi = 'arm'
  endif
elif host_machine.cpu_family() == 'aarch64'
  host_arch = 'arm64'
  host_abi = 'arm64'
elif host_machine.cpu_family() == 'mips'
  host_arch = 'mips'
  if host_machine.endian() == 'little'
    host_abi = 'mipsel'
  else
    host_abi = 'mips'
  endif
else
  host_arch = host_machine.cpu_family()
  host_abi = host_arch
endif

c_languages = ['c', 'cpp']
if host_os_family == 'darwin'
  c_languages += ['objc', 'objcpp']
  add_languages('objc', 'objcpp')
endif

cc = meson.get_compiler('c')

frida_component_cflags = []
buildtype = get_option('buildtype')
if buildtype == 'release' or buildtype == 'minsize'
  frida_component_cflags += [
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS',
    '-DG_DISABLE_CAST_CHECKS',
  ]
endif

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
  if d.get(0) == host_arch
    cdata.set(d.get(1), 1)
  endif
endforeach

headers = [
  'sys/user.h',
]
foreach h : headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

if cc.has_header_symbol('sys/xattr.h', 'getxattr')
  cdata.set('HAVE_SYS_XATTR_H', 1)
endif

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

enable_diet_value = get_option('enable_diet')
if enable_diet_value == 'auto'
  cpu = host_machine.cpu_family()
  is_embedded_linux = host_os == 'linux' and (cpu == 'arm' or cpu == 'aarch64' or cpu == 'mips')
  is_arm_hardfloat_linux = host_os == 'linux' and cpu == 'arm' and host_machine.cpu().endswith('hf')
  enable_diet = (is_embedded_linux and not is_arm_hardfloat_linux) or host_os == 'qnx'
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

if host_os_family == 'linux'
  add_project_arguments('-D_GNU_SOURCE=1', language: c_languages)
endif

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

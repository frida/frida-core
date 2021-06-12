project('frida-core', 'vala', 'c', 'cpp',
  version: '1.0.0',
  meson_version: '>=0.54.0',
  default_options: ['c_std=gnu99', 'cpp_std=c++11'],
)

api_version = '1.0'

host_os = host_machine.system()
if host_os == 'android'
  host_os_family = 'linux'
else
  host_os_family = host_os
endif
host_is_64bit = host_machine.cpu_family().endswith('64')
if host_machine.cpu_family() == 'arm'
  host_arch = 'arm'
  host_abi = 'arm'
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
  add_languages('objc', 'objcpp', native: false)
endif

cc = meson.get_compiler('c')

vala_flags = []

frida_component_cflags = []
ndebug = get_option('b_ndebug')
if ndebug == 'true' or (ndebug == 'if-release' and not get_option('debug'))
  frida_component_cflags += [
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS',
    '-DG_DISABLE_CAST_CHECKS',
  ]
endif

if host_arch == 'arm'
  is_hardfloat_src = '''
  #ifndef __ARM_PCS_VFP
  # error Not hardfloat
  #endif
  '''
  if cc.compiles(is_hardfloat_src, name: 'hardfloat ABI')
    host_abi = 'armhf'
  endif
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

if cc.sizeof('void *') == 8
  host_cpu_mode = '64'
else
  host_cpu_mode = '32'
endif

cdata = configuration_data()

if host_os_family == 'windows'
  shlib_suffix = '.dll'
elif host_os_family == 'darwin'
  shlib_suffix = '.dylib'
else
  shlib_suffix = '.so'
endif

helper_name = 'frida-helper'
agent_name = 'frida-agent' + shlib_suffix
gadget_name = 'frida-gadget' + shlib_suffix

if host_os_family == 'darwin'
  asset_dir = get_option('libdir') / 'frida'
  asset_path_template = get_option('prefix') / get_option('libdir') / 'frida'
else
  asset_dir = get_option('libdir') / 'frida' / host_cpu_mode
  asset_path_template = get_option('prefix') / get_option('libdir') / 'frida' / '<arch>'
endif

if get_option('assets') == 'embedded'
  vala_flags += '--define=HAVE_EMBEDDED_ASSETS'
else
  cdata.set_quoted('FRIDA_HELPER_PATH', asset_path_template / helper_name)
  cdata.set_quoted('FRIDA_AGENT_PATH', asset_path_template / agent_name)
endif

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
  'locale.h',
  'xlocale.h',
  'sys/user.h',
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

if get_option('b_sanitize') == 'address'
  cdata.set('HAVE_ASAN', 1)
endif

glib_dep = dependency('glib-2.0', version: '>=2.56')
gobject_dep = dependency('gobject-2.0')
gmodule_dep = dependency('gmodule-2.0')
gio_dep = dependency('gio-2.0')
gee_dep = dependency('gee-0.8')
json_glib_dep = dependency('json-glib-1.0')
libsoup_dep = dependency('libsoup-2.4')
gum_dep = dependency('frida-gum-1.0')
gumjs_dep = dependency('frida-gumjs-1.0')

if host_os_family != 'windows'
  gio_unix_dep = dependency('gio-unix-2.0')
endif

backend_deps_private = []
backend_libs_private = []

if host_os == 'android'
  libselinux_dep = dependency('libselinux', version: '>=3.0')
  libsepol_dep = dependency('libsepol', version: '>=3.0')
  backend_deps_private += [libselinux_dep, libsepol_dep]
endif

tls_provider_dep = dependency('gioopenssl', required: false)
if tls_provider_dep.found()
  cdata.set('HAVE_GIOOPENSSL', 1)
  vala_flags += ['--define=HAVE_GIOOPENSSL']
  backend_deps_private += tls_provider_dep
endif

nice_dep = dependency('nice', required: false)
if nice_dep.found()
  openssl_dep = dependency('openssl')
  usrsctp_dep = dependency('usrsctp')

  cdata.set('HAVE_NICE', 1)
  vala_flags += ['--define=HAVE_NICE']
  backend_deps_private += [nice_dep, openssl_dep, usrsctp_dep]
else
  openssl_dep = []
  usrsctp_dep = []
endif

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

modulate = files('tools/modulate.py')
post_process_module = files('tools/post-process-module.sh')

mapper_opt = get_option('mapper')
if mapper_opt.auto()
  have_mapper = host_os_family == 'darwin'
else
  have_mapper = mapper_opt.enabled()
endif
if have_mapper
  cdata.set('HAVE_MAPPER', 1)
endif

configure_file(input: 'config.h.in',
  output: 'config.h',
  configuration: cdata)

add_project_arguments(
  '-include', 'config.h',
  '-DG_LOG_DOMAIN="Frida"',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_56',
  '-DG_DISABLE_DEPRECATED',
  language: c_languages)

if host_os_family == 'linux'
  add_project_arguments('-D_GNU_SOURCE=1', language: c_languages)
endif

vala_flags += [
  '--vapidir=' + meson.current_source_dir() / 'vapi',
  '--pkg', 'config',
]

vala_flags += ['--define=' + host_os_family.to_upper()]
if host_os != host_os_family
  vala_flags += ['--define=' + host_os.to_upper()]
endif
vala_flags += ['--define=' + host_arch.to_upper()]
if host_abi != host_arch
  vala_flags += ['--define=' + host_abi.to_upper()]
endif
if get_option('agent_legacy') != ''
  vala_flags += ['--define=CROSS_ARCH']
endif
add_project_arguments(vala_flags, language: ['vala'])

subdir('tools')
subdir('lib')
subdir('src')
subdir('server')
subdir('portal')
subdir('web-gateway')
subdir('inject')

if get_option('tests')
  subdir('tests')
endif

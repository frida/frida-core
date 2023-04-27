project('frida-core', 'vala', 'c', 'cpp',
  version: '1.0.0',
  meson_version: '>=0.58.0',
  default_options: ['c_std=gnu99', 'cpp_std=c++11'],
)

api_version = '1.0'

header_install_dir = get_option('includedir') / 'frida-' + api_version

build_os = build_machine.system()
if build_os == 'android'
  build_os_family = 'linux'
else
  build_os_family = build_os
endif
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
elif host_machine.cpu_family() == 'mips64'
  host_arch = 'mips'
  if host_machine.endian() == 'little'
    host_abi = 'mips64el'
  else
    host_abi = 'mips64'
  endif
else
  host_arch = host_machine.cpu_family()
  host_abi = host_arch
endif
gumjs_archs = {
  'x86': 'ia32',
  'x86_64': 'x64',
}
host_arch_gumjs = gumjs_archs.get(host_arch, host_arch)

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

if host_os_family == 'darwin'
  apple_os_flavors = [
    ['macOS',   'OSX'],
    ['iOS',     'IOS'],
    ['watchOS', 'WATCH'],
    ['tvOS',    'TV'],
  ]
  foreach candidate : apple_os_flavors
    name = candidate[0]
    constant = candidate[1]
    if cc.compiles('''
                   #include <TargetConditionals.h>
                   #if !TARGET_OS_@0@
                   # error Nope
                   #endif
                   '''.format(constant),
                   name: f'compiling for @name@')
      host_os = name.to_lower()
      break
    endif
  endforeach
  if host_os == 'darwin'
    error('Unable to detect Apple OS flavor')
  endif

  have_ptrauth_src = '''
#ifdef __clang__
# if __has_feature (ptrauth_calls)
#  define HAVE_PTRAUTH 1
# endif
#endif

#ifndef HAVE_PTRAUTH
# error Pointer authentication not supported
#endif
'''
  have_ptrauth = cc.compiles(have_ptrauth_src, name: 'pointer authentication')

  if host_arch == 'arm64' and have_ptrauth
    host_abi = 'arm64e'
  endif
endif

if host_os_family == 'linux' and cc.has_header('android/api-level.h')
  host_os = 'android'
endif

if cc.sizeof('void *') == 8
  host_cpu_mode = '64'
else
  host_cpu_mode = '32'
endif

cdata = configuration_data()
if cc.get_define('FRIDA_VERSION') == ''
  version = meson.project_version()
  tokens = version.split('.')
  cdata.set_quoted('FRIDA_VERSION', version)
  cdata.set('FRIDA_MAJOR_VERSION', tokens[0].to_int())
  cdata.set('FRIDA_MINOR_VERSION', tokens[1].to_int())
  cdata.set('FRIDA_MICRO_VERSION', tokens[2].to_int())
  cdata.set('FRIDA_NANO_VERSION', 0)
endif

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
  default_asset_path_template = get_option('prefix') / get_option('libdir') / 'frida'
else
  asset_dir = get_option('libdir') / 'frida' / host_cpu_mode
  default_asset_path_template = get_option('prefix') / get_option('libdir') / 'frida' / '<arch>'
endif

asset_path_template = get_option('asset_path_template')
if asset_path_template == ''
  asset_path_template = default_asset_path_template
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

if host_os == 'linux'
  glibc_src = '''
#include <features.h>

#if defined (__GLIBC__) && !defined (__UCLIBC__)
#else
# error Not glibc
#endif
'''
  uclibc_src = '''
#include <features.h>

#if !defined (__UCLIBC__)
# error Not uClibc
#endif
'''
  if cc.compiles(glibc_src, name: 'compiling for glibc')
    cdata.set('HAVE_GLIBC', 1)
  elif cc.compiles(uclibc_src, name: 'compiling for uClibc')
    cdata.set('HAVE_UCLIBC', 1)
  else
    cdata.set('HAVE_MUSL', 1)
  endif
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
libsoup_dep = dependency('libsoup-3.0')
gum_dep = dependency('frida-gum-1.0')
gumjs_dep = dependency('frida-gumjs-1.0')
gumjs_inspector_dep = dependency('frida-gumjs-inspector-1.0')
brotlidec_dep = dependency('libbrotlidec')

have_v8 = gumjs_dep.get_variable('gumjs_v8') == 'enabled'
if have_v8
  vala_flags += ['--define=HAVE_V8']
  v8_mksnapshot = find_program('v8-mksnapshot-@0@-@1@'.format(host_os, host_abi), required: false)
  if not v8_mksnapshot.found()
    v8_mksnapshot = ''
  endif
else
  v8_mksnapshot = ''
endif

native_glib_dep = dependency('glib-2.0', version: '>=2.56', native: true)
native_gio_dep = dependency('gio-2.0', native: true)
native_gee_dep = dependency('gee-0.8', native: true)
native_brotlienc_dep = dependency('libbrotlienc', native: true)

if host_os_family != 'windows'
  gio_unix_dep = dependency('gio-unix-2.0')
endif

backend_deps_private = []
backend_libs_private = []

if host_os_family == 'linux' and cc.has_function('openpty', prefix: '#include <pty.h>')
  vala_flags += '--define=HAVE_OPENPTY'
endif

if host_os == 'android'
  libselinux_dep = dependency('libselinux', version: '>=3.0')
  libsepol_dep = dependency('libsepol', version: '>=3.0')
  backend_deps_private += [libselinux_dep, libsepol_dep]
endif

tls_provider_dep = dependency('gioopenssl', required: get_option('connectivity'))
if tls_provider_dep.found()
  cdata.set('HAVE_GIOOPENSSL', 1)
  vala_flags += ['--define=HAVE_GIOOPENSSL']
  backend_deps_private += tls_provider_dep
endif

nice_dep = dependency('nice', required: get_option('connectivity'))
if nice_dep.found()
  openssl_dep = dependency('openssl')
  usrsctp_dep = dependency('usrsctp')

  cdata.set('HAVE_NICE', 1)
  vala_flags += ['--define=HAVE_NICE']
  backend_deps_private += [nice_dep, openssl_dep, usrsctp_dep]

  if cc.has_member('struct sockaddr_conn', 'sconn_len',
                   dependencies: [usrsctp_dep],
                   prefix: '#include <usrsctp.h>')
    cdata.set('HAVE_SCONN_LEN', 1)
  endif
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

if host_os_family != 'windows'
  ar = find_program('ar')
  nm = find_program('nm')
  if host_os_family == 'darwin'
    readelf = ''
    otool = find_program('otool')
    libtool = find_program('libtool')
  else
    readelf = find_program('readelf')
    otool = ''
    libtool = ''
  endif
  strip = find_program('strip')
else
  ar = ''
  nm = ''
  readelf = ''
  otool = ''
  libtool = ''
  strip = ''
endif
if host_os_family == 'darwin'
  install_name_tool = find_program('install_name_tool')
  lipo = find_program('lipo')
  codesign = find_program('codesign')
else
  install_name_tool = ''
  lipo = ''
  codesign = ''
endif

modulate = files('tools/modulate.py')
post_process_module = [
  files('tools/post-process-module.sh'),
  host_os,
  '>>>', strip, '<<<',
  get_option('strip').to_string(),
  install_name_tool,
  codesign,
]

mapper_opt = get_option('mapper')
if mapper_opt.auto()
  have_mapper = host_os_family == 'darwin'
else
  have_mapper = mapper_opt.enabled()
endif
if have_mapper
  cdata.set('HAVE_MAPPER', 1)
endif

configure_file(
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

native_vala_flags = [
  '--vapidir=' + meson.current_source_dir() / 'vapi',
]
add_project_arguments(native_vala_flags, language: ['vala'], native: true)

subdir('tools')
subdir('lib')
subdir('src')
if host_os != 'watchos'
  subdir('server')
  subdir('portal')
  subdir('inject')

  if host_os != 'tvos'
    if get_option('tests')
      subdir('tests')
    endif
  endif
endif

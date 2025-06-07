project('frida-core', 'vala', 'c', 'cpp',
  version: run_command(find_program('python3'), files('tools' / 'detect-version.py'),
    capture: true,
    check: true).stdout().strip(),
  meson_version: '>=1.1.0',
  default_options: ['c_std=gnu99,c99', 'cpp_std=c++17'],
)

fs = import('fs')

if not meson.get_compiler('vala').version().endswith('-frida')
  error('''Incompatible Vala compiler detected.

Frida currently relies on features not yet upstream. Grab the Frida-optimized
Vala compiler from:

    https://github.com/frida/vala''')
endif

c_languages = ['c', 'cpp']
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

releng = meson.global_source_root() / 'releng'
if not fs.exists(releng)
  releng = meson.project_source_root() / 'releng'
endif

frida_version = get_option('frida_version')
if frida_version == ''
  frida_version = run_command(releng / 'frida_version.py', meson.project_source_root(), check: true).stdout().strip()
endif
tokens = frida_version.split('.')
frida_major_version = tokens[0].to_int()
frida_minor_version = tokens[1].to_int()
if tokens.length() == 4
  frida_micro_version = tokens[2].split('-')[0].to_int() - 1
  frida_nano_version = tokens[3].to_int() + 1
else
  assert(tokens.length() == 3)
  frida_micro_version = tokens[2].to_int()
  frida_nano_version = 0
endif
frida_profile = (frida_version != '0.0.0' and frida_nano_version == 0) ? 'prod' : 'dev'

api_version = '1.0'

header_install_dir = get_option('includedir') / f'frida-@api_version@'

build_os = build_machine.system()
if build_os == 'android'
  build_os_family = 'linux'
else
  build_os_family = build_os
endif
host_os_family = host_machine.system()
if host_os_family == 'android'
  host_os_family = 'linux'
endif
tokens = host_machine.subsystem().split('-')
host_os = tokens[0]
if tokens.length() == 2
  host_config = tokens[1]
elif host_os_family == 'windows'
  if cc.get_argument_syntax() == 'msvc'
    host_config = get_option('b_vscrt')
  else
    host_config = 'mingw'
  endif
else
  host_config = ''
endif
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
if cc.sizeof('void *') == 8
  host_cpu_mode = '64'
else
  host_cpu_mode = '32'
endif
host_docks_mobile_devices = host_os in ['windows', 'macos', 'linux'] and host_cpu_mode == '64'

if host_os_family == 'darwin'
  c_languages += ['objc', 'objcpp']
  add_languages('objc', 'objcpp', native: false)
endif

python = import('python').find_installation()

if cc.get_argument_syntax() == 'msvc'
  host_toolchain = 'microsoft'
  resource_blob_extension = '.obj'
else
  host_toolchain = (host_os_family == 'darwin') ? 'apple' : 'gnu'
  resource_blob_extension = '.S'
endif

vala_flags = []

frida_component_cflags = []
ndebug = get_option('b_ndebug')
optimize_for_prod = ndebug == 'true' or (ndebug == 'if-release' and not get_option('debug'))
if optimize_for_prod
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

if host_machine.endian() == 'big'
  if host_abi in ['arm', 'armhf']
    host_abi = 'armbe8'
  elif host_abi == 'arm64'
    host_abi = 'arm64be'
  endif
endif

if host_os_family == 'darwin' and host_arch == 'arm64'
  host_is_modern = host_abi == 'arm64e'
else
  host_is_modern = host_cpu_mode == '64'
endif

cdata = configuration_data()

cdata.set_quoted('FRIDA_VERSION', frida_version)
cdata.set('FRIDA_MAJOR_VERSION', frida_major_version)
cdata.set('FRIDA_MINOR_VERSION', frida_minor_version)
cdata.set('FRIDA_MICRO_VERSION', frida_micro_version)
cdata.set('FRIDA_NANO_VERSION', frida_nano_version)

escaped_prefix = get_option('prefix')
if host_os_family == 'windows'
  escaped_prefix = escaped_prefix.replace('\\', '\\\\')
endif
cdata.set_quoted('FRIDA_PREFIX', escaped_prefix)

exe_suffix = (host_os_family == 'windows') ? '.exe' : ''
if host_os_family == 'windows'
  shlib_suffix = '.dll'
elif host_os_family == 'darwin'
  shlib_suffix = '.dylib'
else
  shlib_suffix = '.so'
endif

helper_name = 'frida-helper' + exe_suffix
agent_name = 'frida-agent' + shlib_suffix
gadget_name = 'frida-gadget' + shlib_suffix

root_asset_dir = get_option('libdir') / 'frida'
if host_os_family == 'darwin'
  asset_dir = root_asset_dir
  default_asset_path_template = get_option('prefix') / get_option('libdir') / 'frida'
else
  asset_dir = root_asset_dir / host_cpu_mode
  asset_dir_modern = root_asset_dir / '64'
  asset_dir_legacy = root_asset_dir / '32'
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

gum_dep = dependency('frida-gum-1.0', default_options: [
  f'frida_version=@frida_version@',
  'gumjs=enabled',
])
gumjs_dep = dependency('frida-gumjs-1.0')
gumjs_inspector_dep = dependency('frida-gumjs-inspector-1.0')

glib_options = [
  'cocoa=disabled',
  'selinux=disabled',
  'xattr=false',
  'libmount=disabled',
  'tests=false',
  'nls=disabled',
]
if optimize_for_prod
  glib_options += [
    'glib_debug=disabled',
    'glib_assert=false',
    'glib_checks=false',
  ]
endif

gee_options = [
  'disable-introspection=true',
]
if optimize_for_prod
  gee_options += 'disable-internal-asserts=true'
endif

glib_dep = dependency('glib-2.0', version: '>=2.72', default_options: glib_options)
gobject_dep = dependency('gobject-2.0')
gmodule_dep = dependency('gmodule-2.0')
gio_dep = dependency('gio-2.0')
gee_dep = dependency('gee-0.8', default_options: gee_options)
json_glib_dep = dependency('json-glib-1.0', default_options: [
  'introspection=disabled',
  'gtk_doc=disabled',
  'tests=false',
])
libsoup_dep = dependency('libsoup-3.0', default_options: [
  'gssapi=disabled',
  'ntlm=disabled',
  'brotli=disabled',
  'tls_check=false',
  'introspection=disabled',
  'vapi=disabled',
  'docs=disabled',
  'examples=disabled',
  'tests=false',
  'sysprof=disabled',
])
brotlidec_dep = dependency('libbrotlidec')
quickjs_dep = dependency('quickjs', required: get_option('barebone_backend'), default_options: [
  'libc=false',
  'bignum=true',
  'atomics=disabled',
  'stack_check=disabled',
])

native_glib_dep = dependency('glib-2.0', version: '>=2.74', native: true, default_options: glib_options)
native_gio_dep = dependency('gio-2.0', native: true)
native_gee_dep = dependency('gee-0.8', native: true, default_options: gee_options)
native_brotlienc_dep = dependency('libbrotlienc', native: true)

if host_os_family == 'windows'
  gio_windows_dep = dependency('gio-windows-2.0')
else
  gio_unix_dep = dependency('gio-unix-2.0')
endif

if host_os == 'android'
  minizip_dep = dependency('minizip', required: false, default_options: [
    'zlib=enabled',
    'lzma=disabled',
  ])
endif

if host_toolchain == 'microsoft'
  lib = find_program('lib')
  ar = ''
  nm = ''
  ranlib = ''
  strip = ''
else
  lib = ''
  ar = find_program('ar')
  nm = find_program('nm')
  ranlib = find_program('ranlib')
  strip = find_program('strip')
endif
if host_os_family != 'windows'
  if host_os_family == 'darwin'
    readelf = ''
    otool = find_program('otool')
    libtool = find_program('libtool')
  else
    readelf = find_program('readelf')
    otool = ''
    libtool = ''
  endif
else
  readelf = ''
  otool = ''
  libtool = ''
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

have_local_backend = get_option('local_backend').allowed()
have_fruity_backend = get_option('fruity_backend') \
    .disable_auto_if(not host_docks_mobile_devices) \
    .allowed()
have_droidy_backend = get_option('droidy_backend') \
    .disable_auto_if(not host_docks_mobile_devices) \
    .allowed()
have_socket_backend = get_option('socket_backend').allowed()
have_barebone_backend = get_option('barebone_backend') \
    .disable_if(not quickjs_dep.found()) \
    .disable_auto_if(not host_docks_mobile_devices) \
    .allowed()
compiler_backend_opt = get_option('compiler_backend') \
    .disable_auto_if(host_os == 'watchos')
have_compiler_backend = false
if compiler_backend_opt.allowed()
  go = find_program('go', native: true, required: false)
  if go.found()
    message('Detecting cgo availability')
    detect_output = run_command(
      [
        python,
        files('tools' / 'cgo' / 'detect.py'),
        go,
        host_os,
        host_abi,
        cc.get_id(),
        '>>>', cc.cmd_array(), '<<<',
        '>>>', ar, '<<<',
        '>>>', nm, '<<<',
        '>>>', ranlib, '<<<',
      ],
      capture: true,
      check: true
    ).stdout()
    lines = detect_output.split('\n')
    status = lines[0]
    if status == 'ok'
      have_compiler_backend = true
      go_config = lines[1]
    else
      error_message = lines[1]
      if compiler_backend_opt.enabled()
        error(error_message)
      else
        warning(f'Building without Compiler backend: @error_message@')
      endif
    endif
  elif compiler_backend_opt.enabled()
    error('Need Go >= 1.24 to build the Compiler backend powered by ESBuild and typescript-go')
  else
    warning('Building without Compiler backend: Go >= 1.24 not found')
  endif
endif

build_gadget = get_option('gadget') \
    .disable_auto_if(meson.is_subproject()) \
    .allowed()

build_server = get_option('server') \
    .disable_if(not have_local_backend, error_message: 'frida-server requires the local backend to be included') \
    .disable_if(host_os == 'watchos', error_message: 'frida-server not yet supported on watchOS') \
    .disable_auto_if(meson.is_subproject()) \
    .allowed()

build_portal = get_option('portal') \
    .disable_if(host_os == 'watchos', error_message: 'frida-portal not yet supported on watchOS') \
    .disable_auto_if(meson.is_subproject()) \
    .allowed()

build_inject = get_option('inject') \
    .disable_if(not have_local_backend, error_message: 'frida-inject requires the local backend to be included') \
    .disable_if(host_os == 'watchos', error_message: 'frida-inject not yet supported on watchOS') \
    .disable_auto_if(meson.is_subproject()) \
    .allowed()

build_tests = get_option('tests') \
    .disable_if(host_os == 'watchos', error_message: 'tests not yet supported on watchOS') \
    .disable_auto_if(meson.is_subproject() or not meson.can_run_host_binaries()) \
    .allowed()

foreach b : [['local', have_local_backend],
             ['fruity', have_fruity_backend],
             ['droidy', have_droidy_backend],
             ['socket', have_socket_backend],
             ['barebone', have_barebone_backend],
             ['compiler', have_compiler_backend]]
  if b[1]
    vala_flags += '--define=HAVE_@0@_BACKEND'.format(b[0].to_upper())
  endif
endforeach

if host_os_family == 'darwin' or host_os == 'android' or have_barebone_backend or have_compiler_backend
  node = find_program('node', version: '>=18.0.0', native: true, required: false)
  if not node.found()
    error('Need Node.js >= 18.0.0 to process JavaScript code at build time')
  endif
  npm = find_program('npm', native: true, required: false)
  if not npm.found()
    error('Need npm to process JavaScript code at build time')
  endif
endif

gi_dep = dependency('gobject-introspection-1.0', required: false)
if gi_dep.found()
  girdir = gi_dep.get_variable('girdir')
else
  girdir = get_option('prefix') / get_option('datadir') / 'gir-1.0'
endif

vapidir = get_option('prefix') / get_option('datadir') / 'vala' / 'vapi'

gum_vala_args = [
  '--pkg=frida-gum-1.0',
  '--vapidir=' + gum_dep.get_variable('frida_vapidir'),
]
gumjs_vala_args = ['--pkg=frida-gumjs-1.0', '--pkg=gio-2.0', gum_vala_args]
gumjs_inspector_vala_args = ['--pkg=frida-gumjs-inspector-1.0', gum_vala_args]

have_v8 = gumjs_dep.get_variable('gumjs_v8') == 'enabled'
if have_v8
  vala_flags += ['--define=HAVE_V8']
endif

backend_deps_private = []
backend_reqs_private = []
backend_libs_private = []

openssl_options = [
  'cli=disabled',
]
if host_os_family == 'windows' and cc.get_argument_syntax() != 'msvc'
  openssl_options += 'asm=disabled'
endif
openssl_dep = dependency('openssl',
  required: have_fruity_backend or get_option('connectivity').enabled(),
  modules: cc.get_argument_syntax() == 'msvc' ? ['OpenSSL::SSL'] : [],
  default_options: openssl_options,
)

if have_fruity_backend
  foreach dep : ['libnghttp2', 'libngtcp2', 'libngtcp2_crypto_quictls', 'libusb-1.0']
    backend_deps_private += dependency(dep)
    backend_reqs_private += dep
  endforeach

  lwip_options = [
    'ipv4=disabled',
    'ipv6=enabled',
    'dns=disabled',
    'arp=disabled',
    'ethernet=enabled',
    'tcp_mss=4036',
    'tcp_snd_buf=65535',
    'tcp_wnd=65535',
  ]
  if optimize_for_prod
    lwip_options += 'lwip_debug=disabled'
  else
    lwip_options += 'lwip_debug=enabled'
  endif
  backend_deps_private += dependency('lwip', default_options: lwip_options)
  backend_reqs_private += 'lwip'
endif

if quickjs_dep.found()
  backend_deps_private += quickjs_dep
  backend_reqs_private += 'quickjs'
endif

if host_os_family == 'linux' and cc.has_function('openpty', prefix: '#include <pty.h>')
  vala_flags += '--define=HAVE_OPENPTY'
endif

if host_os == 'android'
  termux_elf_cleaner = find_program('termux-elf-cleaner', native: true)
  libselinux_dep = dependency('libselinux', version: '>=3.0')
  libsepol_dep = dependency('libsepol', version: '>=3.0')
  backend_deps_private += [libselinux_dep, libsepol_dep]
  backend_reqs_private += ['libselinux', 'libsepol']
else
  termux_elf_cleaner = []
endif

tls_provider_dep = dependency('gioopenssl', required: get_option('connectivity'), default_options: [
  'gnutls=disabled',
  'openssl=enabled',
  'libproxy=disabled',
  'gnome_proxy=disabled',
  'tests=false',
])
tls_provider_vala_args = []
if tls_provider_dep.found()
  tls_provider_vala_args += [
    '--pkg=gioopenssl',
    '--vapidir=' + tls_provider_dep.get_variable('vapidir'),
  ]
  cdata.set('HAVE_GIOOPENSSL', 1)
  vala_flags += ['--define=HAVE_GIOOPENSSL']
  backend_deps_private += tls_provider_dep
  backend_reqs_private += 'gioopenssl'
endif

nice_dep = dependency('nice', required: get_option('connectivity'), default_options: [
  'gupnp=disabled',
  'gstreamer=disabled',
  'crypto-library=openssl',
  'examples=disabled',
  'tests=disabled',
  'introspection=disabled',
])
if nice_dep.found()
  usrsctp_dep = dependency('usrsctp', default_options: [
    'sctp_inet=false',
    'sctp_inet6=false',
    'sctp_build_programs=false',
  ])

  cdata.set('HAVE_NICE', 1)
  vala_flags += ['--define=HAVE_NICE']
  backend_deps_private += [nice_dep, openssl_dep, usrsctp_dep]
  backend_reqs_private += ['nice', 'openssl', 'usrsctp']

  if host_os_family in ['darwin', 'freebsd', 'qnx']
    cdata.set('HAVE_SCONN_LEN', 1)
  endif
else
  usrsctp_dep = []
endif

if host_os_family == 'windows'
  backend_libs_private += ['-lsetupapi']
endif
if host_os_family == 'darwin'
  backend_libs_private += ['-Wl,-framework,Foundation', '-lbsm']
endif
if host_os == 'macos'
  backend_libs_private += ['-Wl,-framework,AppKit']
endif
if host_os in ['ios', 'tvos']
  backend_libs_private += ['-Wl,-framework,CoreGraphics', '-Wl,-framework,UIKit']
endif

if get_option('devkits').length() != 0
  if get_option('default_library') != 'static'
    error('Devkits can only be generated from static libraries')
  endif
  mkdevkit = [python, releng / 'mkdevkit.py']
  uninstalled_dir = meson.global_build_root() / 'meson-uninstalled'
  devkit_options = [
    '--cc', '>>>', cc.cmd_array(), '<<<',
    '--c-args', '>>>', get_option('c_args'), '<<<',
    '--pkg-config', '>>>', find_program('pkg-config'), '<<<',
    '--pkg-config-path', '>>>', uninstalled_dir, get_option('pkg_config_path'), '<<<',
  ]
  if host_toolchain == 'microsoft'
    static_lib_prefix = ''
    static_lib_suffix = '.lib'
    devkit_options += ['--lib', '>>>', lib, '<<<']
  else
    static_lib_prefix = 'lib'
    static_lib_suffix = '.a'
    devkit_options += [
      '--ar', '>>>', ar, '<<<',
      '--nm', '>>>', nm, '<<<',
    ]
    objcopy = find_program('objcopy', required: false)
    if objcopy.found()
      devkit_options += ['--objcopy', '>>>', objcopy, '<<<']
    endif
  endif
  if host_os_family == 'darwin'
    devkit_options += ['--libtool', '>>>', libtool, '<<<']
  endif
endif

modulate = [
  python,
  files('tools' / 'modulate.py'),
  '--endian', host_machine.endian(),
  '--nm', '>>>', nm, '<<<',
  '--readelf', '>>>', readelf, '<<<',
  '--otool', '>>>', otool, '<<<',
  '--output', '@OUTPUT@',
  '@INPUT@',
]
post_process = [
  python,
  files('tools' / 'post-process.py'),
  host_os,
  host_abi,
  '>>>', strip, '<<<',
  get_option('strip').to_string(),
  '>>>', install_name_tool, '<<<',
  '>>>', codesign, '<<<',
  '>>>', termux_elf_cleaner, '<<<',
  '@OUTPUT@',
  '@INPUT0@',
]

compile_js_agent = files('tools' / 'compile-js-agent.py')

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
  (cc.get_argument_syntax() == 'msvc') ? '/FI' : '-include', meson.current_build_dir() / 'config.h',
  '-DG_LOG_DOMAIN="Frida"',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_56',
  '-DG_DISABLE_DEPRECATED',
  language: c_languages)

# Our Vala compiler emits warnings pragmas for GCC >= 5, so for older versions we'll need to
# suppress them through GCC's command-line options. It would be better to only do this for
# Vala-generated sources, but this will have to do for now.
if cc.get_id() == 'gcc' and cc.compiles('#if __GNUC__ >= 5\n#error NOTNEEDED\n#endif')
  add_project_arguments('-w', language: 'c')
endif

vapidir = meson.current_source_dir() / 'vapi'
vala_flags += [
  '--vapidir=' + vapidir,
  '--pkg', 'config',
]

vala_flags += '--define=' + host_os_family.to_upper()
if host_os != host_os_family
  vala_flags += '--define=' + host_os.to_upper()
endif
vala_flags += '--define=' + host_arch.to_upper()
if host_abi != host_arch
  vala_flags += '--define=' + host_abi.to_upper()
endif
vala_flags += '--define=' + host_machine.endian().to_upper() + '_ENDIAN'
add_project_arguments(vala_flags, language: 'vala')
add_project_arguments('-I' + vapidir, language: 'c')

native_vala_flags = [
  '--vapidir=' + meson.current_source_dir() / 'vapi',
]
add_project_arguments(native_vala_flags, language: 'vala', native: true)
add_project_arguments('-I' + vapidir, language: 'c', native: true)

subdir('compat')
subdir('tools')
subdir('lib')
subdir('src')
if build_server
  subdir('server')
endif
if build_portal
  subdir('portal')
endif
if build_inject
  subdir('inject')
endif
if build_tests
  subdir('tests')
endif

summary(
  {
    'local': have_local_backend,
    'fruity': have_fruity_backend,
    'droidy': have_droidy_backend,
    'socket': have_socket_backend,
    'barebone': have_barebone_backend,
    'compiler': have_compiler_backend,
  },
  section: 'Backends',
  bool_yn: true,
)
summary(
  {
    'compat': compat_summary,
    'assets': get_option('assets'),
    'mapper': have_mapper,
    'connectivity': tls_provider_dep.found(),
    'gadget': build_gadget,
    'server': build_server,
    'portal': build_portal,
    'inject': build_inject,
    'tests': build_tests,
  },
  section: 'Features',
  bool_yn: true,
)

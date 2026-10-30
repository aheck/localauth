project('localauth', 'cpp',
  meson_version: '>=1.1.0',
  default_options: ['cpp_std=c++20', 'warning_level=2'])

cpp = meson.get_compiler('cpp')
platform = host_machine.system()
if platform not in ['linux', 'darwin', 'windows']
  error('LocalAuth supports Linux, macOS and Windows only')
endif

platform_deps = [dependency('threads')]
if platform == 'windows'
  platform_deps += [cpp.find_library('bcrypt'), cpp.find_library('advapi32')]
endif

localauth_dep = declare_dependency(
  include_directories: include_directories('include'),
  dependencies: platform_deps)
meson.override_dependency('localauth', localauth_dep)

if get_option('tests')
  tests = executable('localauth-tests', 'test.cpp', dependencies: localauth_dep)
  test('crypto', tests, args: ['crypto'])
  test('authentication', tests, args: ['authentication'])
  test('hardening', tests, args: ['hardening'])
  test('lifecycle', tests, args: ['lifecycle'])
  test('cross-account', tests, args: ['cross-account'])
endif

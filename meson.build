project('SoB', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++23'])

subdir('source')

json_dep = dependency('nlohmann_json')
openssl_dep = dependency('openssl')
libsecp256k1_dep = dependency('libsecp256k1')

executable('SoB',
           main_source,
          dependencies : [json_dep, openssl_dep, libsecp256k1_dep])

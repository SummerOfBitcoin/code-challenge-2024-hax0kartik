project('SoB', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=gnu++23'])

add_global_arguments('-fexperimental-library', '-stdlib=libc++', language: 'cpp')
add_global_link_arguments('-stdlib=libc++', language: 'cpp')

subdir('source')

json_dep = dependency('nlohmann_json')
libsecp256k1_dep = dependency('libsecp256k1')

executable('SoB',
           main_source,
          dependencies : [json_dep, libsecp256k1_dep])

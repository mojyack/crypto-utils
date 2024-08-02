project('crypto-utils', 'cpp', version: '1.0.0', default_options : ['warning_level=3', 'werror=false', 'cpp_std=c++20'])

subdir('src')

example_files = files(
  'src/main.cpp',
  'src/aes.cpp',
  'src/base64.cpp',
  'src/hmac.cpp',
  'src/random.cpp',
  'src/sha.cpp',
)

executable('example', example_files,
  dependencies : crypto_util_libs
)

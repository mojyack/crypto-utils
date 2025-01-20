project('crypto-utils', 'cpp', version: '1.0.0', default_options : ['warning_level=3', 'werror=false', 'cpp_std=c++23'])

subdir('src')

example_files = files(
  'src/main.cpp',
  'src/cipher.cpp',
  'src/aes.cpp',
  'src/c20p1305.cpp',
  'src/base64.cpp',
  'src/hmac.cpp',
  'src/sha.cpp',
)

executable('example', example_files,
  dependencies : crypto_utils_deps,
)

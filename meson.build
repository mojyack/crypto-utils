project('crypto-utils', 'cpp', version: '1.0.0', default_options : ['warning_level=3', 'werror=false', 'cpp_std=c++23'])

subdir('src')

executable('example',
  files(
    'src/aes.cpp',
    'src/base64.cpp',
    'src/c20p1305.cpp',
    'src/cipher.cpp',
    'src/hmac.cpp',
    'src/main.cpp',
    'src/sha.cpp',
    'src/x25519.cpp',
  ),
  dependencies : crypto_utils_deps,
)

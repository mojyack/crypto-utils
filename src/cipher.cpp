#include <openssl/evp.h>

#include "cipher.hpp"

namespace crypto {
auto alloc_cipher_context() -> CipherContext* {
    return EVP_CIPHER_CTX_new();
}

auto free_cipher_context(CipherContext* const context) -> void {
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)context);
}
} // namespace crypto

#include <openssl/evp.h>

#include "aes.hpp"
#include "macros/unwrap.hpp"

namespace crypto::aes {
namespace {
auto is_valid_key(const BytesRef key) -> bool {
    return key.size() == 128 / 8 || key.size() == 192 / 8 || key.size() == 256 / 8;
}

auto cipher_suite_from_key_size(const size_t size) -> const EVP_CIPHER* {
    switch(size) {
    case 128 / 8:
        return EVP_aes_128_cbc();
    case 192 / 8:
        return EVP_aes_192_cbc();
    case 256 / 8:
        return EVP_aes_256_cbc();
    default:
        return nullptr;
    }
}
} // namespace

auto encrypt(CipherContext* const context, const BytesRef key, const BytesRef iv, const BytesRef data, const BytesRef dest) -> bool {
    ensure(is_valid_key(key));

    const auto ctx = (EVP_CIPHER_CTX*)context;
    unwrap(suite, cipher_suite_from_key_size(key.size()));
    ensure(EVP_EncryptInit(ctx, &suite, (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    auto len = 0;
    ensure(EVP_EncryptUpdate(ctx, (unsigned char*)dest.data(), &len, (unsigned char*)data.data(), data.size()) != 0);
    ensure(EVP_EncryptFinal(ctx, (unsigned char*)dest.data() + len, &len) != 0);
    return true;
}

auto encrypt(CipherContext* const context, const BytesRef key, const BytesRef iv, const BytesRef data) -> std::optional<BytesArray> {
    auto ret = BytesArray(calc_encryption_buffer_size(data.size()));
    ensure(encrypt(context, key, iv, data, ret));
    return ret;
}

auto decrypt(CipherContext* const context, const BytesRef key, const BytesRef iv, const BytesRef data, const BytesRef dest) -> std::optional<size_t> {
    ensure(is_valid_key(key));

    const auto ctx = (EVP_CIPHER_CTX*)context;
    unwrap(suite, cipher_suite_from_key_size(key.size()));
    ensure(EVP_DecryptInit(ctx, &suite, (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    auto body_len   = 0;
    auto remain_len = 0;
    ensure(EVP_DecryptUpdate(ctx, (unsigned char*)dest.data(), &body_len, (unsigned char*)data.data(), data.size()) != 0);
    ensure(EVP_DecryptFinal(ctx, (unsigned char*)dest.data() + body_len, &remain_len) != 0);
    return body_len + remain_len;
}

auto decrypt(CipherContext* const context, const BytesRef key, const BytesRef iv, const BytesRef data) -> std::optional<BytesArray> {
    auto ret = BytesArray(calc_decryption_buffer_size(data.size()));
    unwrap(size, decrypt(context, key, iv, data, ret));
    ret.resize(size);
    return ret;
}
} // namespace crypto::aes

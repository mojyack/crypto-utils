#include <openssl/evp.h>

#include <limits>

#include "c20p1305.hpp"
#include "macros/assert.hpp"

namespace crypto::c20p1305 {
namespace {
auto update_aad(EVP_CIPHER_CTX* const ctx, const bool encrypting, const BytesSpan aad) -> bool {
    ensure(aad.size() <= std::numeric_limits<int>::max());
    auto len = 0;
    ensure((encrypting ? EVP_EncryptUpdate : EVP_DecryptUpdate)(ctx, nullptr, &len, (const unsigned char*)aad.data(), aad.size()) != 0);
    return true;
}
} // namespace

auto encrypt(CipherContext* const context, const BytesRef<key_len> key, const BytesRef<iv_len> iv, const BytesSpan aad, const BytesSpan data, const BytesMutSpan dest) -> bool {
    ensure(data.size() <= std::numeric_limits<int>::max());
    ensure(dest.size() == calc_encryption_buffer_size(data.size()));

    const auto ctx = (EVP_CIPHER_CTX*)context;
    ensure(EVP_EncryptInit(ctx, EVP_chacha20_poly1305(), (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);
    ensure(aad.empty() || update_aad(ctx, true, aad));

    const auto tag_head = (unsigned char*)dest.data();
    const auto enc_head = (unsigned char*)dest.data() + tag_len;

    auto body_len   = 0;
    auto remain_len = 0;
    if(!data.empty()) {
        ensure(EVP_EncryptUpdate(ctx, enc_head, &body_len, (unsigned char*)data.data(), int(data.size())) != 0);
    }
    ensure(EVP_EncryptFinal(ctx, enc_head + body_len, &remain_len) != 0);
    ensure(body_len + remain_len == int(data.size()));
    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag_head) != 0);
    return true;
}

auto encrypt(CipherContext* const context, const BytesRef<key_len> key, const BytesRef<iv_len> iv, const BytesSpan aad, const BytesSpan data) -> std::optional<BytesVec> {
    auto ret = BytesVec(calc_encryption_buffer_size(data.size()));
    ensure(encrypt(context, key, iv, aad, data, ret));
    return ret;
}

auto decrypt(CipherContext* const context, const BytesRef<key_len> key, const BytesRef<iv_len> iv, const BytesSpan aad, const BytesSpan data, const BytesMutSpan dest) -> bool {
    ensure(data.size() >= tag_len);
    ensure(data.size() - tag_len <= std::numeric_limits<int>::max());
    ensure(dest.size() == calc_decryption_buffer_size(data.size()));

    const auto ctx = (EVP_CIPHER_CTX*)context;
    ensure(EVP_DecryptInit(ctx, EVP_chacha20_poly1305(), (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);
    ensure(aad.empty() || update_aad(ctx, false, aad));

    const auto tag_head = (unsigned char*)data.data();
    const auto enc_head = (unsigned char*)data.data() + tag_len;
    const auto enc_len  = data.size() - tag_len;

    auto          body_len   = 0;
    auto          remain_len = 0;
    unsigned char final_byte = 0;
    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag_head) != 0);
    if(enc_len != 0) {
        ensure(EVP_DecryptUpdate(ctx, (unsigned char*)dest.data(), &body_len, enc_head, int(enc_len)) != 0);
    }
    auto final_head = dest.empty() ? &final_byte : (unsigned char*)dest.data() + body_len;
    ensure(EVP_DecryptFinal(ctx, final_head, &remain_len) != 0);
    ensure(size_t(body_len + remain_len) == dest.size());
    return true;
}

auto decrypt(CipherContext* const context, const BytesRef<key_len> key, const BytesRef<iv_len> iv, const BytesSpan aad, const BytesSpan data) -> std::optional<BytesVec> {
    if(data.size() < tag_len) {
        return std::nullopt;
    }
    auto ret = BytesVec(calc_decryption_buffer_size(data.size()));
    ensure(decrypt(context, key, iv, aad, data, ret));
    return ret;
}
} // namespace crypto::c20p1305

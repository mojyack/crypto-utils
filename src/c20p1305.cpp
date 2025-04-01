#include <openssl/evp.h>

#include "c20p1305.hpp"
#include "macros/assert.hpp"

namespace crypto::c20p1305 {
auto encrypt(CipherContext* context, const BytesRef key, const BytesRef iv, const BytesRef data) -> std::optional<BytesArray> {
    const auto ctx = (EVP_CIPHER_CTX*)context;
    ensure(EVP_EncryptInit(ctx, EVP_chacha20_poly1305(), (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    auto       ret      = BytesArray(data.size() + tag_len);
    const auto tag_head = (unsigned char*)ret.data();
    const auto enc_head = (unsigned char*)ret.data() + +tag_len;

    auto body_len   = 0;
    auto remain_len = 0;
    ensure(EVP_EncryptUpdate(ctx, enc_head, &body_len, (unsigned char*)data.data(), data.size()) != 0);
    ensure(EVP_EncryptFinal(ctx, enc_head + body_len, &remain_len) != 0);
    ensure(body_len + remain_len == int(data.size()));
    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag_head) != 0);
    return ret;
}

auto decrypt(CipherContext* context, const BytesRef key, const BytesRef iv, const BytesRef data) -> std::optional<BytesArray> {
    ensure(data.size() > tag_len);

    const auto ctx = (EVP_CIPHER_CTX*)context;
    ensure(EVP_DecryptInit(ctx, EVP_chacha20_poly1305(), (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    const auto tag_head = (unsigned char*)data.data();
    const auto enc_head = (unsigned char*)data.data() + tag_len;
    const auto enc_len  = data.size() - tag_len;

    auto ret        = BytesArray(data.size() - tag_len);
    auto body_len   = 0;
    auto remain_len = 0;
    ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag_head) != 0);
    ensure(EVP_DecryptUpdate(ctx, (unsigned char*)ret.data(), &body_len, enc_head, enc_len) != 0);
    ensure(EVP_DecryptFinal(ctx, (unsigned char*)ret.data() + body_len, &remain_len) != 0);
    ret.resize(body_len + remain_len);
    return ret;
}
} // namespace crypto::c20p1305

#include <openssl/evp.h>

#include "c20p1305.hpp"
#include "macros/assert.hpp"

namespace crypto::c20p1305 {
constexpr auto poly1305_tag_len = 16;

auto encrypt(CipherContext* const context, const Key& key, const IV& iv, const std::span<const std::byte> data) -> std::optional<std::vector<std::byte>> {
    const auto ctx = (EVP_CIPHER_CTX*)context;
    assert_o(EVP_EncryptInit(ctx, EVP_chacha20_poly1305(), (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    auto       ret      = std::vector<std::byte>(data.size() + poly1305_tag_len);
    const auto tag_head = (unsigned char*)ret.data();
    const auto enc_head = (unsigned char*)ret.data() + +poly1305_tag_len;

    auto body_len   = 0;
    auto remain_len = 0;
    assert_o(EVP_EncryptUpdate(ctx, enc_head, &body_len, (unsigned char*)data.data(), data.size()) != 0);
    assert_o(EVP_EncryptFinal(ctx, enc_head + body_len, &remain_len) != 0);
    assert_o(body_len + remain_len == int(data.size()));
    assert_o(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, poly1305_tag_len, tag_head) != 0);
    return ret;
}

auto decrypt(CipherContext* const context, const Key& key, const IV& iv, const std::span<const std::byte> data) -> std::optional<std::vector<std::byte>> {
    assert_o(data.size() > poly1305_tag_len);

    const auto ctx = (EVP_CIPHER_CTX*)context;
    assert_o(EVP_DecryptInit(ctx, EVP_chacha20_poly1305(), (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    const auto tag_head = (unsigned char*)data.data();
    const auto enc_head = (unsigned char*)data.data() + poly1305_tag_len;
    const auto enc_len  = data.size() - poly1305_tag_len;

    auto ret        = std::vector<std::byte>(data.size() - poly1305_tag_len);
    auto body_len   = 0;
    auto remain_len = 0;
    assert_o(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, poly1305_tag_len, tag_head) != 0);
    assert_o(EVP_DecryptUpdate(ctx, (unsigned char*)ret.data(), &body_len, enc_head, enc_len) != 0);
    assert_o(EVP_DecryptFinal(ctx, (unsigned char*)ret.data() + body_len, &remain_len) != 0);
    ret.resize(body_len + remain_len);
    return ret;
}
} // namespace crypto::c20p1305

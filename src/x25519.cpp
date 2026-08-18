#include <functional>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "macros/autoptr.hpp"
#include "macros/unwrap.hpp"
#include "x25519.hpp"

namespace crypto::x25519 {
namespace {
declare_autoptr(PKeyContext, EVP_PKEY_CTX, EVP_PKEY_CTX_free);
declare_autoptr(BigNum, BIGNUM, BN_free);
declare_autoptr(PKey, EVP_PKEY, EVP_PKEY_free);

template <size_t N>
auto read_array(std::function<int(unsigned char*, size_t*)> func) -> std::optional<BytesArray<N>> {
    auto len = 0uz;
    ensure(func(NULL, &len));
    ensure(len == N);
    auto ret = BytesArray<N>();
    ensure(func((unsigned char*)ret.data(), &len));
    return ret;
}
} // namespace

auto generate() -> std::optional<KeyPair> {
    auto ctx = AutoPKeyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL));
    ensure(ctx.get() != NULL);
    ensure(EVP_PKEY_keygen_init(ctx.get()) > 0);

    auto pkey = AutoPKey();
    ensure(EVP_PKEY_keygen(ctx.get(), std::inout_ptr(pkey)) > 0);
    unwrap_mut(raw_priv, read_array<key_len>(std::bind(EVP_PKEY_get_raw_private_key, pkey.get(), std::placeholders::_1, std::placeholders::_2)));
    unwrap_mut(raw_pub, read_array<key_len>(std::bind(EVP_PKEY_get_raw_public_key, pkey.get(), std::placeholders::_1, std::placeholders::_2)));
    return KeyPair{std::move(raw_priv), std::move(raw_pub)};
}

auto derive_secret(const BytesRef<key_len> raw_priv, const BytesRef<key_len> raw_pub) -> std::optional<BytesArray<key_len>> {
    auto priv = AutoPKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, (unsigned char*)raw_priv.data(), raw_priv.size()));
    ensure(priv.get() != NULL);
    auto pub = AutoPKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, (unsigned char*)raw_pub.data(), raw_pub.size()));
    ensure(pub.get() != NULL);

    auto ctx = AutoPKeyContext(EVP_PKEY_CTX_new(priv.get(), NULL));
    ensure(ctx.get() != NULL);

    ensure(EVP_PKEY_derive_init(ctx.get()) > 0);
    ensure(EVP_PKEY_derive_set_peer(ctx.get(), pub.get()));
    unwrap_mut(ret, read_array<key_len>(std::bind(EVP_PKEY_derive, ctx.get(), std::placeholders::_1, std::placeholders::_2)));
    return ret;
}
} // namespace crypto::x25519

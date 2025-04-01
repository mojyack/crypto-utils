#include "aes.hpp"
#include "base64.hpp"
#include "c20p1305.hpp"
#include "hmac.hpp"
#include "macros/unwrap.hpp"
#include "sha.hpp"
#include "util/random.hpp"
#include "util/span.hpp"
#include "x25519.hpp"

namespace {
template <class T, class U>
auto operator==(const std::span<T> a, const std::span<U> b) -> bool {
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}

auto print_bytes(const crypto::BytesRef data) -> void {
    for(auto b : data) {
        std::print("{:X}", int(b));
    }
    std::println();
}

auto engine = RandomEngine();

auto aes_test(const crypto::BytesRef data) -> bool {
    auto ctx = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    for(const auto key_len : {16, 24, 32}) {
        std::println("key size {}", key_len);
        const auto key = engine.generate(key_len);
        const auto iv  = engine.generate<crypto::aes::iv_len>();
        unwrap(enc, crypto::aes::encrypt(ctx.get(), key, iv, data));
        unwrap(dec, crypto::aes::decrypt(ctx.get(), key, iv, enc));
        ensure(data == std::span(dec));
    }
    return true;
}

auto chacha20_poly1305_test(const crypto::BytesRef data) -> bool {
    auto       ctx = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    const auto iv  = engine.generate<crypto::c20p1305::iv_len>();
    const auto key = engine.generate<crypto::c20p1305::key_len>();
    unwrap(enc, crypto::c20p1305::encrypt(ctx.get(), key, iv, data));
    unwrap(dec, crypto::c20p1305::decrypt(ctx.get(), key, iv, enc));
    ensure(data == std::span(dec));
    return true;
}

auto base64_test(const crypto::BytesRef data) -> bool {
    const auto enc = crypto::base64::encode(data);
    const auto dec = crypto::base64::decode(enc);
    ensure(data == std::span(dec));
    return true;
}

auto hmac_test(const crypto::BytesRef data) -> bool {
    const auto key = to_span("crypto_utils_private_key");

    unwrap(hash, crypto::hmac::compute_hmac_sha256(key, data));
    std::print("hmac: ");
    print_bytes(hash);

    return true;
}

auto sha_test(const crypto::BytesRef data) -> bool {
    unwrap(sha1, crypto::sha::calc_sha1(data));
    std::print("sha1: ");
    print_bytes(sha1);

    unwrap(sha256, crypto::sha::calc_sha256(data));
    std::print("sha256: ");
    print_bytes(sha256);
    return true;
}

auto x25519_test() -> bool {
    unwrap(pair1, crypto::x25519::generate());
    std::println("1");
    std::println("private: {}", crypto::base64::encode(pair1.priv));
    std::println("public : {}", crypto::base64::encode(pair1.pub));
    unwrap(pair2, crypto::x25519::generate());
    std::println("2");
    std::println("private: {}", crypto::base64::encode(pair2.priv));
    std::println("public : {}", crypto::base64::encode(pair2.pub));

    unwrap(sec1, crypto::x25519::derive_secret(pair1.priv, pair2.pub));
    unwrap(sec2, crypto::x25519::derive_secret(pair2.priv, pair1.pub));
    std::println("result1: {}", crypto::base64::encode(sec1));
    std::println("result2: {}", crypto::base64::encode(sec2));

    ensure(sec1 == sec2);

    return true;
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    ensure(argc == 2, "usage: example DATA");

    const auto data = to_span(argv[1]);

    std::println("aes");
    ensure(aes_test(data));
    std::println("ok");

    std::println("chacha20_poly1305");
    ensure(chacha20_poly1305_test(data));
    std::println("ok");

    std::println("base64");
    ensure(base64_test(data));
    std::println("ok");

    std::println("hmac");
    ensure(hmac_test(data));
    std::println("ok");

    std::println("sha");
    ensure(sha_test(data));
    std::println("ok");

    std::println("x25519");
    ensure(x25519_test());
    std::println("ok");

    return 0;
}

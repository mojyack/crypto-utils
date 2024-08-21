#include "aes.hpp"
#include "base64.hpp"
#include "c20p1305.hpp"
#include "hmac.hpp"
#include "macros/unwrap.hpp"
#include "sha.hpp"
#include "util/random.hpp"
#include "util/span.hpp"

namespace {
template <class T, class U>
auto operator==(const std::span<T> a, const std::span<U> b) -> bool {
    if(a.size() != b.size()) {
        return false;
    }
    for(auto i = 0u; i < a.size(); i += 1) {
        if(a[i] != b[i]) {
            return i;
        }
    }
    return true;
}

auto print_bytes(const crypto::BytesRef data) -> void {
    for(auto b : data) {
        printf("%02X", int(b));
    }
    printf("\n");
}

auto engine = RandomEngine();

auto aes_test(const crypto::BytesRef data) -> bool {
    auto ctx = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    for(const auto key_len : {16, 24, 32}) {
        print("key size ", key_len);
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
    printf("hmac: ");
    print_bytes(hash);

    return true;
}

auto sha_test(const crypto::BytesRef data) -> bool {
    const auto sha1 = crypto::sha::calc_sha1(data);
    printf("sha1: ");
    print_bytes(sha1);

    const auto sha256 = crypto::sha::calc_sha256(data);
    printf("sha256: ");
    print_bytes(sha256);
    return true;
}

auto run(const char* const arg) -> bool {
    const auto data = to_span(arg);

    print("aes");
    ensure(aes_test(data));
    print("ok");

    print("chacha20_poly1305");
    ensure(chacha20_poly1305_test(data));
    print("ok");

    print("base64");
    ensure(base64_test(data));
    print("ok");

    print("base64");
    ensure(base64_test(data));
    print("ok");

    print("hmac");
    ensure(hmac_test(data));
    print("ok");

    print("sha");
    ensure(sha_test(data));
    print("ok");

    // aes test
    return true;
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    if(argc != 2) {
        print("usage: example DATA");
        return 1;
    }
    return run(argv[1]) ? 0 : 1;
}

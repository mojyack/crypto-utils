#include "aes.hpp"
#include "base64.hpp"
#include "c20p1305.hpp"
#include "hmac.hpp"
#include "macros/unwrap.hpp"
#include "random.hpp"
#include "sha.hpp"
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

auto print_bytes(const std::span<const std::byte> data) -> void {
    for(auto b : data) {
        printf("%02X", int(b));
    }
    printf("\n");
}

auto aes_test(const std::span<const std::byte> data) -> bool {
    auto ctx = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    auto iv  = crypto::aes::IV();
    auto key = std::array<std::byte, crypto::aes::block_size>();
    crypto::random::fill_by_random(iv);
    crypto::random::fill_by_random(key);
    unwrap_ob(enc, crypto::aes::encrypt(ctx.get(), key, iv, data));
    unwrap_ob(dec, crypto::aes::decrypt(ctx.get(), key, iv, enc));
    assert_b(data == std::span(dec));
    return true;
}

auto chacha20_poly1305_test(const std::span<const std::byte> data) -> bool {
    auto ctx = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    auto iv  = crypto::c20p1305::IV();
    auto key = crypto::c20p1305::Key();
    crypto::random::fill_by_random(iv);
    crypto::random::fill_by_random(key);
    unwrap_ob(enc, crypto::c20p1305::encrypt(ctx.get(), key, iv, data));
    unwrap_ob(dec, crypto::c20p1305::decrypt(ctx.get(), key, iv, enc));
    assert_b(data == std::span(dec));
    return true;
}

auto base64_test(const std::span<const std::byte> data) -> bool {
    const auto enc = crypto::base64::encode(data);
    const auto dec = crypto::base64::decode(enc);
    assert_b(data == std::span(dec));
    return true;
}

auto hmac_test(const std::span<const std::byte> data) -> bool {
    const auto key = to_span("crypto_utils_private_key");

    unwrap_ob(hash, crypto::hmac::compute_hmac_sha256(key, data));
    printf("hmac: ");
    print_bytes(hash);

    return true;
}

auto sha_test(const std::span<const std::byte> data) -> bool {
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
    assert_b(aes_test(data));
    print("ok");

    print("chacha20_poly1305");
    assert_b(chacha20_poly1305_test(data));
    print("ok");

    print("base64");
    assert_b(base64_test(data));
    print("ok");

    print("base64");
    assert_b(base64_test(data));
    print("ok");

    print("hmac");
    assert_b(hmac_test(data));
    print("ok");

    print("sha");
    assert_b(sha_test(data));
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

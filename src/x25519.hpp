#pragma once
#include <optional>

#include "util/bytes.hpp"

namespace crypto::x25519 {
constexpr auto key_len = 32;

struct KeyPair {
    BytesArray<key_len> priv;
    BytesArray<key_len> pub;
};

auto generate() -> std::optional<KeyPair>;
auto derive_secret(BytesRef<key_len> raw_priv, BytesRef<key_len> raw_pub) -> std::optional<BytesArray<key_len>>;
} // namespace crypto::x25519

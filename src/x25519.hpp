#pragma once
#include <optional>

#include "bytes.hpp"

namespace crypto::x25519 {
struct KeyPair {
    BytesArray priv;
    BytesArray pub;
};

auto generate() -> std::optional<KeyPair>;
auto derive_secret(BytesRef raw_priv, BytesRef raw_pub) -> std::optional<BytesArray>;
} // namespace crypto::x25519

#pragma once
#include <optional>

#include "bytes.hpp"
#include "util/prependable-buffer.hpp"

namespace crypto::x25519 {
struct KeyPair {
    PrependableBuffer priv;
    PrependableBuffer pub;
};

auto generate() -> std::optional<KeyPair>;
auto derive_secret(BytesRef raw_priv, BytesRef raw_pub) -> std::optional<PrependableBuffer>;
} // namespace crypto::x25519

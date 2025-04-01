#pragma once
#include <optional>

#include "bytes.hpp"
#include "cipher.hpp"

namespace crypto::c20p1305 {
constexpr auto iv_len  = 16;
constexpr auto key_len = 32;
constexpr auto tag_len = 16;

auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
} // namespace crypto::c20p1305

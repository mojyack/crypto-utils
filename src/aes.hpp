#pragma once
#include <optional>

#include "bytes.hpp"
#include "cipher.hpp"

namespace crypto::aes {
constexpr auto iv_len    = 16;
constexpr auto block_len = 16;

auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
} // namespace crypto::aes

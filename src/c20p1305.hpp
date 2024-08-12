#pragma once
#include <optional>
#include <vector>

#include "bytes.hpp"
#include "cipher.hpp"

namespace crypto::c20p1305 {
constexpr auto iv_len  = 16;
constexpr auto key_len = 32;

auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<std::vector<std::byte>>;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<std::vector<std::byte>>;
} // namespace crypto::c20p1305

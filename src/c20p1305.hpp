#pragma once
#include <array>
#include <optional>
#include <span>
#include <vector>

#include "cipher.hpp"

namespace crypto::c20p1305 {
using IV  = std::array<std::byte, 16>;
using Key = std::array<std::byte, 32>;

auto encrypt(CipherContext* context, const Key& key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>>;
auto decrypt(CipherContext* context, const Key& key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>>;
} // namespace crypto::c20p1305

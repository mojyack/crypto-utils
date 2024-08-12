#pragma once
#include <array>
#include <optional>
#include <span>
#include <vector>

#include "cipher.hpp"

namespace crypto::aes {
constexpr auto block_size = 128 / 8;

using IV = std::array<std::byte, block_size>;

auto encrypt(CipherContext* context, std::span<const std::byte> key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>>;
auto decrypt(CipherContext* context, std::span<const std::byte> key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>>;
} // namespace crypto::aes

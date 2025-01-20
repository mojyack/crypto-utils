#pragma once
#include <array>
#include <optional>

#include "bytes.hpp"

namespace crypto::sha {
auto calc_sha1(BytesRef data) -> std::optional<std::array<std::byte, 20>>;
auto calc_sha256(BytesRef data) -> std::optional<std::array<std::byte, 32>>;
} // namespace crypto::sha

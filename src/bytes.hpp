#pragma once
#include <span>
#include <vector>

namespace crypto {
using BytesArray  = std::vector<std::byte>;
using BytesRef    = std::span<const std::byte>;
using MutBytesRef = std::span<std::byte>;
} // namespace crypto

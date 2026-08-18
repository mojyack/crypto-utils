#pragma once
#include <optional>

#include "util/bytes.hpp"

namespace crypto::sha {
auto calc_sha1(BytesSpan data) -> std::optional<BytesArray<20>>;
auto calc_sha256(BytesSpan data) -> std::optional<BytesArray<32>>;
} // namespace crypto::sha

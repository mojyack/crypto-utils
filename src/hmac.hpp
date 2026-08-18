#include <array>
#include <optional>

#include "util/bytes.hpp"

namespace crypto::hmac {
auto compute_hmac_sha256(BytesSpan key, BytesSpan data) -> std::optional<std::array<std::byte, 32>>;
}

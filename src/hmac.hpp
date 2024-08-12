#include <array>
#include <optional>

#include "bytes.hpp"

namespace crypto::hmac {
auto compute_hmac_sha256(BytesRef key, BytesRef data) -> std::optional<std::array<std::byte, 32>>;
}

#include <array>
#include <optional>
#include <span>

namespace crypto::hmac {
auto compute_hmac_sha256(std::span<const std::byte> key, std::span<const std::byte> data) -> std::optional<std::array<std::byte, 32>>;
}

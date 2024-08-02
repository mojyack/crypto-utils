#include <span>
#include <string_view>
#include <vector>

namespace crypto::base64 {
auto encode(const std::span<const std::byte> bytes) -> std::string;
auto decode(const std::string_view str) -> std::vector<std::byte>;
} // namespace base64

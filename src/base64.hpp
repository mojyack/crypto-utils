#include <string_view>
#include <vector>

#include "bytes.hpp"

namespace crypto::base64 {
auto encode(BytesRef bytes) -> std::string;
auto decode(const std::string_view str) -> std::vector<std::byte>;
} // namespace crypto::base64

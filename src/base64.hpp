#include <string_view>

#include "bytes.hpp"

namespace crypto::base64 {
auto encode(BytesRef bytes) -> std::string;
auto decode(const std::string_view str) -> BytesArray;
} // namespace crypto::base64

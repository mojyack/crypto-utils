#include <optional>
#include <string_view>

#include "bytes.hpp"

namespace crypto::base64 {
inline auto calc_decode_buffer_size(size_t str_len) -> std::optional<size_t> {
    if(str_len * 3 % 4 != 0) {
        return std::nullopt;
    } else {
        // maximum possible size, see decode() result for actual size
        return str_len * 3 / 4;
    }
}

auto encode(BytesRef bytes) -> std::string;
auto decode(const std::string_view str, MutBytesRef dest) -> std::optional<size_t>;
auto decode(const std::string_view str) -> std::optional<BytesArray>;
} // namespace crypto::base64

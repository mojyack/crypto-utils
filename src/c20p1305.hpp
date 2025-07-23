#pragma once
#include <optional>

#include "bytes.hpp"
#include "cipher.hpp"

namespace crypto::c20p1305 {
constexpr auto iv_len  = 16;
constexpr auto key_len = 32;
constexpr auto tag_len = 16;

inline auto calc_encryption_buffer_size(size_t data_size) -> size_t {
    return data_size + tag_len;
}

inline auto calc_decryption_buffer_size(size_t data_size) -> size_t {
    return data_size - tag_len;
}

auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data, BytesRef dest) -> bool;
auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data, BytesRef dest) -> bool;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
} // namespace crypto::c20p1305

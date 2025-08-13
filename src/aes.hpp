#pragma once
#include <optional>

#include "bytes.hpp"
#include "cipher.hpp"

namespace crypto::aes {
constexpr auto iv_len    = 16;
constexpr auto block_len = 16;

inline auto calc_encryption_buffer_size(size_t data_size) -> size_t {
    // padding required(even if data_size % block_size == 0)
    return (data_size / block_len + 1) * block_len;
}

inline auto calc_decryption_buffer_size(size_t data_size) -> size_t {
    // maximum possible size, see decrypt() result for actual size
    return data_size;
}

auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data, MutBytesRef dest) -> bool;
auto encrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data, MutBytesRef dest) -> std::optional<size_t>;
auto decrypt(CipherContext* context, BytesRef key, BytesRef iv, BytesRef data) -> std::optional<BytesArray>;
} // namespace crypto::aes

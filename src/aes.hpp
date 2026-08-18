#pragma once
#include <optional>

#include "cipher.hpp"
#include "util/bytes.hpp"

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

auto encrypt(CipherContext* context, BytesSpan key, BytesRef<iv_len> iv, BytesSpan data, BytesMutSpan dest) -> bool;
auto encrypt(CipherContext* context, BytesSpan key, BytesRef<iv_len> iv, BytesSpan data) -> std::optional<BytesVec>;
auto decrypt(CipherContext* context, BytesSpan key, BytesRef<iv_len> iv, BytesSpan data, BytesMutSpan dest) -> std::optional<size_t>;
auto decrypt(CipherContext* context, BytesSpan key, BytesRef<iv_len> iv, BytesSpan data) -> std::optional<BytesVec>;
} // namespace crypto::aes

#pragma once
#include <optional>

#include "cipher.hpp"
#include "util/bytes.hpp"

namespace crypto::c20p1305 {
constexpr auto iv_len  = 16;
constexpr auto key_len = 32;
constexpr auto tag_len = 16;

inline auto calc_encryption_buffer_size(const size_t data_size) -> size_t {
    return data_size + tag_len;
}

inline auto calc_decryption_buffer_size(const size_t data_size) -> size_t {
    return data_size - tag_len;
}

auto encrypt(CipherContext* context, BytesRef<key_len> key, BytesRef<iv_len> iv, BytesSpan aad, BytesSpan data, BytesMutSpan dest) -> bool;
auto encrypt(CipherContext* context, BytesRef<key_len> key, BytesRef<iv_len> iv, BytesSpan aad, BytesSpan data) -> std::optional<BytesVec>;
auto decrypt(CipherContext* context, BytesRef<key_len> key, BytesRef<iv_len> iv, BytesSpan aad, BytesSpan data, BytesMutSpan dest) -> bool;
auto decrypt(CipherContext* context, BytesRef<key_len> key, BytesRef<iv_len> iv, BytesSpan aad, BytesSpan data) -> std::optional<BytesVec>;
} // namespace crypto::c20p1305

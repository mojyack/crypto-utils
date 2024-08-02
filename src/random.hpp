#pragma once
#include <span>

namespace crypto::random {
auto fill_by_random(std::span<std::byte> data) -> void;
}

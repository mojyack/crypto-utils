#include <random>

#include "random.hpp"

namespace {
auto engine = std::mt19937((std::random_device())());
}

namespace crypto::random {
auto fill_by_random(std::span<std::byte> data) -> void {
    auto engine = std::mt19937((std::random_device())());
    for(auto& b : data) {
        b = std::byte(engine());
    }
}
} // namespace crypto::random

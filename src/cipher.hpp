#pragma once
#include "macros/autoptr.hpp"

namespace crypto {
using CipherContext = void;

auto alloc_cipher_context() -> CipherContext*;
auto free_cipher_context(CipherContext* context) -> void;

declare_autoptr(CipherContext, CipherContext, free_cipher_context);
} // namespace crypto
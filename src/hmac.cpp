#include <openssl/err.h>
#include <openssl/hmac.h>

#include "hmac.hpp"

#define CUTIL_NS
#include "macros/assert.hpp"
#include "macros/autoptr.hpp"

namespace crypto::hmac {
namespace {
declare_autoptr(MDContext, EVP_MD_CTX, EVP_MD_CTX_free);
declare_autoptr(PKey, EVP_PKEY, EVP_PKEY_free);
} // namespace

auto compute_hmac_sha256(const std::span<const std::byte> key, const std::span<const std::byte> data) -> std::optional<std::vector<std::byte>> {
    auto mdctx = AutoMDContext(EVP_MD_CTX_new());
    assert_o(mdctx.get() != NULL);
    auto md = EVP_get_digestbyname("SHA256");
    assert_o(md != NULL);
    auto pkey = AutoPKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, (unsigned char*)key.data(), key.size()));
    assert_o(pkey.get() != NULL);

    auto buf     = std::vector<std::byte>(EVP_MAX_MD_SIZE);
    auto buf_len = size_t(EVP_MAX_MD_SIZE);
    assert_o(EVP_DigestSignInit(mdctx.get(), NULL, md, NULL, pkey.get()) == 1);
    assert_o(EVP_DigestSignUpdate(mdctx.get(), data.data(), data.size()) == 1);
    assert_o(EVP_DigestSignFinal(mdctx.get(), (unsigned char*)buf.data(), &buf_len) == 1);
    buf.resize(buf_len);

    return buf;
}
} // namespace crypto::hmac

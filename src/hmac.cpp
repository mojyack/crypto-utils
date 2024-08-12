#include <openssl/err.h>
#include <openssl/hmac.h>

#include "hmac.hpp"
#include "macros/assert.hpp"
#include "macros/autoptr.hpp"

namespace crypto::hmac {
namespace {
declare_autoptr(MDContext, EVP_MD_CTX, EVP_MD_CTX_free);
declare_autoptr(PKey, EVP_PKEY, EVP_PKEY_free);
} // namespace

auto compute_hmac_sha256(const BytesRef key, const BytesRef data) -> std::optional<std::array<std::byte, 32>> {
    auto mdctx = AutoMDContext(EVP_MD_CTX_new());
    assert_o(mdctx.get() != NULL);
    auto md = EVP_get_digestbyname("SHA256");
    assert_o(md != NULL);
    auto pkey = AutoPKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, (unsigned char*)key.data(), key.size()));
    assert_o(pkey.get() != NULL);

    auto buf     = std::array<std::byte, 32>();
    auto buf_len = buf.size();
    assert_o(EVP_DigestSignInit(mdctx.get(), NULL, md, NULL, pkey.get()) == 1);
    assert_o(EVP_DigestSignUpdate(mdctx.get(), data.data(), data.size()) == 1);
    assert_o(EVP_DigestSignFinal(mdctx.get(), (unsigned char*)buf.data(), &buf_len) == 1);

    return buf;
}
} // namespace crypto::hmac

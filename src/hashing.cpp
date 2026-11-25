#include "hashing.h"

#include <iostream>

#include <openssl/rand.h>

// sha512 ...
#include <openssl/err.h>
#include <openssl/evp.h>

// argon2
#include <openssl/core_names.h>     /* OSSL_KDF_*           */
#include <openssl/params.h>         /* OSSL_PARAM_*         */
#include <openssl/thread.h>         /* OSSL_set_max_threads */
#include <openssl/kdf.h>            /* EVP_KDF_*            */

namespace hashing {

    static bool
    hash(const std::string_view &text,
         const std::span<uint8_t, SALT_SIZE> *salt,
         std::span<uint8_t, SHA512_SIZE> &out_hash,
         const EVP_MD *hash_func) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            std::cerr << "[ERROR] " << ERR_get_error();
            return false;
        }

        if (   !EVP_DigestInit_ex(ctx, hash_func, nullptr)
            || (salt ? !EVP_DigestUpdate(ctx, salt->data(), salt->size()) : 0)
            || !EVP_DigestUpdate(ctx, text.data(), text.size())
            || !EVP_DigestFinal_ex(ctx, out_hash.data(), nullptr)
        ) {
            std::cerr << "[ERROR] " << ERR_get_error();
            EVP_MD_CTX_free(ctx);
            return false;
        }

        EVP_MD_CTX_free(ctx);
        return true;
    }

    bool
    gen_salt(const std::span<uint8_t, SALT_SIZE> out_salt) {
        int res = RAND_bytes(out_salt.data(), hashing::SALT_SIZE);
        if (res != 1) std::cerr << ERR_get_error() << std::endl;
        return res == 1;
    }

    bool
    sha512(const std::string_view text,
           std::span<uint8_t, SALT_SIZE> salt,
           std::span<uint8_t, SHA512_SIZE> out_hash) {
        return hash(text, &salt, out_hash, EVP_sha512());
    }

    bool
    sha512(const std::string_view text,
           std::span<uint8_t, SHA512_SIZE> out_hash) {
        return hash(text, nullptr, out_hash, EVP_sha512());
    }

    /**
    https://www.rfc-editor.org/info/rfc9106/
    * 1.   If a uniformly safe option that is not tailored to your
        application or hardware is acceptable, select Argon2id with t=1
        iteration, p=4 lanes, m=2^(21) (2 GiB of RAM), 128-bit salt, and
        256-bit tag size.  This is the FIRST RECOMMENDED option.

    Argon2id
    t=1 iteration
    p=4 lanes (threads)
    m=2^(21) (2 GiB of RAM)
    128-bit salt
    256-bit tag size

     * @param text
     * @param salt
     * @param out_hash
     */
    bool
    argon2id(const std::string_view text,
             const std::span<uint8_t, SALT_SIZE> salt,
             std::span<uint8_t, ARGON2ID_SIZE> out_hash) {
        int retval = false;

        EVP_KDF *kdf = nullptr;
        EVP_KDF_CTX *ctx = nullptr;
        OSSL_PARAM params[7];

        const char *type    = "ARGON2ID";
        uint32_t iterations = 1;
        uint32_t lanes      = 4;
        uint32_t threads    = 4;
        uint32_t memcost    = 1<<21;

        if (OSSL_set_max_threads(nullptr, threads) != 1) goto fail;
        params[0] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS,        &threads);
        params[1] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,   &lanes);
        params[2] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,     salt.data(), SALT_SIZE);
        params[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)text.data(),text.size());
        params[5] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,           &iterations);
        params[6] = OSSL_PARAM_construct_end();

        if (!((kdf = EVP_KDF_fetch(nullptr, type, nullptr)))) goto fail;
        if (!((ctx = EVP_KDF_CTX_new(kdf)))) goto fail;

        if (EVP_KDF_derive(ctx, out_hash.data(), out_hash.size(), params) != 1) goto fail;
        retval = true;

        fail:
        if (retval == false) std::cerr << "[ERROR]" << ERR_get_error() << std::endl;
        EVP_KDF_free(kdf);
        EVP_KDF_CTX_free(ctx);
        OSSL_set_max_threads(nullptr, 0);

        return retval;
    }
}

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "lib_standard_app/crypto_helpers.h"

WARN_UNUSED_RESULT cx_err_t bip32_derive_with_seed_schnorr_sign_hash_256(unsigned int derivation_mode,
                                                                       cx_curve_t   curve,
                                                                       const uint32_t *path,
                                                                       size_t          path_len,
                                                                       uint32_t        sign_mode,
                                                                       cx_md_t         hashID,
                                                                       const uint8_t  *hash,
                                                                       size_t          hash_len,
                                                                       uint8_t        *sig,
                                                                       size_t         *sig_len,
                                                                       unsigned char  *seed,
                                                                       size_t          seed_len)
{
    cx_err_t                  error = CX_OK;
    cx_ecfp_256_private_key_t privkey;
    size_t                    buf_len = *sig_len;

    // Derive private key according to BIP32 path
    CX_CHECK(bip32_derive_with_seed_init_privkey_256(
        derivation_mode, curve, path, path_len, &privkey, NULL, seed, seed_len));

    CX_CHECK(
        cx_ecschnorr_sign_no_throw(&privkey, sign_mode, hashID, hash, hash_len, sig, sig_len));

end:
    explicit_bzero(&privkey, sizeof(privkey));

    if (error != CX_OK) {
        // Make sure the caller doesn't use uninitialized data in case
        // the return code is not checked.
        explicit_bzero(sig, buf_len);
    }
    if(error == CX_EC_INVALID_CURVE) {
        PRINTF("Invalid Curve\n");
    }
    if(error == CX_INTERNAL_ERROR) {
        PRINTF("Internal Error\n");
    }
    if(error == CX_OVERFLOW) {
        PRINTF("Internal OVERFLOW\n");
    }
    if(error == CX_INVALID_PARAMETER){
        PRINTF("INVALID PARAMETER\n");
    }
    if(error != CX_OK) {
        PRINTF("Error Other: %u\n", error);
    }
    return error;
}
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os.h"
#include "cx.h"

/**
 * @brief   Sign a hash with ecdsa using the device seed derived from the specified bip32 path and
 * seed key.
 *
 * @param[in]  derivation_mode Derivation mode, one of HDW_NORMAL / HDW_ED25519_SLIP10 / HDW_SLIP21.
 *
 * @param[in]  curve           Curve identifier.
 *
 * @param[in]  path            Bip32 path to use for derivation.
 *
 * @param[in]  path_len        Bip32 path length.
 *
 * @param[in]  hashID          Message digest algorithm identifier.
 *
 * @param[in]  hash            Digest of the message to be signed.
 *                             The length of *hash* must be shorter than the group order size.
 *                             Otherwise it is truncated.
 *
 * @param[in]  hash_len        Length of the digest in octets.
 *
 * @param[out] sig             Buffer where to store the signature.
 *                             The signature is encoded in TLV:  **30 || L || 02 || Lr || r || 02 ||
 * Ls || s**
 *
 * @param[in]  sig_len         Length of the signature buffer, updated with signature length.
 *
 * @param[out] info            Set with CX_ECCINFO_PARITY_ODD if the y-coordinate is odd when
 * computing **[k].G**.
 *
 * @param[in]  seed            Seed key to use for derivation.
 *
 * @param[in]  seed_len        Seed key length.
 *
 * @return                     Error code:
 *                             - CX_OK on success
 *                             - CX_EC_INVALID_CURVE
 *                             - CX_INTERNAL_ERROR
 */
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
                                                                       size_t          seed_len);
/**
 * @brief   Sign a hash with ecdsa using the device seed derived from the specified bip32 path.
 *
 * @param[in]  derivation_mode Derivation mode, one of HDW_NORMAL / HDW_ED25519_SLIP10 / HDW_SLIP21.
 *
 * @param[in]  curve           Curve identifier.
 *
 * @param[in]  path            Bip32 path to use for derivation.
 *
 * @param[in]  path_len        Bip32 path length.
 *
 * @param[in]  hashID          Message digest algorithm identifier.
 *
 * @param[in]  hash            Digest of the message to be signed.
 *                             The length of *hash* must be shorter than the group order size.
 *                             Otherwise it is truncated.
 *
 * @param[in]  hash_len        Length of the digest in octets.
 *
 * @param[out] sig             Buffer where to store the signature.
 *                             The signature is encoded in TLV:  **30 || L || 02 || Lr || r || 02 ||
 * Ls || s**
 *
 * @param[in]  sig_len         Length of the signature buffer, updated with signature length.
 *
 * @param[out] info            Set with CX_ECCINFO_PARITY_ODD if the y-coordinate is odd when
 * computing **[k].G**.
 *
 * @return                     Error code:
 *                             - CX_OK on success
 *                             - CX_EC_INVALID_CURVE
 *                             - CX_INTERNAL_ERROR
 */
WARN_UNUSED_RESULT static inline cx_err_t bip32_derive_schnorr_sign_hash_256(cx_curve_t      curve,
                                                                           const uint32_t *path,
                                                                           size_t          path_len,
                                                                           uint32_t       sign_mode,
                                                                           cx_md_t        hashID,
                                                                           const uint8_t *hash,
                                                                           size_t         hash_len,
                                                                           uint8_t       *sig,
                                                                           size_t        *sig_len)
{
    return bip32_derive_with_seed_schnorr_sign_hash_256(HDW_NORMAL,
                                                      curve,
                                                      path,
                                                      path_len,
                                                      sign_mode,
                                                      hashID,
                                                      hash,
                                                      hash_len,
                                                      sig,
                                                      sig_len,
                                                      NULL,
                                                      0);
}
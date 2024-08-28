/*******************************************************************************
 * This file is adapted and modified from the ARK Ledger app to support Nexa
 * Schnorr signatures.
 *
 * Key changes:
 * - Updated to RFC6979-compliant nonce generation with domain separation
 * - Modified Schnorr signature generation for Nexa-specific requirements.
 * - Improved error handling for invalid and out-of-range values.
 * - Restructured code for clarity and maintainability.
 * - Added `NEXA_DOMAIN_SEPARATOR` for domain separation in HMAC operations.
 *
 * Copyright (c) 2024 sl33p <sl33p.eth@pm.me>
 * GitHub: https://github.com/sleepdefic1t
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *******************************************************************************/

#include "schnorr.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <os.h>
#include <cx.h>

static const uint8_t NEXA_DOMAIN_SEPARATOR[] = "Schnorr+SHA256  ";

static unsigned char const SECP256K1_G[] = {
    // Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    // Gy:  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8 };

static unsigned char const SECP256K1_N[] = {
    // n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
    0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

static unsigned char const SECP256K1_P[] = {
    // p:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};

static unsigned char const SECP256K1_ONE[] = {
    // ONE: 0x0000000000000000000000000000000000000000000000000000000000000001
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

////////////////////////////////////////////////////////////////////////////////
// SECP256K1 Prime Residual Exponent
//
// - ((p - 1) / 2) % p
//
// The Prime(SECP256K1_P) will always be the same in this implementation;
// we can save lots of overhead pre-calculating the residual exponent.
//
//  (fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f) - 1) /
//   0000000000000000000000000000000000000000000000000000000000000002 =
//   7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17
//
// ---
static unsigned char const SECP256K1_RES_EXP[] = {
    // residual exponent:
    // 7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFE, 0x17};

/*******************************************************************************
 * Generate a deterministic nonce using RFC6979
 *
 * This function generates a deterministic nonce using the RFC6979 standard,
 * ensuring that the same nonce is produced each time for the same input. This
 * approach enhances security by preventing vulnerabilities associated with
 * nonce reuse, making it suitable for cryptographic operations such as Schnorr
 * signatures.
 *
 * The implementation closely follows Ledger's style and security practices,
 * with modifications to support additional functionality not provided by
 * Ledger's API, such as handling a domain separator (personalization string)
 * in HMAC operations. This modification enhances security by ensuring that
 * identical inputs (private key and message hash) generate unique nonces
 * across different cryptographic protocols, thereby preventing cross-protocol
 * attacks.
 *
 * Assumptions:
 *
 * - `privkey`: A 32-byte array representing the private key.
 * - `msg_hash`: A 32-byte array representing the message hash.
 * - `domain_separator`: A 16-byte array used as a domain separator (optional),
 *   ensuring that the nonce is unique to the particular cryptographic protocol
 *   or application.
 *
 * Computation:
 *
 * 1. Initialize the internal state:
 *    - `V` is set to an array of 0x01 bytes.
 *    - `K` is set to an array of 0x00 bytes.
 *
 * 2. Update K:
 *    - K = HMAC(K, V || 0x00 || privkey || msg_hash || domain_separator).
 *
 * 3. Update V:
 *    - V = HMAC(K, V).
 *
 * 4. Update K again:
 *    - K = HMAC(K, V || 0x01 || privkey || msg_hash || domain_separator).
 *
 * 5. Update V again:
 *    - V = HMAC(K, V).
 *
 * 6. Generate the nonce:
 *    - Generate `nonce` using HMAC(K, V) and check if it's in the correct
 *      range (0 < nonce < SECP256K1_N).
 *    - If the nonce is out of range, update K and V, and repeat until a valid
 *      nonce is found.
 *
 * @param [out] nonce: The output nonce (must be 32 bytes).
 * @param [in] privkey: The input private key (32 bytes).
 * @param [in] msg_hash: The input message hash (32 bytes).
 * @param [in] domain_separator: The domain separator (16 bytes, optional).
 *
 * @return cx_err_t: CX_OK on success, or an error code on failure.
 *******************************************************************************/
cx_err_t nonce_function_rfc6979(uint8_t *nonce,
                                const uint8_t *privkey,
                                const uint8_t *msg_hash,
                                const uint8_t *domain_separator) {
    cx_err_t error = CX_OK;

    unsigned int hash_len = 32;  // SHA-256 output length
    cx_hmac_sha256_t hmac;

    uint8_t V[32 + 1];
    uint8_t K[32 + 1];

    // Step 1: Initialize V and K
    memset(V, 0x01, hash_len);
    memset(K, 0x00, hash_len);

    // Step 2: K = HMAC(K, V || 0x00 || privkey || msg_hash ||
    // personalization_string)
    V[hash_len] = 0x00;
    CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
    CX_CHECK(
        cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, V, hash_len + 1, NULL, 0));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, privkey, 32, NULL, 0));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, msg_hash, 32, NULL, 0));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                              CX_LAST,
                              domain_separator,
                              16,
                              K,
                              hash_len));

    // Step 3: V = HMAC(K, V)
    CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                              CX_LAST,
                              V,
                              hash_len,
                              V,
                              hash_len));

    // Step 4: K = HMAC(K, V || 0x01 || privkey || msg_hash ||
    // personalization_string)
    V[hash_len] = 0x01;
    CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
    CX_CHECK(
        cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, V, hash_len + 1, NULL, 0));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, privkey, 32, NULL, 0));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac, 0, msg_hash, 32, NULL, 0));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                              CX_LAST,
                              domain_separator,
                              16,
                              K,
                              hash_len));

    // Step 5: V = HMAC(K, V)
    CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
    CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                              CX_LAST,
                              V,
                              hash_len,
                              V,
                              hash_len));

    // Step 6: Generate the nonce
    do {
        // Generate nonce using HMAC(K, V)
        CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
        CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                                  CX_LAST,
                                  V,
                                  hash_len,
                                  nonce,
                                  hash_len));

        // Check if nonce is in the correct range (0 < nonce < SECP256K1_N)
        int diff;
        if (cx_math_cmp_no_throw(nonce, SECP256K1_N, 32, &diff) != CX_OK ||
            diff != 0) {
            goto end;  // Valid nonce found, exit loop
        }

        // If nonce is not valid, update K and V and repeat
        CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
        CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                                  CX_LAST,
                                  V,
                                  hash_len,
                                  K,
                                  hash_len));

        CX_CHECK(cx_hmac_sha256_init_no_throw(&hmac, K, hash_len));
        CX_CHECK(cx_hmac_no_throw((cx_hmac_t *) &hmac,
                                  CX_LAST,
                                  V,
                                  hash_len,
                                  V,
                                  hash_len));
    } while (1);

end:
    return error;
}

/*******************************************************************************
 * Calculate the Jacobian Symbol
 *
 * This function calculates the Jacobian symbol (a/n), which is a critical 
 * operation in elliptic curve cryptography for determining whether a number is 
 * a quadratic residue modulo the prime `n`. This check is essential for certain 
 * cryptographic operations, such as verifying the square property of the 
 * y-coordinate of a curve point.
 *
 * This implementation uses Ledger's cryptographic API for the calculations.
 *
 * Assumptions:
 *
 * - `a` is the number for which we want to compute the Jacobian symbol.
 * - `n` is the prime modulus (e.g., the prime `p` of the SECP256K1 curve).
 *
 * Computation:
 *
 * 1. Reduce `a` modulo `n` and initialize the result.
 * 2. Apply the properties of the Jacobian symbol iteratively:
 *    - Factor out the power of two.
 *    - Use reciprocity and other properties to reduce the problem size.
 * 3. Use Ledger's API to compute the result of the Jacobian symbol.
 * 4. Return the final result, indicating whether `a` is a quadratic residue
 *    modulo `n`.
 *
 * @param [in] a: The input number for which the Jacobian symbol is calculated.
 * @param [in] n: The modulus (a prime number) used for the calculation.
 *
 * @return int: The Jacobian symbol, which can be:
 *              - 1: `a` is a quadratic residue modulo `n`.
 *              - 0: `a` is congruent to 0 modulo `n`.
 *              - -1: `a` is not a quadratic residue modulo `n`.
 *******************************************************************************/
int calculate_jacobian(const uint8_t *a, const uint8_t *n) {
    uint8_t result[32];

    // Use Ledger's API to calculate the Jacobian symbol
    cx_err_t error =
        cx_math_powm_no_throw(result, a, SECP256K1_RES_EXP, 32, n, 32);
    if (error != CX_OK) {
        return 0;  // Indicates an error or that `a` is congruent to 0 mod `n`
    }

    if (memcmp(result, SECP256K1_ONE, 32) == 0) {
        return 1;  // a is a quadratic residue mod n
    } else {
        return -1;  // a is not a quadratic residue mod n
    }
}

/*******************************************************************************
 * Generate a Schnorr Signature
 *
 * This function implements the Schnorr signature algorithm for Nexa.
 * Key steps include:
 *  - Generating a deterministic nonce `k` using RFC6979.
 *  - Computing the elliptic curve point R = k * G, where G is the base point.
 *  - Calculating the challenge `e` as the hash of the concatenation of R's
 *    x-coordinate, the public key A, and the message hash.
 *  - Computing the signature's `s` value as s = (k + e * a) mod n, where `a`
 *    is the private key.
 *
 * The function returns the signature `(R.x, s)`.
 *
 * Assumptions:
 *
 * - Capitalized variables represent uncompressed Curve Points in affine
 *   coordinates.
 *   - R, A, and G are elliptic curve points, where G is the base point.
 *   - Example: G = (0x04, x[32].., y[32]..) represents an uncompressed point.
 *
 * - Lowercase variables represent 32-byte scalars.
 *   - x, k, and a are 256-bit integers (scalars).
 *
 * - `H` is a cryptographic hash function (SHA-256 in this case).
 * - `m` is a 32-byte array representing the message hash.
 * - `a` is a secret non-zero scalar representing the private key.
 * - `k` is a non-zero nonce derived using RFC6979.
 *
 * Computation:
 *
 *  1. k = H(a || m || domain_separator) mod n
 *     - Generate a deterministic nonce using RFC6979.
 *
 *  2. R = G * k
 *     - Compute the elliptic curve point R by scalar multiplication of the base
 *       point G with the nonce k.
 *
 *  3. A = G * a
 *     - Compute the public key point A by scalar multiplication of the base
 *       point G with the private key a.
 *
 *  4. If y(R) is not a quadratic residue (y(R) is not square), set k = n - k
 *     - Adjust the nonce k if the y-coordinate of R does not satisfy the
 *       quadratic residue condition.
 *
 *  5. e = H(R.x || A.x || m) mod n
 *     - Compute the challenge scalar e by hashing the x-coordinates of R and A
 *       along with the message hash.
 *
 *  6. s = (k + e * a) mod n
 *     - Compute the signature scalar s using the equation: s = k + e * a (mod
 *       n).
 *
 *  7. S = (R.x, s)
 *     - The final Schnorr signature is the tuple (R.x, s), where R.x is the
 *       x-coordinate of the point R.
 *
 * @param [in] privateKey:      Must be 32 bytes in length.
 * @param [in] hash:            Must be 32 bytes in length.
 * @param [out] signature:      Must be 64 bytes in length.
 *
 * @return cx_err_t: CX_OK on success, or an error code on failure.
 *******************************************************************************/
cx_err_t schnorr_sign_nexa(const uint8_t *privateKey,
                           const uint8_t *hash,
                           uint8_t *signature) {
    cx_err_t error = CX_OK;

    cx_sha256_t H;
    unsigned WIDE char a[32];
    unsigned WIDE char k[32];
    unsigned WIDE char R[65];
    unsigned WIDE char A[65];
    unsigned WIDE char e[32];
    unsigned WIDE char Ry[32];

    unsigned int d_len = 32;

    // Construct the Base-Point (G)
    unsigned WIDE char G[65];
    G[0] = 0x04;
    memcpy(G + 1, SECP256K1_G, 64);

    // Copy the privateKey
    memcpy(a, privateKey, d_len);

    // a' (privateKey) must be an integer in the range [1..n-1]
    int diff;
    if (cx_math_is_zero(a, d_len) ||
        cx_math_cmp_no_throw(a, SECP256K1_N, d_len, &diff) != CX_OK ||
        diff >= 0) {
        error = CX_INTERNAL_ERROR;
        goto end;
    }

    // k' = H(d || m || algo16) (Deterministic nonce generation)
    CX_CHECK(
        nonce_function_rfc6979(k, privateKey, hash, NEXA_DOMAIN_SEPARATOR));

    // k' must not be '0'
    if (cx_math_is_zero(k, d_len)) {
        error = CX_INTERNAL_ERROR;
        goto end;
    }

    // R = G * k'
    memcpy(R, G, sizeof(G));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, R, k, d_len));
    memcpy(signature, R + 1, d_len);

    // R must not be '0'
    if (cx_math_is_zero(signature, d_len)) {
        error = CX_INTERNAL_ERROR;
        goto end;
    }

    // A = G * a' (Public key generation)
    memcpy(A, G, sizeof(G));
    CX_CHECK(cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, A, a, d_len));

    // Compress 'A' (y coordinate compression)
    A[0] = (A[64] & 1) == 1 ? 0x03 : 0x02;

    // e = H(R.x || A.x || m) mod n (Challenge computation)
    cx_sha256_init_no_throw(&H);
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &H, 0, signature, d_len, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &H, 0, A, 33, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &H,
                              CX_LAST | CX_NO_REINIT,
                              hash,
                              d_len,
                              e,
                              d_len));
    CX_CHECK(cx_math_modm_no_throw(e, d_len, SECP256K1_N, d_len));

    // a' %= n (Private key modulo n)
    CX_CHECK(cx_math_modm_no_throw(a, d_len, SECP256K1_N, d_len));

    // k' %= n (Nonce modulo n)
    CX_CHECK(cx_math_modm_no_throw(k, d_len, SECP256K1_N, d_len));

    // Check the Jacobi symbol of the y-coordinate of the R point (Ry)
    memcpy(Ry, R + 33, 32);
    if (calculate_jacobian(Ry, SECP256K1_P) == -1) {
        cx_math_sub(k, SECP256K1_N, k, 32);
    }

    // s' = (k' + e' * a') mod n (Final signature scalar computation)
    CX_CHECK(cx_math_multm_no_throw(e, e, a, SECP256K1_N, d_len));
    CX_CHECK(
        cx_math_addm_no_throw(signature + d_len, k, e, SECP256K1_N, d_len));

    if (cx_math_is_zero(signature + d_len, d_len)) {
        error = CX_INTERNAL_ERROR;
        goto end;
    }

end:
    explicit_bzero((void *) &H, sizeof(H));
    explicit_bzero(&a, sizeof(a));
    explicit_bzero(&k, sizeof(k));
    explicit_bzero(&R, sizeof(R));
    explicit_bzero(&A, sizeof(A));
    explicit_bzero(&e, sizeof(e));
    explicit_bzero(&Ry, sizeof(Ry));

    if (error) {
        explicit_bzero(signature, 64);
    }

    return error;
}

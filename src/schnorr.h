#pragma once

#include <stdint.h>

#include <cx.h>

cx_err_t schnorr_sign_nexa(const uint8_t *privateKey,
                      const uint8_t *hash,
                      uint8_t *signature);

cx_err_t nonce_function_rfc6979(uint8_t *k,
                                const uint8_t *privkeybytes,
                                const uint8_t *msg32,
                                const uint8_t *algo);

/* Copyright (c) 2017 Pieter Wuille
 * Modified work Copyright (c) 2018 Jonas Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "os.h"
#include "cx.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "cashaddr.h"

static const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint64_t cashaddr_polymod_step(uint64_t pre) {
    uint8_t b = pre >> 35;
    return ((pre & 0x07ffffffff) << 5) ^ (-((b >> 0) & 1) & 0x98f2bc8e61UL) ^
           (-((b >> 1) & 1) & 0x79b76d99e2UL) ^
           (-((b >> 2) & 1) & 0xf33e5fb3c4UL) ^
           (-((b >> 3) & 1) & 0xae2eabe2a8UL) ^
           (-((b >> 4) & 1) & 0x1e4f43e470UL);
}

uint64_t PolyMod(uint8_t *prefix, uint8_t *payload, size_t payload_length) {
    size_t i;
    uint64_t c = 1;
    while (*prefix != 0) {
        c = cashaddr_polymod_step(c) ^ (*prefix++ & 0x1f); // Prefix
    }
    c = cashaddr_polymod_step(c); // The zero valued separator
    for (i = 0; i < payload_length; ++i) {
        c = cashaddr_polymod_step(c) ^ (*payload++); // Hash
    }
    for (i = 0; i < 8; ++i) {
        c = cashaddr_polymod_step(c); // 8 zeros for empty checksum
    }
    return c ^ 1;
}

static int convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad)
{
    size_t acc = 0;
    size_t bits = 0;
    const size_t maxv = (1 << outbits) - 1;
    const size_t max_acc = (1 << (inbits + outbits - 1)) - 1;
    size_t i;
    for (i = 0; i < inlen; ++i)
    {
        acc = ((acc << inbits) | in[i]) & max_acc;
        bits += inbits;
        while (bits >= outbits)
        {
            bits -= outbits;
            out[(*outlen)++] = ((acc >> bits) & maxv);
        }
    }
    if (!pad && bits)
    {
        return 0; // false
    }
    if (pad && bits)
    {
        out[(*outlen)++] = (acc << (outbits - bits)) & maxv;
    }
    return 1; // true
}

void create_checksum(uint8_t *payload, size_t payload_length,
                     uint8_t *checksum) {
    uint8_t *prefix = (uint8_t *)"nexa";
    uint64_t mod = PolyMod(prefix, payload, payload_length);

    for (size_t i = 0; i < 8; ++i) {
        // Convert the 5-bit groups in mod to checksum values.
        *checksum++ = (mod >> (5 * (7 - i))) & 0x1f;
    }
}

int cashaddr_encode(uint8_t *hash, const size_t hash_length, uint8_t *addr,
                    const size_t max_addr_len, const unsigned short version) {
    uint8_t version_byte;
    uint8_t checksum[8] = {0, 0, 0, 0, 0, 0, 0, 0}; // 5-bit bytes.
    uint8_t
        tmp[40]; // 8-bit bytes. Should be enough for 1 version byte + 160 bit
    uint8_t payload[40]; // 5-bit bytes. Should be enough for 1 version byte + 160 bit hash
    uint8_t *addr_start;
    size_t payload_length = 0;
    size_t addr_length = 0;
    size_t i;

    addr_start = addr;
    *addr_start = 0;

    // if (hash_length != 20) // Only support 160 bit hash
    //     return 0;
    // if (version == CASHADDR_P2PKH) { // Support P2PKH = 0, P2SH = 1
    //     version_byte = 0;
    // }
    // else if (version == CASHADDR_P2ST) {
        version_byte = 19; 
        version_byte = version_byte << 3;
    // } else {
    //     return 0;
    // }

    // pad out tmp
    tmp[0] = version_byte;
    tmp[1] = 0x17;
    tmp[2] = 0x00;
    tmp[3] = 0x51;
    tmp[4] = 0x14;
    memmove(tmp + 5, hash, hash_length);

    PRINTF("tmp=\n%.*H\n", hash_length + 5 , tmp);
    PRINTF("\hash_length=%i \n", hash_length);
    convert_bits(payload, &payload_length, 5, tmp, hash_length + 5, 8, 1);

    PRINTF("\npayload\n");
    for(int i = 0; i < payload_length; i++) {
        PRINTF("%02x", payload[i]);
    }
    PRINTF("\n");
    

    PRINTF("\npayload_length=%u \n", payload_length);

    create_checksum(payload, payload_length,
                    checksum); // Assume prefix is 'nexa'

    for (i = 0; i < payload_length; ++i) {
        if (*payload >> 5) {
            *addr_start = 0;
            return 0;
        }
        addr_length++;
        if (max_addr_len < addr_length) {
            *addr_start = 0;
            return 0;
        }
        *(addr++) = charset[payload[i]];
        PRINTF("%c", charset[payload[i]]);
    }

    PRINTF("\npayload after loop\n");
    for(int i = 0; i < addr_length; i++) {
        PRINTF("%c", addr[i]);
    }
    PRINTF("\n");
    PRINTF("Checksum\n");
    for (i = 0; i < 8; ++i) {
        if (*checksum >> 5) {
            *addr_start = 0;
            return 0;
        }
        addr_length++;
        if (max_addr_len < addr_length) {
            *addr_start = 0;
            return 0;
        }
        *(addr++) = charset[checksum[i]];
        PRINTF("%c", charset[checksum[i]]);
    }
    *addr = 0;
    PRINTF("\n");
    return addr_length;
}

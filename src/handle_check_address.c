#include "handle_check_address.h"
#include "os.h"
#include "btchip_helpers.h"
#include "bip32_path.h"
#include "btchip_ecc.h"
#include "btchip_apdu_get_wallet_public_key.h"
#include "cashaddr.h"
#include <string.h>

bool derive_compressed_public_key(
    unsigned char* serialized_path, unsigned char serialized_path_length,
    unsigned char* public_key, unsigned char public_key_length) {
    UNUSED(public_key_length);
    uint8_t pubKey[65];

    if (btchip_get_public_key(serialized_path, serialized_path_length, pubKey, NULL)){
        return false;
    }

    btchip_compress_public_key_value(pubKey);
    memcpy(public_key, pubKey, 33);
    return true;
}

bool get_address_from_compressed_public_key(
    char * address,
    unsigned char max_address_length
) {

    // Cashaddr P2ST
    int keyLength = 33;
    uint8_t tmp[20];
    uint8_t buffer[34];
    buffer[0] = keyLength;
    memcpy(buffer + 1, address, keyLength);

    PRINTF("keylength:%u", keyLength);
    btchip_public_key_hash160(buffer, // IN
                                keyLength + 1,            // INLEN
                                tmp);
    if (!cashaddr_encode(tmp, 20, (uint8_t *)address, max_address_length, CASHADDR_P2ST))
        return false;

    return true;
}

static int os_strcmp(const char* s1, const char* s2) {
    size_t size = strlen(s1) + 1;
    return memcmp(s1, s2, size);
}

int handle_check_address(check_address_parameters_t* params) {
    unsigned char compressed_public_key[33];
    PRINTF("Params on the address %d\n",(unsigned int)params);
    PRINTF("Address to check %s\n",params->address_to_check);
    PRINTF("Inside handle_check_address\n");
    if (params->address_to_check == 0) {
        PRINTF("Address to check == 0\n");
        return 0;
    }
    if (!derive_compressed_public_key(
        params->address_parameters + 1,
        params->address_parameters_length - 1,
        compressed_public_key,
        sizeof(compressed_public_key))) {
        return 0;
    }

    char address[51];
    if (!get_address_from_compressed_public_key(
        address,
        sizeof(address))) {
        PRINTF("Can't create address from given public key\n");
        return 0;
    }
    if (os_strcmp(address,params->address_to_check) != 0) {
        PRINTF("Addresses don't match\n");
        return 0;
    }
    PRINTF("Addresses match\n");
    return 1;
}

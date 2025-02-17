/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#include "btchip_bagl_extensions.h"

#include "cashaddr.h"
#include "btchip_apdu_get_wallet_public_key.h"

int get_public_key_chain_code(unsigned char* keyPath, size_t keyPath_len, bool uncompressedPublicKeys, unsigned char* publicKey, unsigned char* chainCode) {
    uint8_t public_key[65];
    int keyLength = 0;

    if (btchip_get_public_key(keyPath, keyPath_len, public_key, chainCode)) {
        return keyLength;
    }

    btchip_compress_public_key_value(public_key);
    keyLength = 33;

    memmove(publicKey, public_key,
               sizeof(public_key));
    return keyLength;
}

unsigned short btchip_apdu_get_wallet_public_key() {
    unsigned char keyLength;
    unsigned char uncompressedPublicKeys = 0;
    uint32_t request_token;
    unsigned char chainCode[32];
    uint8_t is_derivation_path_unusual = 0;

    bool display = (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_DISPLAY);
    bool display_request_token = N_btchip.pubKeyRequestRestriction && (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_REQUEST_TOKEN) && G_io_apdu_media == IO_APDU_MEDIA_U2F;
    bool require_user_approval = N_btchip.pubKeyRequestRestriction && !(display_request_token || display) && G_io_apdu_media == IO_APDU_MEDIA_U2F;
    // bool cashAddr = (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_CASHADDR);
    if (display && btchip_context_D.called_from_swap)
    {
        return BTCHIP_SW_INCORRECT_DATA;
    }
    switch (G_io_apdu_buffer[ISO_OFFSET_P1])
    {
    case P1_NO_DISPLAY:
    case P1_DISPLAY:
    case P1_REQUEST_TOKEN:
        break;
    default:
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    switch (G_io_apdu_buffer[ISO_OFFSET_P2])
    {
    case P2_LEGACY:
        break;
    case P2_CASHADDR:
        break;
    default:
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_LC] < 0x01)
    {
        return BTCHIP_SW_INCORRECT_LENGTH;
    }
    if (display)
    {
        is_derivation_path_unusual = set_key_path_to_display(G_io_apdu_buffer + ISO_OFFSET_CDATA);
    }

    if(display_request_token)
    {
        uint8_t request_token_offset = ISO_OFFSET_CDATA + G_io_apdu_buffer[ISO_OFFSET_CDATA]*4 + 1;
        request_token = btchip_read_u32(G_io_apdu_buffer + request_token_offset, true, false);
    }

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode))
    {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (os_global_pin_is_validated() != BOLOS_UX_OK)
    {
        return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    PRINTF("pin ok\n");

    unsigned char bip44_enforced = enforce_bip44_coin_type(G_io_apdu_buffer + ISO_OFFSET_CDATA, true);

    G_io_apdu_buffer[0] = 65;
    keyLength = get_public_key_chain_code(G_io_apdu_buffer + ISO_OFFSET_CDATA, MAX_BIP32_PATH_LENGTH, false, G_io_apdu_buffer + 1, chainCode);

    if (keyLength == 0)
    {
        return BTCHIP_SW_TECHNICAL_PROBLEM;
    }
    
    // Cashaddr
    uint8_t tmp[20];
    uint8_t buffer[34];
    memcpy(buffer+1, G_io_apdu_buffer + 1, keyLength);

    buffer[0] = 33;

    PRINTF("\nkeylength:%u \n", keyLength);

    for(int i = 0; i < keyLength; i++) {
        PRINTF("%02x", buffer[i]);
    }
    PRINTF("\n");

btchip_public_key_hash160(buffer, // IN
                                keyLength + 1,            // INLEN
                                tmp);
    PRINTF("GET HASH 160\n");
    for(int i = 0; i < 20; i++) {
        PRINTF("%02x", tmp[i]);
    }
    PRINTF("\n");
    keyLength =
        cashaddr_encode(tmp, 20, G_io_apdu_buffer + 67, 50, CASHADDR_P2ST);

    G_io_apdu_buffer[66] = keyLength;
    PRINTF("Length %d\n", keyLength);
    if (!uncompressedPublicKeys)
    {
        // Restore for the full key component
        G_io_apdu_buffer[1] = 0x04;
    }

    // output chain code
    memmove(G_io_apdu_buffer + 1 + 65 + 1 + keyLength, chainCode, sizeof(chainCode));
    btchip_context_D.outLength = 1 + 65 + 1 + keyLength + sizeof(chainCode);

    // privacy : force display the address if the path isn't standard
    // and could reveal another fork holdings according to BIP 44 rules
    if (!display && !bip44_enforced)
    {
        display = true;
    }

    if (display)
    {
        if (keyLength > 50)
        {
            return BTCHIP_SW_INCORRECT_DATA;
        }
        // Hax, avoid wasting space
        memmove(G_io_apdu_buffer + 200, G_io_apdu_buffer + 67, keyLength);
        G_io_apdu_buffer[200 + keyLength] = '\0';
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_display_public_key(is_derivation_path_unusual);
    }
    // If the token requested has already been approved in a previous call, the source is trusted so don't ask for approval again
    else if(display_request_token && (!btchip_context_D.has_valid_token || memcmp(&request_token, btchip_context_D.last_token, 4)))
    {
        // disable the has_valid_token flag and store the new token
        btchip_context_D.has_valid_token = false;
        memcpy(btchip_context_D.last_token, &request_token, 4);
        // Hax, avoid wasting space
        snprintf((char *)G_io_apdu_buffer + 200, 9, "%08X", request_token);
        G_io_apdu_buffer[200 + 8] = '\0';
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_display_token();
    }
    else if(require_user_approval)
    {
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_request_pubkey_approval();
    }

    return BTCHIP_SW_OK;
}

void btchip_bagl_user_action_display(unsigned char confirming)
{
    unsigned short sw = BTCHIP_SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming)
    {
        // status was already set by the last call
        btchip_context_D.outLength -= 2;

    }
    else
    {
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
}

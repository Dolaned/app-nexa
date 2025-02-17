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

#define GET_TRUSTED_INPUT_P1_FIRST 0x00
#define GET_TRUSTED_INPUT_P1_NEXT 0x80

unsigned short btchip_apdu_get_trusted_input() {
    unsigned char apduLength;
    unsigned char dataOffset = 0;
    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P1] == GET_TRUSTED_INPUT_P1_FIRST) {
        // Initialize
        btchip_context_D.transactionTargetInput =
            btchip_read_u32(G_io_apdu_buffer + ISO_OFFSET_CDATA, 1, 0);
        btchip_context_D.transactionContext.transactionState =
            BTCHIP_TRANSACTION_NONE;
        btchip_context_D.trustedInputProcessed = 0;
        btchip_set_check_internal_structure_integrity(1);
        // TODO, THIS OFFSET BELOW WAS BREAKING EVERYTHING
        dataOffset = 0;
        btchip_context_D.transactionHashOption = TRANSACTION_HASH_FULL;
    } else if (G_io_apdu_buffer[ISO_OFFSET_P1] != GET_TRUSTED_INPUT_P1_NEXT) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P2] != 0x00) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }
    btchip_context_D.transactionBufferPointer =
        G_io_apdu_buffer + ISO_OFFSET_CDATA + dataOffset;
    btchip_context_D.transactionDataRemaining = apduLength - dataOffset;
    PRINTF("TRANSACTION DATA REMAINING: %u \n", btchip_context_D.transactionDataRemaining);

    PRINTF("BEFORE PARSE TRUSTED INPUT \n");
    transaction_parse(PARSE_MODE_TRUSTED_INPUT);
    PRINTF("AFTER PARSE TRUSTED INPUT \n");
    if (btchip_context_D.transactionContext.transactionState ==
        BTCHIP_TRANSACTION_PARSED) {
       PRINTF("Trusted INPUT TX PARSED \n");

        btchip_context_D.transactionContext.transactionState =
            BTCHIP_TRANSACTION_NONE;
        btchip_set_check_internal_structure_integrity(1);
        if (!btchip_context_D.trustedInputProcessed) {
            // Output was not found
            return BTCHIP_SW_INCORRECT_DATA;
        }

        if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, CX_LAST,
                NULL, 0, G_io_apdu_buffer + TRUSTED_INPUT_SIZE, 32)) {
            return BTCHIP_SW_TECHNICAL_PROBLEM;
        }

        // Otherwise prepare
        cx_rng(G_io_apdu_buffer, 8);
        G_io_apdu_buffer[0] = MAGIC_TRUSTED_INPUT;
        G_io_apdu_buffer[1] = 0x00;
        cx_hash_sha256(G_io_apdu_buffer + TRUSTED_INPUT_SIZE, 32, G_io_apdu_buffer + 4, 32);

        btchip_write_u32_le(G_io_apdu_buffer + 4 + 32,
                            0);
        memmove(G_io_apdu_buffer + 4 + 32 + 4,
                   btchip_context_D.transactionContext.transactionAmount, 8);

        cx_hmac_sha256((uint8_t *)N_btchip.bkp.trustedinput_key,
                       sizeof(N_btchip.bkp.trustedinput_key), G_io_apdu_buffer,
                       TRUSTED_INPUT_SIZE, G_io_apdu_buffer + TRUSTED_INPUT_SIZE, 32);
        btchip_context_D.outLength = TRUSTED_INPUT_TOTAL_SIZE;
    } else {
        PRINTF("Transaction State: %u \n", btchip_context_D.transactionContext.transactionState);
        
        PRINTF("TX DATA IS NOT OK \n");
    }
    return BTCHIP_SW_OK;
}

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
#include "btchip_display_variables.h"
#include "ui.h"

#define SIGHASH_ALL 0x01

unsigned short btchip_apdu_hash_sign() {
    unsigned long int lockTime;
    uint32_t sighashType;
    unsigned char dataBuffer[5];
    unsigned char authorizationLength;
    unsigned char *parameters = G_io_apdu_buffer + ISO_OFFSET_CDATA;
    unsigned short sw = SW_TECHNICAL_DETAILS(0xF);

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode)) {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if ((G_io_apdu_buffer[ISO_OFFSET_P1] != 0) ||
        (G_io_apdu_buffer[ISO_OFFSET_P2] != 0)) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_LC] < (1 + 1 + 4 + 1)) {
        return BTCHIP_SW_INCORRECT_LENGTH;
    }

    // Check state
    btchip_set_check_internal_structure_integrity(0);
    if (btchip_context_D.transactionContext.transactionState != BTCHIP_TRANSACTION_SIGN_READY){
        PRINTF("TRANSACTION STATE INCORRECT LETS FORCE IT \n");
        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_SIGN_READY;
    }

    if (btchip_context_D.transactionContext.transactionState != BTCHIP_TRANSACTION_SIGN_READY)
    {
        
        PRINTF("Invalid transaction state %d\n", btchip_context_D.transactionContext.transactionState);
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        goto discardTransaction;
    }

    PRINTF("BUFFER OBJECT: %u \n", G_io_apdu_buffer[ISO_OFFSET_CDATA]);

    // Read parameters
    if (G_io_apdu_buffer[ISO_OFFSET_CDATA] > MAX_BIP32_PATH)
    {
        PRINTF("BIP ISSUE \n");
        sw = BTCHIP_SW_INCORRECT_DATA;
        goto discardTransaction;
    }

    PRINTF("HERE \n");
    memmove(btchip_context_D.transactionSummary.keyPath,
            G_io_apdu_buffer + ISO_OFFSET_CDATA,
            MAX_BIP32_PATH_LENGTH);
    parameters += (4 * G_io_apdu_buffer[ISO_OFFSET_CDATA]) + 1;
    authorizationLength = *(parameters++);
    parameters += authorizationLength;
    lockTime = btchip_read_u32(parameters, 1, 0);
    parameters += 4;
    sighashType = *(parameters++);
    btchip_context_D.transactionSummary.sighashType = sighashType;
    PRINTF("Parameters: %u \n", parameters);
    PRINTF("Keypath: %u \n", btchip_context_D.transactionSummary.keyPath);
    PRINTF("authorization len: %u \n", authorizationLength);
    PRINTF("locktime: %u \n", lockTime);
    PRINTF("sighashtype: %u \n", sighashType);

    if (((N_btchip.bkp.config.options & BTCHIP_OPTION_FREE_SIGHASHTYPE) == 0)) {

        if (sighashType != SIGHASH_ALL) {
            PRINTF("NOT SIGHASH ALL \n");
            sw = BTCHIP_SW_INCORRECT_DATA;
            goto discardTransaction;
        }
        
    }

    // Finalize the hash
    btchip_write_u32_le(dataBuffer, lockTime);
    dataBuffer[4] = sighashType;
    PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(dataBuffer), dataBuffer);
    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, 0,
            dataBuffer, sizeof(dataBuffer), NULL, 0)) {
        goto discardTransaction;
    }

    // Check if the path needs to be enforced
    if (!enforce_bip44_coin_type(btchip_context_D.transactionSummary.keyPath, false)) {
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_request_sign_path_approval(btchip_context_D.transactionSummary.keyPath);
    }
    else {
        // Sign immediately
        btchip_bagl_user_action_signtx(1, 1);
    }
    sw = BTCHIP_SW_OK;
    if (btchip_context_D.called_from_swap) {
        // if we signed all outputs we should exit,
        // but only after sending response, so lets raise the
        // vars.swap_data.should_exit flag and check it on timer later
        vars.swap_data.alreadySignedInputs++;
        if (vars.swap_data.alreadySignedInputs >= vars.swap_data.totalNumberOfInputs) {
            vars.swap_data.should_exit = 1;
        }
    }

    // Then discard the transaction and reply
    btchip_set_check_internal_structure_integrity(1);
    return sw;

    discardTransaction:
        btchip_set_check_internal_structure_integrity(1);
        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_NONE;
        return sw;
}

void btchip_bagl_user_action_signtx(unsigned char confirming, unsigned char direct) {
    unsigned short sw = BTCHIP_SW_OK;
    // confirm and finish the apdu exchange //spaghetti
    if (confirming)
    {
        unsigned char hash[32];
        cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, CX_LAST, hash, 0, hash, 32);
        PRINTF("Hash: %.*H\n", sizeof(hash), hash);
        
        // Sign
        size_t out_len = sizeof(G_io_apdu_buffer);
        btchip_sign_schnorr_finalhash(
            btchip_context_D.transactionSummary.keyPath,
            sizeof(btchip_context_D.transactionSummary.keyPath),
            hash, sizeof(hash),
            G_io_apdu_buffer, &out_len,
            ((N_btchip.bkp.config.options &
                BTCHIP_OPTION_DETERMINISTIC_SIGNATURE) != 0));

        btchip_context_D.outLength = G_io_apdu_buffer[1] + 2;
        G_io_apdu_buffer[btchip_context_D.outLength++] = btchip_context_D.transactionSummary.sighashType;
        ui_transaction_finish();

    }
    else
    {
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }

    if (!direct)
    {
        G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
        G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
    }
}

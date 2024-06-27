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

// TODO Trustlet, BAGL : process each output separately.
// review nvm_write policy

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"
#include "ui.h"
#include "lib_standard_app/crypto_helpers.h"

#define FINALIZE_P1_MORE 0x00
#define FINALIZE_P1_LAST 0x80
#define FINALIZE_P1_CHANGEINFO 0xFF

#define FINALIZE_P2_DEFAULT 0x00

#define FLAG_SIGNATURE 0x01
#define FLAG_CHANGE_VALIDATED 0x80

void btchip_apdu_hash_input_finalize_full_reset(void) {
    btchip_context_D.currentOutputOffset = 0;
    btchip_context_D.outputParsingState = BTCHIP_OUTPUT_PARSING_NUMBER_OUTPUTS;
    memset(btchip_context_D.totalOutputAmount, 0,
              sizeof(btchip_context_D.totalOutputAmount));
    btchip_context_D.changeOutputFound = 0;
    btchip_set_check_internal_structure_integrity(1);
}

static bool check_output_displayable() {
    bool displayable = true;
    unsigned char amount[8], isOpReturn, isP2sh, j, nullAmount = 1;
    unsigned char isOpCreate, isOpCall;

    for (j = 0; j < 8; j++) {
        if (btchip_context_D.currentOutput[j] != 0) {
            nullAmount = 0;
            break;
        }
    }
    if (!nullAmount) {
        btchip_swap_bytes(amount, btchip_context_D.currentOutput, 8);
        transaction_amount_add_be(btchip_context_D.totalOutputAmount,
                                  btchip_context_D.totalOutputAmount, amount);
    }
    isOpReturn =
        btchip_output_script_is_op_return(btchip_context_D.currentOutput + 8);
    isP2sh = btchip_output_script_is_p2sh(btchip_context_D.currentOutput + 8);
    isOpCreate =
        btchip_output_script_is_op_create(btchip_context_D.currentOutput + 8,
          sizeof(btchip_context_D.currentOutput) - 8);
    isOpCall =
        btchip_output_script_is_op_call(btchip_context_D.currentOutput + 8,
          sizeof(btchip_context_D.currentOutput) - 8);
    if (btchip_context_D.tmpCtx.output.changeInitialized && !isOpReturn)
    {
        unsigned char addressOffset = (isP2sh ? OUTPUT_SCRIPT_P2SH_PRE_LENGTH : OUTPUT_SCRIPT_REGULAR_PRE_LENGTH);
        if (!isP2sh && memcmp(btchip_context_D.currentOutput + 8 + addressOffset,
            btchip_context_D.tmpCtx.output.changeAddress, 20) == 0)
        {
            if (btchip_context_D.changeOutputFound)
            {
                PRINTF("Error : Multiple change output found");
                THROW(EXCEPTION);
            }
            btchip_context_D.changeOutputFound = true;
            displayable = false;
        }
    }
    return displayable;
}

bool handle_output_state() {
    uint32_t discardSize = 0;
    btchip_context_D.discardSize = 0;
    bool processed = false;
    switch (btchip_context_D.outputParsingState) {
    case BTCHIP_OUTPUT_PARSING_NUMBER_OUTPUTS: {
        btchip_context_D.totalOutputs = 0;
        if (btchip_context_D.currentOutputOffset < 1) {
            break;
        }
        if (btchip_context_D.currentOutput[0] < 0xFD) {
            btchip_context_D.totalOutputs = btchip_context_D.remainingOutputs =
                btchip_context_D.currentOutput[0];
            discardSize = 1;
            btchip_context_D.outputParsingState = BTCHIP_OUTPUT_PARSING_OUTPUT;
            processed = true;
            break;
        }
        if (btchip_context_D.currentOutput[0] == 0xFD) {
            if (btchip_context_D.currentOutputOffset < 3) {
                break;
            }
            btchip_context_D.totalOutputs = btchip_context_D.remainingOutputs =
                (btchip_context_D.currentOutput[2] << 8) |
                btchip_context_D.currentOutput[1];
            discardSize = 3;
            btchip_context_D.outputParsingState = BTCHIP_OUTPUT_PARSING_OUTPUT;
            processed = true;
            break;
        } else if (btchip_context_D.currentOutput[0] == 0xFE) {
            if (btchip_context_D.currentOutputOffset < 5) {
                break;
            }
            btchip_context_D.totalOutputs = btchip_context_D.remainingOutputs =
                btchip_read_u32(btchip_context_D.currentOutput + 1, 0, 0);
            discardSize = 5;
            btchip_context_D.outputParsingState = BTCHIP_OUTPUT_PARSING_OUTPUT;
            processed = true;
            break;
        } else {
            THROW(EXCEPTION);
        }
    } break;

    case BTCHIP_OUTPUT_PARSING_OUTPUT: {
        unsigned int scriptSize;
        if (btchip_context_D.currentOutputOffset < 9) {
            break;
        }
        if (btchip_context_D.currentOutput[8] < 0xFD) {
            scriptSize = btchip_context_D.currentOutput[8];
            discardSize = 1;
        } else if (btchip_context_D.currentOutput[8] == 0xFD) {
            if (btchip_context_D.currentOutputOffset < 9 + 2) {
                break;
            }
            scriptSize =
                btchip_read_u32(btchip_context_D.currentOutput + 9, 0, 0);
            discardSize = 3;
        } else {
            // Unrealistically large script
            THROW(EXCEPTION);
        }
        if (btchip_context_D.currentOutputOffset <
            8 + discardSize + scriptSize) {
            discardSize = 0;
            break;
        }

        processed = true;

        discardSize += 8 + scriptSize;

        if (check_output_displayable()) {
            btchip_context_D.io_flags |= IO_ASYNCH_REPLY;

            // The output can be processed by the UI

            btchip_context_D.discardSize = discardSize;
            discardSize = 0;
        } else {
            btchip_context_D.remainingOutputs--;
        }
    } break;

    default:
        THROW(EXCEPTION);
    }

    if (discardSize != 0) {
        memmove(btchip_context_D.currentOutput,
                   btchip_context_D.currentOutput + discardSize,
                   btchip_context_D.currentOutputOffset - discardSize);
        btchip_context_D.currentOutputOffset -= discardSize;
    }

    return processed;
}

// out should be 33 bytes, even only 20 bytes is significant for output
int get_pubkey_hash160(unsigned char* keyPath, size_t keyPath_len, unsigned char* out) {
    cx_ecfp_public_key_t public_key;
    int keyLength;
    if (btchip_get_public_key(keyPath, keyPath_len, public_key.W, NULL)) {
        return -1;
    }
    if (((N_btchip.bkp.config.options &
            BTCHIP_OPTION_UNCOMPRESSED_KEYS) != 0)) {
        keyLength = 65;
    } else {
        btchip_compress_public_key_value(public_key.W);
        keyLength = 33;
    }
    btchip_public_key_hash160(
        public_key.W,   // IN
        keyLength,      // INLEN
        out             // OUT
    );
    return 0;
}

unsigned short btchip_apdu_hash_input_finalize_full_internal(
    btchip_transaction_summary_t *transactionSummary) {
    unsigned char authorizationHash[32];
    unsigned char apduLength;
    unsigned short sw = BTCHIP_SW_OK;
    unsigned char *target = G_io_apdu_buffer;
    unsigned char p1 = G_io_apdu_buffer[ISO_OFFSET_P1];
    unsigned char hashOffset = 0;

    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    if ((p1 != FINALIZE_P1_MORE) && (p1 != FINALIZE_P1_LAST) &&
        (p1 != FINALIZE_P1_CHANGEINFO)) {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    PRINTF("p1: %u \n", p1);

    // Check state
    btchip_set_check_internal_structure_integrity(0);
    PRINTF("Transaction State: %u \n", btchip_context_D.transactionContext.transactionState);
    if (btchip_context_D.transactionContext.transactionState !=
            BTCHIP_TRANSACTION_PRESIGN_READY) {
        PRINTF("Error1 \n");
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        goto discardTransaction;
    }

    

    if (p1 == FINALIZE_P1_CHANGEINFO) {
        if (!btchip_context_D.transactionContext.firstSigned) {
            // Already validated, should be prevented on the client side
return_OK:
            return BTCHIP_SW_OK;
        }
        if (!btchip_context_D.tmpCtx.output.changeAccepted) {
            PRINTF("Error2 \n");
            sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
            goto discardTransaction;
        }
        memset(transactionSummary, 0,
                sizeof(btchip_transaction_summary_t));
        if (G_io_apdu_buffer[ISO_OFFSET_CDATA] == 0x00) {
            // Called with no change path, abort, should be prevented on
            // the client side
            goto return_OK;
        }
        memmove(transactionSummary->keyPath,
                G_io_apdu_buffer + ISO_OFFSET_CDATA,
                MAX_BIP32_PATH_LENGTH);

        if (get_pubkey_hash160(transactionSummary->keyPath, sizeof(transactionSummary->keyPath), btchip_context_D.tmpCtx.output.changeAddress)) {
            sw = SW_TECHNICAL_DETAILS(0x0F);
            goto discardTransaction;
        }
        PRINTF("Change address = %.*H\n", 20, btchip_context_D.tmpCtx.output.changeAddress);

        btchip_context_D.tmpCtx.output.changeInitialized = 1;
        btchip_context_D.tmpCtx.output.changeAccepted = 0;

        // if the bip44 change path provided is not canonical or its index are unsual, ask for user approval
        if(bip44_derivation_guard(transactionSummary->keyPath, true)) {
            if (btchip_context_D.called_from_swap) {
                PRINTF("In swap mode only standart path is allowed\n");
                PRINTF("Error3 \n");
                sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
                goto discardTransaction;
            }
            btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
            btchip_context_D.outputParsingState = BTCHIP_BIP44_CHANGE_PATH_VALIDATION;
            btchip_bagl_request_change_path_approval(transactionSummary->keyPath);
        }

        goto return_OK;
    }

    // Always update the transaction & authorization hashes with the given data
    if ((int)(apduLength - hashOffset) < 0)
    {
        sw = BTCHIP_SW_INCORRECT_DATA;
        goto discardTransaction;
    }
    PRINTF("--- ADD TO HASH FULL:\n%.*H\n", apduLength - hashOffset, G_io_apdu_buffer + ISO_OFFSET_CDATA + hashOffset);
    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, 0,
                G_io_apdu_buffer + ISO_OFFSET_CDATA + hashOffset,
                apduLength - hashOffset, NULL, 0))
    {
        sw = SW_TECHNICAL_DETAILS(0x0F);
        goto discardTransaction;
    }

    if (btchip_context_D.transactionContext.firstSigned)
    {
        if ((btchip_context_D.currentOutputOffset + apduLength) > sizeof(btchip_context_D.currentOutput))
        {
            PRINTF("Output is too long to be checked\n");
            sw = BTCHIP_SW_INCORRECT_DATA;
            goto discardTransaction;
        }
        memmove(btchip_context_D.currentOutput +
                btchip_context_D.currentOutputOffset,
                G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength);
        btchip_context_D.currentOutputOffset += apduLength;

        while (handle_output_state() && (!(btchip_context_D.io_flags & IO_ASYNCH_REPLY)))
            // intentionally do nothing
            ;

        // Finalize the TX if necessary

        if ((btchip_context_D.remainingOutputs == 0) && (!(btchip_context_D.io_flags & IO_ASYNCH_REPLY)))
        {
            btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
            btchip_context_D.outputParsingState = BTCHIP_OUTPUT_FINALIZE_TX;
        }
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P1] == FINALIZE_P1_MORE)
    {
        PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", apduLength, G_io_apdu_buffer + ISO_OFFSET_CDATA);
        if (cx_hash_no_throw(&btchip_context_D.transactionHashAuthorization.header, 0,
            G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength, NULL, 0))
        {
            sw = SW_TECHNICAL_DETAILS(0x0F);
            goto discardTransaction;
        }
        G_io_apdu_buffer[0] = 0x00;
        btchip_context_D.outLength = 1;
        btchip_context_D.tmpCtx.output.multipleOutput = 1;
        goto return_OK;
    }

    PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", apduLength, G_io_apdu_buffer + ISO_OFFSET_CDATA);
    if (cx_hash_no_throw(&btchip_context_D.transactionHashAuthorization.header,
        CX_LAST, G_io_apdu_buffer + ISO_OFFSET_CDATA, apduLength, authorizationHash, 32))
    {
        sw = SW_TECHNICAL_DETAILS(0x0F);
        goto discardTransaction;
    }

    if (btchip_context_D.transactionContext.firstSigned)
    {
        if (!btchip_context_D.tmpCtx.output.changeInitialized)
        {
            memset(transactionSummary, 0, sizeof(btchip_transaction_summary_t));
        }

        transactionSummary->payToAddressVersion = G_coin_config->p2pkh_version;
        transactionSummary->payToScriptHashVersion = G_coin_config->p2st_version;

        // Generate new nonce
        cx_rng(transactionSummary->transactionNonce, 8);
    }

    G_io_apdu_buffer[0] = 0x00;
    target++;

    *target = 0x00;
    target++;

    btchip_context_D.outLength = (target - G_io_apdu_buffer);

    // Check that the input being signed is part of the same
    // transaction, otherwise abort
    // (this is done to keep the transaction counter limit per session
    // synchronized)
    if (btchip_context_D.transactionContext.firstSigned)
    // if(true)
    {
        memmove(transactionSummary->authorizationHash,
                authorizationHash,
                sizeof(transactionSummary->authorizationHash));
        goto return_OK;
    }
    else
    {
        PRINTF("Auth Hash: \n");

        for(int i = 0; i < 32; i++) {
            PRINTF("%02x", authorizationHash[i]);
        }
        PRINTF("\n");

        PRINTF("Auth Hash summary: \n");

        for(int i = 0; i < 32; i++) {
            PRINTF("%02x", transactionSummary->authorizationHash[i]);
        }
        PRINTF("\n");
        if (btchip_secure_memcmp(
                    authorizationHash,
                    transactionSummary->authorizationHash,
                    sizeof(transactionSummary->authorizationHash)))
        {
            PRINTF("Authorization hash not matching, aborting\n");
            sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
            goto discardTransaction;
        }
        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_SIGN_READY;
        sw = BTCHIP_SW_OK;
    }
    btchip_apdu_hash_input_finalize_full_reset();
    return sw;

discardTransaction:
    btchip_apdu_hash_input_finalize_full_reset();
    ui_transaction_error();
    btchip_context_D.transactionContext.transactionState =
        BTCHIP_TRANSACTION_NONE;
    btchip_context_D.outLength = 0;

    memmove(G_io_apdu_buffer, btchip_context_D.currentOutput,
            btchip_context_D.currentOutputOffset);
    btchip_context_D.outLength = btchip_context_D.currentOutputOffset;
    return sw;
}

unsigned short btchip_apdu_hash_input_finalize_full() {
    PRINTF("state=%d\n", btchip_context_D.outputParsingState);
    unsigned short sw = btchip_apdu_hash_input_finalize_full_internal(
        &btchip_context_D.transactionSummary);
        // PRINTF("SW BELOW: \n");
        PRINTF("SW: %u \n", sw);
    if (btchip_context_D.io_flags & IO_ASYNCH_REPLY) {
        // if the UI reject the processing of the request, then reply
        // immediately
        bool status;
        if(btchip_context_D.outputParsingState == BTCHIP_BIP44_CHANGE_PATH_VALIDATION) {
            btchip_context_D.outputParsingState = BTCHIP_OUTPUT_PARSING_NUMBER_OUTPUTS;
            return sw;
        }
        else if (btchip_context_D.outputParsingState == BTCHIP_OUTPUT_FINALIZE_TX) {
            status = btchip_bagl_finalize_tx();
        }
        else {
            status = btchip_bagl_confirm_single_output();
        }
        if (!status) {
            PRINTF("FAILING IN HERE");
            ui_transaction_error();
            btchip_context_D.io_flags &= ~IO_ASYNCH_REPLY;
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_context_D.outLength = 0;
            sw = BTCHIP_SW_INCORRECT_DATA;
        }
    }
    return sw;
}

unsigned char btchip_bagl_user_action(unsigned char confirming) {
    unsigned short sw = BTCHIP_SW_OK;

    // confirm and finish the apdu exchange //spaghetti

    if (confirming) {
        // Check if all inputs have been confirmed

        if (btchip_context_D.outputParsingState ==
            BTCHIP_OUTPUT_PARSING_OUTPUT) {
            btchip_context_D.remainingOutputs--;
        }

        while (btchip_context_D.remainingOutputs != 0) {
            memmove(btchip_context_D.currentOutput,
                       btchip_context_D.currentOutput +
                           btchip_context_D.discardSize,
                       btchip_context_D.currentOutputOffset -
                           btchip_context_D.discardSize);
            btchip_context_D.currentOutputOffset -=
                btchip_context_D.discardSize;
            btchip_context_D.io_flags &= ~IO_ASYNCH_REPLY;
            while (handle_output_state() &&
                   (!(btchip_context_D.io_flags & IO_ASYNCH_REPLY)))
                ;
            if (btchip_context_D.io_flags & IO_ASYNCH_REPLY) {
                if (!btchip_bagl_confirm_single_output()) {
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_NONE;
                    sw = BTCHIP_SW_INCORRECT_DATA;
                    break;
                } else {
                    // Let the UI play
                    return 1;
                }
            } else {
                // Out of data to process, wait for the next call
                break;
            }
        }

        if ((btchip_context_D.outputParsingState ==
             BTCHIP_OUTPUT_PARSING_OUTPUT) &&
            (btchip_context_D.remainingOutputs == 0)) {
            btchip_context_D.outputParsingState = BTCHIP_OUTPUT_FINALIZE_TX;
            if (!btchip_bagl_finalize_tx()) {
                btchip_context_D.outputParsingState =
                    BTCHIP_OUTPUT_PARSING_NONE;
                btchip_context_D.transactionContext.transactionState =
                    BTCHIP_TRANSACTION_NONE;
                sw = BTCHIP_SW_INCORRECT_DATA;
            } else {
                // Let the UI play
                return 1;
            }
        }

        if (btchip_context_D.outputParsingState == BTCHIP_OUTPUT_FINALIZE_TX)
        {
            PRINTF("sign ready change\n");
            btchip_context_D.transactionContext.firstSigned = 0;
            btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_SIGN_READY;
        }
        btchip_context_D.outLength -= 2; // status was already set by the last call
    }
    else
    {
        // Discard transaction
        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_NONE;
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

    if ((btchip_context_D.outputParsingState == BTCHIP_OUTPUT_FINALIZE_TX) || (sw != BTCHIP_SW_OK))
    {
        // we've finished the processing of the input
        btchip_apdu_hash_input_finalize_full_reset();
    }

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);

    return 0;
}

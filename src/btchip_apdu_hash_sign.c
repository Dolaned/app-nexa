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
#include "lib_standard_app/crypto_helpers.h"
#include "ui.h"
#include "schnorr.h"
#include "bip32_path.h"
#define SIGHASH_ALL 0x01

unsigned short btchip_apdu_hash_sign() {
    uint32_t lockTime;
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
    PRINTF("BUFFER OBJECT =%.*H\n", 255, G_io_apdu_buffer);
    PRINTF("BUFFER OBJECT: %u \n", G_io_apdu_buffer);

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
    // btchip_context_D.lockTime = lockTime;
    PRINTF("Parameters: %.*h\n",sizeof(parameters), parameters);
    PRINTF("Keypath: %.*h\n",41, btchip_context_D.transactionSummary.keyPath);
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

    // preimage = nVersion + bh2u(hashPrevouts) + bh2u(hashInputAmounts) + bh2u(hashSequence) + scriptCode + bh2u(hashOutputs) + nLocktime + '00'
    int bufferSize = 137;
    unsigned char buffer[137];
    int bufferOffset = 0;
    cx_sha256_init_no_throw(&btchip_context_D.transactionHashFull);

    // version
    memcpy(&buffer[bufferOffset], &btchip_context_D.transactionVersion, 1);
    bufferOffset +=1;
                
    // prevouts
    unsigned char prevoutHash[32];
    memset(prevoutHash, 0, 32);
    cx_hash_no_throw(&btchip_context_D.hashPrevouts.header, CX_LAST, NULL, 0, prevoutHash, 32);
    cx_hash_sha256(prevoutHash, 32, prevoutHash, 32);

    memcpy(&buffer[bufferOffset], prevoutHash, 32);
    bufferOffset +=32;

                
    //input amounts
    unsigned char hashInputAmounts[32];
    memset(hashInputAmounts, 0, 32);
    cx_hash_no_throw(&btchip_context_D.hashInputAmounts.header, CX_LAST, NULL, 0, hashInputAmounts, 32);
    cx_hash_sha256(hashInputAmounts, 32, hashInputAmounts, 32);

    memcpy(&buffer[bufferOffset], hashInputAmounts, 32);
    bufferOffset +=32;

    //sequence
    unsigned char hashSequence[32];
    memset(hashSequence, 0, 32);
    cx_hash_no_throw(&btchip_context_D.hashSequence.header, CX_LAST, NULL, 0, hashSequence, 32);
    cx_hash_sha256(hashSequence, 32, hashSequence, 32);

    memcpy(&buffer[bufferOffset], hashSequence, 32);
    bufferOffset +=32;

    //Script code
    unsigned char scriptcode[2] = { 0x6C, 0xAD };
    unsigned char scriptCodeSize = 2;

    memcpy(&buffer[bufferOffset], &scriptCodeSize, 1);
    bufferOffset +=1;

    memcpy(&buffer[bufferOffset], scriptcode, 2);
    bufferOffset +=2;

    //Outputs
    unsigned char hashOutputs[32];
    memset(hashOutputs, 0, 32);
    cx_hash_no_throw(&btchip_context_D.hashOutputs.header, CX_LAST, NULL, 0, hashOutputs, 32);
    cx_hash_sha256(hashOutputs, 32, hashOutputs, 32);

    memcpy(&buffer[bufferOffset], hashOutputs, 32);
    bufferOffset +=32;


    //locktime
    memcpy(&buffer[bufferOffset], &lockTime, 4);
    bufferOffset +=4;
                
    // 0x00
    unsigned char hashtype[1] = {0};
    memcpy(&buffer[bufferOffset], hashtype, 1);
    bufferOffset +=1;

    PRINTF("PREIMAGE SERIALISATION= %.*H\n", bufferOffset, buffer);
    PRINTF("PREVOUT Hash=%.*H\n", 32, prevoutHash);
    PRINTF("HASH SEQUENCE Hash=%.*H\n", 32, hashSequence);
    PRINTF("INPUTS Hash=%.*H\n", 32, hashInputAmounts);
    PRINTF("HASH OUTPUTS Hash=%.*H\n", 32, hashOutputs);

    PRINTF("--- ADD TO HASH FULL:\n%.*H\n", bufferSize, buffer);
    unsigned char hash[32];
    cx_hash_sha256(buffer, bufferSize, hash, 32);

    PRINTF("PRE IMAGE Hash: %.*H\n", sizeof(hash), hash);

    PRINTF("--- ADD TO HASH FULL:\n%.*H\n", 32, hash);
        cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, 0,
            hash, 32, NULL, 0);

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
        bool error = false;
        unsigned char hash[32];

        cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, CX_LAST, NULL, 0, hash, 32);
        //8FFF121BE06CB45A91CE42A0A938A751A73C33C7A13D6114FEF33009D24189ED
        PRINTF("Double Hash: %.*H\n", sizeof(hash), hash);
        cx_ecfp_private_key_t private_key;
        cx_ecfp_public_key_t pubkey_tweaked;  // Pubkey corresponding to the key used for signing

        bip32_path_t bip32Path;
        bip32Path.length = btchip_context_D.transactionSummary.keyPath[0];

        if (!parse_serialized_path(&bip32Path, btchip_context_D.transactionSummary.keyPath, sizeof(btchip_context_D.transactionSummary.keyPath))) {
            // return -1;
        }

        if (bip32_derive_init_privkey_256(
            CX_CURVE_256K1,
            bip32Path.path, 
            bip32Path.length,
            &private_key,
            NULL) != CX_OK) {
            error = true;
        }
        // 6975a43131fc91a6a7a6f263716f1c3b8d70519db44f52e57d6995e25dc9298a
        PRINTF("Private Key: %.*h\n", sizeof(private_key.d), private_key.d);
        unsigned char outHash[72];
        size_t outHashLen = 72;
        // // Sign
        PRINTF("Create private key error:%d\n",error);

        // // generate corresponding public key
        unsigned int err = 0;
            cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pubkey_tweaked, &private_key, 1);
        if (err != CX_OK) {
            error = true;
        }

        // // Sign
        PRINTF("Create public key error:%d\n",error);

        size_t out_len = sizeof(G_io_apdu_buffer);


        int Signerr = schnorr_sign_nexa(private_key.d,
                      hash,
                      outHash);

        PRINTF("Sign error: %u\n", Signerr);

        //beb1dc2c65bf002e496ff37e2aad82dd6c1d0f1c06196fb07a3afe4d1a7a9482c3bfee0e33836062e83029b5e70a80179744494c86a38d10cee4bd67adb8a171
        PRINTF("signed Preimage tx: %.*H\n", sizeof(outHash), outHash);

        memcpy(G_io_apdu_buffer, outHash, sizeof(outHash));
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

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
#include "btchip_display_variables.h"

#define CONSENSUS_BRANCH_ID_SAPLING 0x76b809bb
#define CONSENSUS_BRANCH_ID_ZCLASSIC 0x930b540d

//Define for switch statement parsing of transaction for hashing
#define PREVOUT 0x01
#define SEQUENCE 0x02
#define INPUTAMOUNTS 0x03
#define OUTPUTS 0x04
#define SCRIPTSIG 0x05

#define DEBUG_LONG "%d"

void check_transaction_available(unsigned char x) {
    if (btchip_context_D.transactionDataRemaining < x) {
        PRINTF("Check transaction available failed %d < %d\n", btchip_context_D.transactionDataRemaining, x);
        THROW(EXCEPTION);
    }
}

#define OP_HASH160 0xA9
#define OP_EQUAL 0x87
#define OP_CHECKMULTISIG 0xAE

unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char carry = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short val = a[8 - 1 - i] + b[8 - 1 - i] + (carry ? 1 : 0);
        carry = (val > 255);
        target[8 - 1 - i] = (val & 255);
    }
    return carry;
}

unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char borrow = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short tmpA = a[8 - 1 - i];
        unsigned short tmpB = b[8 - 1 - i];
        if (borrow) {
            if (tmpA <= tmpB) {
                tmpA += (255 + 1) - 1;
            } else {
                borrow = 0;
                tmpA--;
            }
        }
        if (tmpA < tmpB) {
            borrow = 1;
            tmpA += 255 + 1;
        }
        target[8 - 1 - i] = (unsigned char)(tmpA - tmpB);
    }

    return borrow;
}

void transaction_offset(unsigned char value, unsigned int hashParseType) {
    PRINTF("INCREASING WITH HASHPARSE TYPE: %u, value: %u\n", hashParseType, value);
    switch (hashParseType)
    {
        case SEQUENCE:
            PRINTF("--- ADD TO SEQUENCE:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
            cx_hash_no_throw(&btchip_context_D.hashSequence.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
            break;
        case PREVOUT:
            PRINTF("--- ADD TO PREVOUT:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
            cx_hash_no_throw(&btchip_context_D.hashPrevouts.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
            break;
        case INPUTAMOUNTS:
            PRINTF("--- ADD TO INPUTAMOUNTS:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
            cx_hash_no_throw(&btchip_context_D.hashInputAmounts.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
            break;
        case OUTPUTS:
            PRINTF("--- ADD TO OUTPUTS:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
            cx_hash_no_throw(&btchip_context_D.hashOutputs.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
            break;

    default:
        break;
    }



    if ((btchip_context_D.transactionHashOption & TRANSACTION_HASH_FULL) != 0 && (hashParseType != SCRIPTSIG))
    {
        PRINTF("--- ADD TO HASH FULL:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
        cx_hash_no_throw(&btchip_context_D.transactionHashFull.header, 0,
            btchip_context_D.transactionBufferPointer, value, NULL, 0);
    }
    if ((btchip_context_D.transactionHashOption & TRANSACTION_HASH_AUTHORIZATION) != 0 && (hashParseType != SCRIPTSIG))
    {
        PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
        cx_hash_no_throw(&btchip_context_D.transactionHashAuthorization.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0);
    }
}

void transaction_offset_increase(unsigned char value, unsigned int hashParseType) {
    transaction_offset(value, hashParseType);
    btchip_context_D.transactionBufferPointer += value;
    btchip_context_D.transactionDataRemaining -= value;
}

unsigned long int transaction_get_varint(unsigned int hashParseType) {
    unsigned char firstByte;
    check_transaction_available(1);
    firstByte = *btchip_context_D.transactionBufferPointer;
    PRINTF("FIRST BYTE CHECKING VARINT: %u \n", firstByte);
    if (firstByte < 0xFD) {
        transaction_offset_increase(1, hashParseType);
        return firstByte;
    } else if (firstByte == 0xFD) {
        unsigned long int result;
        transaction_offset_increase(1, hashParseType);
        check_transaction_available(2);
        result =
            (unsigned long int)(*btchip_context_D.transactionBufferPointer) |
            ((unsigned long int)(*(btchip_context_D.transactionBufferPointer +
                                   1))
             << 8);
        transaction_offset_increase(2, hashParseType);
        return result;
    } else if (firstByte == 0xFE) {
        unsigned long int result;
        transaction_offset_increase(1, hashParseType);
        check_transaction_available(4);
        result =
            btchip_read_u32(btchip_context_D.transactionBufferPointer, 0, 0);
        transaction_offset_increase(4, hashParseType);
        return result;
    } else {
        PRINTF("Varint parsing failed\n");
        THROW(INVALID_PARAMETER);
        return 0;
    }
}

void transaction_parse(unsigned char parseMode) {
    unsigned char optionP2SHSkip2FA =
        ((N_btchip.bkp.config.options & BTCHIP_OPTION_SKIP_2FA_P2SH) != 0);
    btchip_set_check_internal_structure_integrity(0);
    BEGIN_TRY {
        TRY {
            for (;;) {
                switch (btchip_context_D.transactionContext.transactionState) {
                case BTCHIP_TRANSACTION_NONE: {
                    PRINTF("Init transaction parser\n");
                    PRINTF("BUFFERS CLEANED \n");
                    // Reset transaction state
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs = 0;

                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;

                    btchip_context_D.transactionContext.scriptRemaining = 0;

                    memset(
                        btchip_context_D.transactionContext.transactionAmount,
                        0, sizeof(btchip_context_D.transactionContext
                                      .transactionAmount));
                    PRINTF("Transaction Amount: %u \n",btchip_context_D.transactionContext.transactionAmount);

                    // TODO : transactionControlFid
                    // Reset hashes
                    if (cx_sha256_init_no_throw(&btchip_context_D.transactionHashFull))
                    {
                        goto fail;
                    }
                    if (cx_sha256_init_no_throw(&btchip_context_D.transactionHashAuthorization)) {
                        goto fail;
                    }
                    if (cx_sha256_init_no_throw(&btchip_context_D.transactionIdem)) {
                        goto fail;
                    }

                    if (cx_sha256_init_no_throw(&btchip_context_D.hashPrevouts))
                    {
                        goto fail;
                    }

                    if (cx_sha256_init_no_throw(&btchip_context_D.hashSequence))
                    {
                        goto fail;
                    }

                    if (cx_sha256_init_no_throw(&btchip_context_D.hashInputAmounts))
                    {
                        goto fail;
                    }

                    if (cx_sha256_init_no_throw(&btchip_context_D.hashOutputs))
                    {
                        goto fail;
                    }
                    // Parse the beginning of the transaction
                    // Version
                    check_transaction_available(1);
                    memmove(&btchip_context_D.transactionVersion,
                               btchip_context_D.transactionBufferPointer, 1);
                    PRINTF("Transaction Version: \n%.*H\n", 1, btchip_context_D.transactionBufferPointer);
                    transaction_offset_increase(1, 0);

                    // Number of inputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint(0);
                    PRINTF("Number of inputs : " DEBUG_LONG "\n",btchip_context_D.transactionContext.transactionRemainingInputsOutputs);

                    if (btchip_context_D.called_from_swap && parseMode == PARSE_MODE_SIGNATURE)
                    {
                        // remember number of inputs to know when to exit from library
                        // we will count number of already signed inputs and compare with this value
                        // As there are a lot of different states in which we can have different number of input
                        // (when for ex. we sign segregated witness)
                        if (vars.swap_data.totalNumberOfInputs == 0)
                        {
                            vars.swap_data.totalNumberOfInputs =
                                btchip_context_D.transactionContext.transactionRemainingInputsOutputs;
                        }
                        // Reseting the flag, because we should check address ones for each input
                        vars.swap_data.was_address_checked = 0;
                    }
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;

                    __attribute__((fallthrough));
                }

                case BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT: {
                    PRINTF("Process input\n");
                    PRINTF("Parse Mode: %u \n", parseMode);
                    PRINTF("Script to read DEFINED_WAIT_INPUT " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    PRINTF("transaction to read DEFINED_WAIT_INPUT " DEBUG_LONG "\n",btchip_context_D.transactionDataRemaining);
                    unsigned char trustedInputFlag = 1;
                    if (btchip_context_D.transactionContext.transactionRemainingInputsOutputs == 0)
                    {
                        PRINTF("Hashing Done, No remaining inputs \n");
                        // No more inputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_INPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1)
                    {
                        PRINTF("No more data to read \n");
                        // No more data to read, ok
                        goto ok;
                    }

                    PRINTF("Parsing prevout\n");
                    // prevout : 1 type + 32 hash
                    check_transaction_available(33);
                    transaction_offset_increase(33, PREVOUT);

                    btchip_context_D.transactionHashOption = TRANSACTION_HASH_FULL;
                    btchip_context_D.transactionContext.scriptRemaining = transaction_get_varint(SCRIPTSIG);
                    // Read the script length
                    PRINTF("Reading Script Length\n");
                    PRINTF("Script to read " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);

                    
                    if (btchip_context_D.transactionContext.scriptRemaining != 0)
                    {
                        PRINTF("Request to sign relaxed input\n");
                        if (!optionP2SHSkip2FA)
                        {
                            goto fail;
                        }
                    }
                    
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;

                    __attribute__((fallthrough));
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    PRINTF("Process input script, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

                    if (btchip_context_D.transactionContext.scriptRemaining == 0)
                    {
                        unsigned char amount[8];
                        if (parseMode == PARSE_MODE_SIGNATURE)
                        {
                            // Restore dual hash for signature +
                            // authentication
                            btchip_context_D.transactionHashOption = TRANSACTION_HASH_BOTH;
                        }
                        // Sequence
                        PRINTF("CHECKING SEQUENCE\n");
                        check_transaction_available(4);
                        transaction_offset_increase(4, SEQUENCE);

                        // TODO FIX THIS ITS WRONG
                        // if(parseMode == PARSE_MODE_TRUSTED_INPUT){
                            PRINTF("CHECKING AMOUNT\n");
                            check_transaction_available(8);

                            btchip_swap_bytes(
                                    amount,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                            if (transaction_amount_add_be(
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                    amount)) {
                                PRINTF("Overflow\n");
                                goto fail;
                            }
                            PRINTF("Adding amount\n%.*H\n",8,btchip_context_D.transactionBufferPointer);
                            PRINTF("New amount\n%.*H\n",8,btchip_context_D.transactionContext.transactionAmount);
                            transaction_offset_increase(8, INPUTAMOUNTS);
                        // }
                        //amount

                        // Move to next input
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;
                        continue;
                    }
                    dataAvailable = btchip_context_D.transactionContext.scriptRemaining;
                    PRINTF("Data Available: %u\n", dataAvailable);
                        // (btchip_context_D.transactionDataRemaining >
                        //          btchip_context_D.transactionContext
                        //                  .scriptRemaining -
                        //              1
                        //      ? btchip_context_D.transactionContext
                        //                .scriptRemaining -
                        //            1
                        //      : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable, SCRIPTSIG);
                    btchip_context_D.transactionContext.scriptRemaining -= dataAvailable;
                    PRINTF("Process input script 2, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);

                    break;
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_DONE: {
                    PRINTF("Input hashing done\n");
                    if (parseMode == PARSE_MODE_SIGNATURE)
                    {
                        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_PRESIGN_READY;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1)
                    {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Number of outputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint(0);
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    PRINTF("Number of outputs : " DEBUG_LONG "\n",
                        btchip_context_D.transactionContext.transactionRemainingInputsOutputs);
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;

                    __attribute__((fallthrough));
                }
                case BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT: {
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more outputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    //type
                    PRINTF("Getting outputs \n");
                    check_transaction_available(1);
                    memmove(&btchip_context_D.transactionContext.outputType,
                            btchip_context_D.transactionBufferPointer,
                            1);
                    transaction_offset_increase(1, OUTPUTS);

                    // Amount
                    check_transaction_available(8);
                    PRINTF("CURRENT UTXO : " DEBUG_LONG "\n",
                        btchip_context_D.transactionContext.transactionCurrentInputOutput);
                    PRINTF("TARGET UTXO : " DEBUG_LONG "\n",
                        btchip_context_D.transactionTargetInput);
                    // TODO, fix this because output index is no longer used
                    // if ((parseMode == PARSE_MODE_TRUSTED_INPUT) && (btchip_context_D.transactionContext.transactionCurrentInputOutput == 0)) {
                        // Save the amount
                        memmove(btchip_context_D.transactionContext
                                       .transactionAmount,
                                   btchip_context_D.transactionBufferPointer,
                                   8);
                        btchip_context_D.trustedInputProcessed = 1;
                    // }
                    transaction_offset_increase(8,OUTPUTS);
                    // Read the script length
                    btchip_context_D.transactionContext.scriptRemaining =
                        transaction_get_varint(OUTPUTS);

                    PRINTF("Script to read outputs " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;

                    __attribute__((fallthrough));
                }
                case BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    PRINTF("Process output script, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        // Move to next output
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;
                        continue;
                    }
                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                     .scriptRemaining
                             ? btchip_context_D.transactionContext
                                   .scriptRemaining
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable, OUTPUTS);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE: {
                    PRINTF("Output hashing done\n");
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Locktime
                    check_transaction_available(4);
                    memmove(btchip_context_D.lockTime,
                               btchip_context_D.transactionBufferPointer, 4);
                    transaction_offset_increase(4, 0);

                    if (btchip_context_D.transactionDataRemaining == 0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PARSED;
                        continue;
                    } else {
                        btchip_context_D.transactionHashOption = 0;
                        btchip_context_D.transactionContext.scriptRemaining =
                            transaction_get_varint(0);
                        btchip_context_D.transactionHashOption =
                            TRANSACTION_HASH_FULL;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA;
                        continue;
                    }
                }

                case BTCHIP_TRANSACTION_PROCESS_EXTRA: {
                    unsigned char dataAvailable;

                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PARSED;
                        continue;
                    }

                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                     .scriptRemaining
                             ? btchip_context_D.transactionContext
                                   .scriptRemaining
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    transaction_offset_increase(dataAvailable, 0);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }

                case BTCHIP_TRANSACTION_PARSED: {

                    PRINTF("Transaction parsed\n");
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PRESIGN_READY: {
                    PRINTF("Presign ready\n");
                    goto ok;
                }

                case BTCHIP_TRANSACTION_SIGN_READY: {
                    PRINTF("Sign ready\n");
                    goto ok;
                }
                }
            }

        fail:
            PRINTF("Transaction parse - fail\n");
            THROW(EXCEPTION);
        ok : {}
        }
        CATCH_OTHER(e) {
            PRINTF("Transaction parse - surprise fail\n");
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_set_check_internal_structure_integrity(1);
            THROW(e);
        }
        // before the finally to restore the surrounding context if an exception
        // is raised during finally
        FINALLY {
            btchip_set_check_internal_structure_integrity(1);
        }
    }
    END_TRY;
}

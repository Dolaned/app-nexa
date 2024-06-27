from typing import Tuple, List

from ledgercomm import Transport
from bitcoin_client.hwi.cashaddr import decode as cash_addr_decode
from bitcoin_client.hwi.cashaddr import encode as cash_addr_encode
from bitcoin_client.hwi.serialization import (CTransaction, CTxIn, CTxOut, COutPoint,
                                              is_p2pkh, hash160, is_p2st, sha256)
from bitcoin_client.hwi.bech32 import decode as bech32_decode
from bitcoin_client.hwi.base58 import decode as base58_decode
from bitcoin_client.utils import deser_trusted_input
from bitcoin_client.bitcoin_utils import bip143_digest, compress_pub_key
from bitcoin_client.bitcoin_cmd_builder import AddrType
from bitcoin_client.bitcoin_base_cmd import BitcoinBaseCommand


class BitcoinCommand(BitcoinBaseCommand):
    """Bitcoin Command.

    Inherit from BitcoinBaseCommand and provide a high level
    interface to sign Bitcoin transaction.

    Parameters
    ----------
    transport : Transport
        Transport interface to the device.
    debug : bool
        Whether you want to see logging or not.

    """

    def __init__(self, transport: Transport, debug: bool = False) -> None:
        """Init constructor."""
        super().__init__(transport, debug)

    def sign_new_tx(self,
                    address: str,
                    amount: int,
                    fees: int,
                    change_path: str,
                    sign_paths: List[str],
                    raw_utxos: List[Tuple[bytes, int]],
                    lock_time: int = 0) -> List[Tuple[bytes, bytes, Tuple[int, bytes]]]:
        """Sign a new transaction with parameters..

        Parameters
        ----------
        address : str
            Bitcoin address.
        amount : int
            Amount to send to address in satoshis.
        fees : int
            Fees of the new transaction.
        change_path : str
            BIP32 path for the change.
        sign_paths : List[str]
            BIP32 paths to sign inputs.
        raw_utxos : List[Tuple[bytes, int]]
            Pairs of raw hex transaction and output index to use as UTXOs.
        lock_time : int
            Block height or timestamp when transaction is final.

        Returns
        -------
        List[Tuple[bytes, bytes, Tuple[int, bytes]]]
            Tuples (tx_hash_digest, sign_pub_key, (v, der_sig))

        """
        utxos: List[Tuple[CTransaction, int, int]] = []
        amount_available: int = 0
        for raw_tx, output_index in raw_utxos:
            utxo = CTransaction.from_bytes(raw_tx)
            value = utxo.vout[output_index].nValue
            utxos.append((utxo, output_index, value))
            amount_available += value

        sign_pub_keys: List[bytes] = []
        for sign_path in sign_paths:
            sign_pub_key, _, _ = self.get_public_key(
                addr_type=AddrType.CASHADDR,
                bip32_path=sign_path,
                display=False
            )
            sign_pub_keys.append(compress_pub_key(sign_pub_key))

        # inputs: List[Tuple[CTransaction, bytes]] = [
        #     (utxo, self.get_trusted_input(utxo=utxo, output_index=output_index))
        #     for utxo, output_index, _ in utxos
        # ]



        # new transaction
        tx: CTransaction = CTransaction()
        tx.nVersion = 0
        tx.nLockTime = lock_time
        inputs = []
        # prepare vin
        for i, utxo_tuple in enumerate(utxos):
            utxo = utxo_tuple[0]
            output_index = utxo_tuple[1]
            amount = utxo_tuple[2]
            print("UTXO Below \n")
            print(utxo)
            print("UTXO Above \n")


            # assert prev_txid != utxo.sha256

            script_pub_key: bytes = utxo.vout[output_index].scriptPubKey
            # P2ST or P2PKH
            if is_p2pkh(script_pub_key):
                script_pub_key = (b"\x76" +  # OP_DUP
                                  b"\xa9" +  # OP_HASH160
                                  b"\x14" +  # bytes to push (20)
                                  hash160(sign_pub_keys[i]) +  # hash160(pubkey)
                                  b"\x88" +  # OP_EQUALVERIFY
                                  b"\xac")  # OP_CHECKSIG

            elif is_p2st(script_pub_key):
                script_pub_key = (
                    b"\x00" +  # OP_0
                    b"\x51" +  # OP_HASH160
                    b"\x14" +  # bytes to push (20)
                    hash160(sign_pub_keys[i]))  # hash160(pubkey)

            tx.vin.append(CTxIn(outpoint=COutPoint(h=utxo.calcIdem()),
                                scriptSig=script_pub_key,
                                nSequence=0xfffffffd))
            bytesArray = bytearray()
            bytesArray += bytearray(utxo.calcIdem())
            bytesArray += bytearray(output_index.to_bytes(4, 'little'))
            shaResult = sha256(bytes(bytesArray))
            print(shaResult.hex())
            inputs.append({0, amount, shaResult})

        if amount_available - fees > amount:
            print("packer her up boys")
            change_pub_key, _, _ = self.get_public_key(
                addr_type=AddrType.CASHADDR,
                bip32_path=change_path,
                display=False
            )
            change_pubkey_hash = hash160(compress_pub_key(change_pub_key))
            change_script_pubkey: bytes
            if is_p2pkh(script_pub_key):
                script_pub_key = (b"\x76" +  # OP_DUP
                                  b"\xa9" +  # OP_HASH160
                                  b"\x14" +  # bytes to push (20)
                                  change_pubkey_hash +  # hash160(pubkey)
                                  b"\x88" +  # OP_EQUALVERIFY
                                  b"\xac")  # OP_CHECKSIG

            elif is_p2st(script_pub_key):
                script_pub_key = (b"\x00" +  # OP_DUP
                    b"\x51" +  # OP_HASH160
                    b"\x14" +  # bytes to push (20)
                    change_pubkey_hash)  # hash160(pubkey)


            else:
                raise Exception(f"Unsupported address: '{address}'")
            tx.vout.append(
                CTxOut(nValue=amount_available - fees - amount,
                       scriptPubKey=change_script_pubkey)
            )
        else:
            change_path = None
        script_pub_key: bytes
        # P2PKH address (mainnet and testnet)
        if address.startswith("q"):
            script_pub_key = (b"\x76" +  # OP_DUP
                              b"\xa9" +  # OP_HASH160
                              b"\x14" +  # bytes to push (20)
                              base58_decode(address)[1:-4] +  # hash160(pubkey)
                              b"\x88" +  # OP_EQUALVERIFY
                              b"\xac")  # OP_CHECKSIG
        elif address.startswith("n"):
            script_pub_key = cash_addr_decode(address)[2]
        else:
            raise Exception(f"Unsupported address: '{address}'")

        tx.vout.append(CTxOut(nValue=amount,
                              scriptPubKey=script_pub_key))

        for i in range(len(tx.vin)):
            print("vin loop")
            self.untrusted_hash_tx_input_start(tx=tx,
                                               inputs=inputs,
                                               input_index=i,
                                               script=tx.vin[i].scriptSig,
                                               is_new_transaction=(i == 0))
            
        print("sign new tx")

        self.untrusted_hash_tx_input_finalize(tx=tx,
                                              change_path=change_path)

        sigs: List[Tuple[bytes, bytes, Tuple[int, bytes]]] = []
        for i in range(len(tx.vin)):
            # self.untrusted_hash_tx_input_start(tx=tx,
            #                                    inputs=[inputs[i]],
            #                                    input_index=0,
            #                                    script=tx.vin[i].scriptSig,
            #                                    is_new_transaction=False)
            _, _, amount = inputs[i]
            sigs.append(
                (bip143_digest(tx, amount, i),
                 sign_pub_keys[i],
                 self.untrusted_hash_sign(sign_path=sign_paths[i],
                                          lock_time=tx.nLockTime,
                                          sig_hash=1))
            )

        return sigs

    def sign_tx(self,
                tx: CTransaction,
                change_path: str,
                sign_paths: List[str],
                utxos: List[Tuple[CTransaction, int, int]]) -> List[Tuple[int, bytes]]:
        inputs: List[Tuple[CTransaction, bytes]] = [
            (utxo, self.get_trusted_input(utxo=utxo, output_index=output_index))
            for utxo, output_index, _ in utxos
        ]

        for i in range(len(tx.vin)):
            self.untrusted_hash_tx_input_start(tx=tx,
                                               inputs=inputs,
                                               input_index=i,
                                               script=tx.vin[i].scriptSig,
                                               is_new_transaction=(i == 0))

        self.untrusted_hash_tx_input_finalize(tx=tx,
                                              change_path=change_path)

        sigs = []
        for i in range(len(tx.vin)):
            self.untrusted_hash_tx_input_start(tx=tx,
                                               inputs=[inputs[i]],
                                               input_index=0,
                                               script=tx.vin[i].scriptSig,
                                               is_new_transaction=False)
            sigs.append(self.untrusted_hash_sign(sign_path=sign_paths[i],
                                                 lock_time=tx.nLockTime,
                                                 sig_hash=1))

        return sigs

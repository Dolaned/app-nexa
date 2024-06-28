from io import BytesIO

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.utils import deser_trusted_input


def test_get_trusted_inputs(cmd):
    raw_tx: bytes = bytes.fromhex(
        # Version no (4 bytes little endian)
        "02000000"
        # In-counter (varint 1-9 bytes)
        "02"
        # [1] Previous Transaction hash (32 bytes)
        "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
        # [1] Previous Txout-index (4 bytes little endian)
        "00000000"
        # [1] Txin-script length (varint 1-9 bytes)
        "6b"
        # [1] scriptSig (0x6b = 107 bytes)
        "48"
        "3045"
        "0221"
        # r
        "00ca145f0694ffaedd333d3724ce3f4e44aabc0ed5128113660d11f917b3c52053"
        "0220"
        # s
        "7bec7c66328bace92bd525f385a9aa1261b83e0f92310ea1850488b40bd25a5d"
        # sighash
        "01"
        "21"
        # compressed public key
        "032006c64cdd0485e068c1e22ba0fa267ca02ca0c2b34cdc6dd08cba23796b6ee7"
        # [1] sequence_no (4 bytes little endian)
        "fdffffff"
        # [2] Previous Transaction hash (32 bytes)
        "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
        # [2] Previous Txout-index (4 bytes little endian)
        "01000000"
        # [2] Txin-script length (varint 1-9 bytes)
        "6a"
        # [2] scriptSig (0x6a = 106 bytes)
        "47"
        "3044"
        "0220"
        # r
        "2a5d54a1635a7a0ae22cef76d8144ca2a1c3c035c87e7cd0280ab43d34510906"
        "0220"
        # s
        "0c7e07e384b3620ccd2f97b5c08f5893357c653edc2b8570f099d9ff34a0285c"
        "01"
        "21"
        # compressed public key
        "02d82f3fa29d38297db8e1879010c27f27533439c868b1cc6af27dd3d33b243dec"
        # [2] sequence_no (4 bytes little endian)
        "fdffffff"
        # Out-counter (varint 1-9 bytes)
        "01"
        # [1] Value (8 bytes little endian)
        "d7ee7c0100000000"  # 0.24964823 BTC
        # [1] Txout-script length (varint 1-9 bytes)
        "19"
        # [1] scriptPubKey (0x19 = 25 bytes)
        "76a914"
        "0ea263ff8b0da6e8d187de76f6a362beadab7811"
        "88ac"
        # lock_time (4 bytes little endian)
        "e3691900"
    )

    tx: CTransaction
    output_index: int
    trusted_input: bytes

    tx = CTransaction()
    tx.deserialize(BytesIO(raw_tx))
    tx.calc_sha256()

    output_index = 0
    trusted_input = cmd.get_trusted_input(utxo=tx, output_index=output_index)

    _, _, _, prev_txid, out_index, amount, _ = deser_trusted_input(trusted_input)
    assert out_index == output_index
    assert prev_txid == tx.sha256.to_bytes(32, byteorder="little")
    assert amount == tx.vout[out_index].nValue


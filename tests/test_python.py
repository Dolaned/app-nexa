from io import BytesIO

from bitcoin_client.hwi.serialization import CTransaction, sha256, hash256
from bitcoin_client.utils import deser_trusted_input



def test_get_trusted_inputs(cmd):

    greg_preimage: bytes = bytes.fromhex('0057b1abd5c3c0ca2d7a8c7ceaa8dba3f030968c798c27a3356c79c565c19c4ec03f52b4d86040ee526cff04f9cd158b3700f6e14b868df9fabc8263746473732f18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198026cadf1a900b9e3c584e82c8a15677bd2902c2de85d06ce92be261c50f4e2e7aed819a73e060000')
    dolan_preimage: bytes = bytes.fromhex('0057B1ABD5C3C0CA2D7A8C7CEAA8DBA3F030968C798C27A3356C79C565C19C4EC03F52B4D86040EE526CFF04F9CD158B3700F6E14B868DF9FABC8263746473732F18606B350CD8BF565266BC352F0CADDCF01E8FA789DD8A15386327CF8CABE198026CADF1A900B9E3C584E82C8A15677BD2902C2DE85D06CE92BE261C50F4E2E7AED819A73E060000')
    res1 = hash256(greg_preimage).hex()
    res2 = hash256(dolan_preimage).hex()
    print(res1)
    print(res2)
    assert False
    raw_tx: bytes = bytes.fromhex(
        # Version no (4 bytes little endian) TODO: 1 byte
        "00"
        # vin-counter (varint 1-9 bytes)
        "02"
        # [1] Previous Transaction hash (32 bytes)
        "40d1ae8a596b34f48b303e853c56f8f6f54c483babc16978eb182e2154d5f2ab"
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
    idem: bytes
    trusted_input: bytes

    raw_tx = bytes.fromhex('000100dd891f8389bc0ea3fe7b667a2bc12e61f460bb183e20d037329078346a524dd86422210267351b8db6c8b6dde86e348063d88a3c5c2d1ac0e453988c9720045749ff89a0407e5d76eeb01ee0d7e8f581f617ea53437913c05c681c3f215743b4afe1032e073a55247db4638d065e2d8ba058c16dd1d0d718b372c42fce1d2a2ca34a4ea6eefeffffffe80300000000000001012d0300000000000017005114a3fc83ff618b7f5a1ee270964d401a1416b00153a43e0600')
    tx = CTransaction()
    tx.deserialize(BytesIO(raw_tx))
    tx.rehash()

    raw_tx_two = bytes.fromhex('000100251db01d59cb236482aa9b3b145674477ad4218b34d7153f00bfb284bcfe15536422210267351b8db6c8b6dde86e348063d88a3c5c2d1ac0e453988c9720045749ff89a0407e5d76eeb01ee0d7e8f581f617ea53437913c05c681c3f215743b4afe1032e073a55247db4638d065e2d8ba058c16dd1d0d718b372c42fce1d2a2ca34a4ea6eefeffffff2d0300000000000001018602000000000000170051149cdd01d51fefe0f397b992a23018fbab6282fc42a73e0600')
    tx2 = CTransaction()
    tx2.deserialize(BytesIO(raw_tx_two))
    tx2.rehash()

    trusted_input = cmd.get_trusted_input(utxo=tx)

    _, _, _, prev_idem, amount, _, _ = deser_trusted_input(trusted_input)

    assert prev_idem.hex() == tx.idem.hex()

    trusted_input2 = cmd.get_trusted_input(utxo=tx2)

    _, _, _, prev_idem, amount, _, _ = deser_trusted_input(trusted_input2)
    print(prev_idem)

    assert prev_idem.hex() == tx2.idem.hex()



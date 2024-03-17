from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/accept_pubkey.json")
def test_get_public_key(cmd):
    # legacy address
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.CASHADDR,
        bip32_path="m/44'/29223'/1'/1/0",
        display=True
    )
    assert pub_key == bytes.fromhex("04ef5170dd054483c878f3a2c132724675d96f8f74c3346dcc8b44f2bddfc6d9dcfd7a5ea27051f7f1ce5082deceae866889575294e0ec69d92d370e0e8d33523a")
    assert addr == "nqtsq5g5507g8lmp3dl458hzwzty6sq6zsttqq2n36eel304"
    assert bip32_chain_code == bytes.fromhex("061f27e9372b28eebcac06a8c361688f04c109a1f6711ce0f66b55af578ae821")

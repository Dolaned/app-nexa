from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/sign_message.json")
def test_sign_message(cmd):
    result = cmd.sign_message(
            message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.",
            bip32_path="m/44'/29223'/1'/1/0",
    )
    assert result == "MEQCIGPH+Fa8m/fM+mB5aYqzXT8+2vHh3v8RYR0iAfpZ6yZkAiAa++rzrj9SfSnqeu3h1aox6UaQt3CLC/nv3gjwn9nNYQ=="


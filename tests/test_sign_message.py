from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/sign_message.json")
def test_sign_message(cmd):
    result = cmd.sign_message(
            message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.",
            bip32_path="m/44'/29223'/1'/1/0",
    )
    print(result)
    assert result == "MEQCIEja8XR185kvSDTQx+c5f/Grow3QKfdO0c+QPQDxveErAiB6o+v+QUtRN7WL2JMyvvhlvPyc0i0+2pgFNueo6k010g=="


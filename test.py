import sys
import base64
from signatures import Signature5

KEY = "<base64-encoded-key>"
SIG = "<signature>"
IP = ("<ipv4-address>",)
UA = "<user-agent>"


def main():
    key = base64.b64decode(KEY)
    sig = Signature5.create_from_request(SIG, IP, UA, key)
    print(sig.get_payload())
    return 0


if __name__ == '__main__':
    sys.exit(main())
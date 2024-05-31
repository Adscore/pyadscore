# pyadscore

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)

This library provides various utilities for producing and parsing [Adscore](https://adscore.com) signatures, generating custom request payloads, and
virtually anything that might be useful for customers doing server-side integration with the service.

## Usage

### V4 signature verification

This version is not yet supported by this library.

### V5 signature decryption

V5 is in fact an encrypted payload containing various metadata about the traffic. Its decryption does not rely on IP address nor User Agent string,
so it is immune for environment changes usually preventing V4 to be even decoded. Judge result is also included in the payload, but client doing the 
integration can make its own decision basing on the metadata accompanying.

Zone has to be set explicitly to V5 signature, if you don't see the option, please contact support as we are rolling this mode on customer's demand.
The format supports a wide variety of encryption and serialization methods, some of them are included in this repository, but it can be extended to
fulfill specific needs.

It can be integrated in V4-compatible mode, not making use of any V5 features (see V4 verification):

```python
import base64
from signatures import Signature5
from exceptions import VersionError, ParseError, VerifyError
from definitions import judge

crypt_key = base64.b64decode("<base64-encoded-key>")
signature = "<signature>"
user_agent = "<user-agent>"
ip_addresses = ("<ipv4-address>",)

try:
    parser = Signature5.create_from_request(signature, ip_addresses, user_agent, crypt_key)
    result = parser.get_result()
# Judge is the module evaluating final result in the form of single score. RESULTS constant 
# contains array with human-readable descriptions of every numerical result, if needed. 
    human_readable = judge.RESULTS[result]
    print("%s (%s)" % (human_readable["verdict"], human_readable["name"]))
except VersionError:
# It means that the signature is not the V5 one, check your zone settings and ensure the signatures are coming from the chosen zone.    
    pass
except ParseError:
# It means that the signature metadata is malformed and cannot be parsed, or contains invalid data, check for corruption underway.
    pass
except VerifyError:
# Signature could not be verified - see error message for details.
    pass
```

The first difference is that now `crypt_key` may be also a lambda function, accepting single `int` argument - zone ID 
and returning raw key as binary string. 
This is useful in scenarios, where signatures coming from different zones are handled at a single point. This is not possible for V4 signatures, as they
do not carry over any zone information.

As we can see, `create_from_request` also requires a list of IP addresses and User Agent string. This is used for built-in verification routine, but
this time the verification is completely unrelated to decryption. Client integrating might want to replace the verification with its own implementation,
so here is the extended example (without any exception handling for readability):

```python
import base64
from signatures import Signature5

# An example structure holding keys for every zone supported
crypt_keys = {
    123: base64.b64decode("<base64-encoded-key>")
}
signature = "<signature>"

parser = Signature5()
# Parsing/decryption stage
parser.parse(signature, lambda zone_id: crypt_keys[zone_id])
# The payload now contains a decrypted signature data which might be used to verify the signature
payload = parser.get_payload()
# We can still make use of built-in signature validator and only then get_result() is being populated
ip_addresses = ("<ipv4-address>",)
user_agent = "<user-agent>"
parser.verify(ip_addresses, user_agent)
result = parser.get_result()
print("Result: %u" % result)
```
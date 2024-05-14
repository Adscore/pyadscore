from inspect import isfunction
import struct
from Formatter import AbstractFormatter
from Signature import AbstractSignature


class Signature5(AbstractSignature):

    VERSION = 5
    HEADER_LENGTH = 11

    _zone_id = None

    def __init__(self, zone_id=None, payload=None):
        self._zone_id = zone_id
        self._payload = payload

    def get_zone_id(self):
        return self._zone_id

    def set_zone_id(self, zone_id):
        assert isinstance(zone_id, int)
        self._zone_id = zone_id

    @staticmethod
    def create_from_request(signature, ip_addresses, user_agent, crypt_key, formatter=None):
        obj = Signature5()
        if isinstance(crypt_key, (str, bytes)):
            on_crypt_key_request = lambda zone_id: crypt_key  # E731 deliberate violation
        elif isfunction(crypt_key):
            on_crypt_key_request = crypt_key
        else:
            raise TypeError("crypt_key must be a string or a function")
        obj.parse(signature, on_crypt_key_request, formatter)
        obj.verify(ip_addresses, user_agent)
        return obj

    def verify(self, ip_addresses, user_agent):
        assert isinstance(ip_addresses, tuple)
        assert isinstance(user_agent, str)
        # todo
        return True

    def parse(self, signature, on_crypt_key_request, formatter=None):
        assert isinstance(signature, (str, bytes))
        assert isfunction(on_crypt_key_request)
        if formatter is None:
            formatter = self._get_default_formatter()
        else:
            assert isinstance(formatter, AbstractFormatter.AbstractFormatter)
        payload = formatter.parse(signature)
        if len(payload) <= self.HEADER_LENGTH:
            raise RuntimeError("Malformed signature")
        # all vars are in network byte order (big-endian)
        (version, length, zone_id) = struct.unpack('!BHQ', payload)
        if version != self.VERSION:
            raise RuntimeError("Invalid signature version")
        encrypted_payload = payload[self.HEADER_LENGTH:]
        if len(encrypted_payload) < length:
            raise RuntimeError("Truncated signature payload")
        self._payload = self._decrypt_payload(encrypted_payload, on_crypt_key_request(zone_id))
        self._zone_id = zone_id

    def _decrypt_payload(self, payload, key):

        return {}


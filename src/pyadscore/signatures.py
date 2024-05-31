from abc import ABC, abstractmethod
from inspect import isfunction
import struct
from formatters import AbstractFormatter, Base64


class AbstractSignature(ABC):

    _payload = None
    _result = None

    def get_payload(self):
        return self._payload

    def set_payload(self, payload):
        assert isinstance(payload, dict)
        self._payload = payload

    def get_result(self):
        if self._result is None:
            raise RuntimeError("Result unavailable for unverified signature")
        return self._result

    @staticmethod
    @abstractmethod
    def create_from_request(signature, ip_addresses, user_agent, crypt_key, formatter=None):
        pass

    @staticmethod
    def _get_default_formatter():
        return Base64(Base64.BASE64_VARIANT_URLSAFE_NO_PADDING, True)

    @staticmethod
    def _bytes_compare(known, user, n):
        # todo
        pass


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
            obj.parse(signature, lambda zone_id: crypt_key, formatter)
        elif isfunction(crypt_key):
            obj.parse(signature, crypt_key, formatter)
        else:
            raise TypeError("crypt_key must be a string or a function")
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
            assert isinstance(formatter, AbstractFormatter)
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

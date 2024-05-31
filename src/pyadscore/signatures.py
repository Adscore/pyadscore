import socket
from abc import ABC, abstractmethod
from inspect import isfunction
import struct
from socket import inet_pton, inet_ntop

from crypts import CryptFactory
from structs import StructFactory
from formatters import AbstractFormatter, Base64
from exceptions import VersionError, VerifyError, ParseError


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
        return known[:n] == user[:n]


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
        # IP address validation
        p_ipv4_bytes = 4
        if 'ipv4.ip' in self._payload and len(self._payload["ipv4.ip"]):
            p_ipv4_address = inet_pton(socket.AF_INET, self._payload["ipv4.ip"])
        else:
            p_ipv4_address = None
        if 'ipv4.v' in self._payload and isinstance(self._payload["ipv4.v"], int):
            p_ipv4_bytes = int(self._payload["ipv4.v"])
        p_ipv6_bytes = 16
        if 'ipv6.ip' in self._payload and len(self._payload["ipv6.ip"]):
            p_ipv6_address = inet_pton(socket.AF_INET6, self._payload["ipv6.ip"])
        else:
            p_ipv6_address = None
        if 'ipv6.v' in self._payload and isinstance(self._payload["ipv6.v"], int):
            p_ipv6_bytes = int(self._payload["ipv6.v"])
        matching_ip = None
        for ip_address in ip_addresses:
            try:
                n_ip_address = inet_pton(socket.AF_INET, ip_address)
                if p_ipv4_address and self._bytes_compare(n_ip_address, p_ipv4_address, p_ipv4_bytes):
                    matching_ip = n_ip_address
                    break
            except OSError:
                n_ip_address = inet_pton(socket.AF_INET6, ip_address)
                if p_ipv6_address and self._bytes_compare(n_ip_address, p_ipv6_address, p_ipv6_bytes):
                    matching_ip = n_ip_address
                    break
        if matching_ip is None:
            raise VerifyError("Signature IP mismatch")
        # User agent validation
        if "b.ua" not in self._payload:
            raise VerifyError("Signature contains no user agent")
        if self._payload["b.ua"] != user_agent:
            raise VerifyError("Signature user agent mismatch")
        self._result = self._payload["result"]
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
            raise ParseError("Malformed signature")
        # all vars here are in network byte order (big-endian)
        (version, length, zone_id) = struct.unpack('!BHQ', payload[:self.HEADER_LENGTH])
        if version != self.VERSION:
            raise VersionError("Invalid signature version")
        encrypted_payload = payload[self.HEADER_LENGTH:]
        if len(encrypted_payload) < length:
            raise ParseError("Truncated signature payload")
        self._payload = self._decrypt_payload(encrypted_payload, on_crypt_key_request(zone_id))
        self._zone_id = zone_id

    @staticmethod
    def _decrypt_payload(payload, key):
        crypt = CryptFactory.create_from_payload(payload)
        decrypted_payload = crypt.decrypt_with_key(payload, key)
        unpacker = StructFactory.create_from_payload(decrypted_payload)
        unpacked_payload = unpacker.unpack(decrypted_payload)
        return unpacked_payload

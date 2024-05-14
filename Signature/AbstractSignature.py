from Formatter import AbstractFormatter, Base64
from abc import ABC, abstractmethod


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
        return Base64.Base64(Base64.Base64.BASE64_VARIANT_URLSAFE_NO_PADDING, True)

    @staticmethod
    def _bytes_compare(known, user, n):
        # todo
        pass

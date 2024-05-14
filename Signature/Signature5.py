from inspect import isfunction


class Signature5:

    VERSION = 5
    HEADER_LENGTH = 11

    payload = None
    zone_id = None

    def __init__(self, zone_id=None, payload=None):
        self.zone_id = zone_id
        self.payload = payload

    def get_zone_id(self):
        return self.zone_id

    def set_zone_id(self, zone_id):
        assert isinstance(zone_id, int)
        self.zone_id = zone_id

    @staticmethod
    def create_from_request(signature, ip_addresses, user_agent, crypt_key, formatter=None):
        obj = Signature5()
        if isinstance(crypt_key, str):
            on_crypt_key_request = lambda zone_id: crypt_key  # E731 deliberate violation (todo?)
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
        assert isinstance(signature, str)
        assert isfunction(on_crypt_key_request)
        if formatter is None:
            formatter = self.get_default_formatter()
        else:
            assert isinstance(formatter, AbstractFormatter)
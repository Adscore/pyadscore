import sys
from abc import ABC, abstractmethod
from importlib import import_module
import json
from urllib.parse import parse_qs, urlencode, quote

lib_names = ['phpserialize3', 'msgpack']
for lib_name in lib_names:
    try:
        lib = import_module(lib_name)
    except ImportError:
        pass  # print(sys.exc_info())
    else:
        globals()[lib_name] = lib


class AbstractStruct(ABC):
    TYPE = None

    @classmethod
    def _pack(cls, data):
        return cls.TYPE + data

    @classmethod
    def _unpack(cls, data):
        if data[:1] != cls.TYPE:
            raise RuntimeError("Unexpected serializer type")
        return data[1:]


class StructFactory:
    @staticmethod
    def create(name):
        if name == Serialize.TYPE or name == 'serialize' or name == 'Serialize':
            return Serialize()
        if name == Json.TYPE or name == 'json' or name == 'Json' or name == "JSON":
            return Json()
        if name == Rfc3986.TYPE or name == 'rfc3986' or name == 'Rfc3986' or name == "RFC3986":
            return Rfc3986()
        if name == Msgpack.TYPE or name == "msgpack" or name == "Msgpack":
            return Msgpack()
        raise RuntimeError("Unsupported serialization mode")

    @staticmethod
    def create_from_payload(payload):
        return StructFactory.create(payload[:1])


class Rfc3986(AbstractStruct):
    TYPE = b'H'

    def pack(self, data):
        payload = urlencode(data, quote_via=quote)
        return self._pack(payload)

    def unpack(self, data):
        payload = self._unpack(data)
        return parse_qs(payload)


class Json(AbstractStruct):
    TYPE = b'J'

    def pack(self, data):
        payload = json.dumps(data)
        return self._pack(payload)

    def unpack(self, data):
        payload = self._unpack(data)
        return json.loads(payload)


class Serialize(AbstractStruct):
    TYPE = b'S'

    def __init__(self):
        if "phpserialize3" not in globals():
            raise RuntimeError("Required dependency phpserialize3 not installed")
        self.phpserialize3 = globals()["phpserialize3"]

    def pack(self, data):
        payload = self.phpserialize3.dumps(data)
        return self._pack(payload)

    def unpack(self, data):
        payload = self._unpack(data)
        return self.phpserialize3.loads(payload)


class Msgpack(AbstractStruct):
    TYPE = b'M'

    def __init__(self):
        if "msgpack" not in globals():
            raise RuntimeError("Required dependency msgpack not installed")
        self.msgpack = globals()["msgpack"]

    def pack(self, data):
        payload = self.msgpack.dumps(data)
        return self._pack(payload)

    def unpack(self, data):
        payload = self._unpack(data)
        return self.msgpack.loads(payload)
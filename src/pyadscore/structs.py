import sys
from abc import ABC, abstractmethod
from importlib import import_module
import json

lib_names = ['phpserialize3']
for lib_name in lib_names:
    try:
        lib = import_module(lib_name)
    except:
        print(sys.exc_info())
    else:
        globals()[lib_name] = lib


class AbstractStruct(ABC):
    TYPE = ''

    @classmethod
    def _pack(cls, data):
        return cls.TYPE + data

    @classmethod
    def _unpack(cls, data):
        if data[:1] != cls.TYPE:
            raise RuntimeError("Unexpected serializer type")
        return data[1:]


class Json(AbstractStruct):
    TYPE = 'J'

    def pack(self, data):
        payload = json.dumps(data)
        return self._pack(payload)

    def unpack(self, data):
        payload = self._unpack(data)
        return json.loads(payload)


class Serialize(AbstractStruct):
    TYPE = 'S'

    def __init__(self):
        if globals()["phpserialize3"] is None:
            raise RuntimeError("Required dependency phpserialize3 not installed")

    def pack(self, data):
        payload = phpserialize3.dumps(data)
        return self._pack(payload)

    def unpack(self, data):
        payload = self._unpack(data)
        return phpserialize3.loads(payload)
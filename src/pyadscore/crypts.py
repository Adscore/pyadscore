from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from abc import ABC, abstractmethod
from importlib import import_module
import struct
import sys

lib_names = ['nacl']
for lib_name in lib_names:
    try:
        lib = import_module(lib_name)
    except ImportError:
        pass  # print(sys.exc_info())
    else:
        globals()[lib_name] = lib


class AbstractSymmetricCrypt(ABC):
    METHOD_SIZE = 2
    METHOD = None

    @abstractmethod
    def decrypt_with_key(self, data, key):
        pass


class CryptFactory:
    @staticmethod
    def create(name):
        if name == struct.pack("<H", OpenSSL.METHOD) or name == "OpenSSL" or name == "openssl":
            return OpenSSL()
        if name == struct.pack("<H", OpenSSLAEAD.METHOD) or name == "OpenSSLAEAD" or name == "opensslaead":
            return OpenSSLAEAD()
        if name == struct.pack("<H", Secretbox.METHOD) or name == "Secretbox" or name == "secretbox":
            return Secretbox()
        raise RuntimeError("Unsupported encryption mode")

    @staticmethod
    def create_from_payload(payload):
        header = payload[:AbstractSymmetricCrypt.METHOD_SIZE]
        return CryptFactory.create(header)


class Secretbox(AbstractSymmetricCrypt):
    METHOD = 0x0101

    def __init__(self):
        if "nacl" not in globals():
            raise RuntimeError("Required dependency pynacl not installed")
        self.nacl = globals()["nacl"]

    def decrypt_with_key(self, data, key):
        (method,) = struct.unpack("<H", data[:self.METHOD_SIZE])
        if method != self.METHOD:
            raise RuntimeError("Unexpected encryption type")
        nonce = data[self.METHOD_SIZE:self.METHOD_SIZE + self.nacl.secret.SecretBox.NONCE_SIZE]
        data = data[self.METHOD_SIZE + self.nacl.secret.SecretBox.NONCE_SIZE:]
        box = self.nacl.secret.SecretBox(key)
        return box.decrypt(data, nonce)


class OpenSSL(AbstractSymmetricCrypt):
    METHOD = 0x0200  # little-endian
    BLOCK_SIZE = 16

    def decrypt_with_key(self, data, key):
        (method,) = struct.unpack("<H", data[:self.METHOD_SIZE])
        if method != self.METHOD:
            raise RuntimeError("Unexpected encryption type")
        iv = data[self.METHOD_SIZE:self.METHOD_SIZE + self.BLOCK_SIZE]
        data = data[self.METHOD_SIZE + self.BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()


class OpenSSLAEAD(OpenSSL):
    METHOD = 0x0201  # little-endian
    TAG_LENGTH = 16

    def decrypt_with_key(self, data, key):
        (method,) = struct.unpack("<H", data[:self.METHOD_SIZE])
        if method != self.METHOD:
            raise RuntimeError("Unexpected encryption type")
        iv = data[self.METHOD_SIZE:self.METHOD_SIZE + self.BLOCK_SIZE]
        tag = data[self.METHOD_SIZE + self.BLOCK_SIZE:self.METHOD_SIZE + self.BLOCK_SIZE + self.TAG_LENGTH]
        data = data[self.METHOD_SIZE + self.BLOCK_SIZE + self.TAG_LENGTH:]
        cipher = Cipher(algorithms.AES256(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()



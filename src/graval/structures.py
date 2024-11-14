"""
C library structure defs.
"""

from ctypes import (
    Structure,
    POINTER,
    c_char,
    c_ubyte,
    c_size_t,
    c_uint,
    c_bool,
    c_float,
    c_double,
)
from typing import Dict


class GraValDeviceInfo(Structure):
    """
    Device info struct.
    """

    _fields_ = [
        ("name", c_char * 64),
        ("uuid", c_char * 33),
        ("memory", c_size_t),
        ("major", c_uint),
        ("minor", c_uint),
        ("processors", c_uint),
        ("sxm", c_bool),
        ("clock_rate", c_double),
        ("max_threads_per_processor", c_uint),
        ("concurrent_kernels", c_bool),
        ("ecc", c_bool),
        ("challenge_matrix", POINTER(c_float)),
    ]

    @classmethod
    def from_dict(cls, data: Dict) -> "GraValDeviceInfo":
        """
        Create a struct from normal python dict.
        """
        device = cls()
        name_bytes = data["name"].encode("utf-8")[:64]
        uuid_bytes = data["uuid"].encode("utf-8")[:33]
        name_array = (c_char * 64)()
        uuid_array = (c_char * 33)()
        name_array.value = name_bytes
        uuid_array.value = uuid_bytes
        device.name = bytes(name_array)
        device.uuid = bytes(uuid_array)
        device.memory = data["memory"]
        device.major = data["major"]
        device.minor = data["minor"]
        device.processors = data["processors"]
        device.sxm = data["sxm"]
        device.clock_rate = data["clock_rate"]
        device.max_threads_per_processor = data["max_threads_per_processor"]
        device.concurrent_kernels = data["concurrent_kernels"]
        device.ecc = data["ecc"]
        device.challenge_matrix = None
        return device

    def to_dict(self) -> Dict:
        """
        Convert struct to normal python dict.
        """
        return {
            "name": self.name.decode("utf-8").rstrip("\x00"),
            "uuid": self.uuid.decode("utf-8").rstrip("\x00"),
            "memory": self.memory,
            "major": self.major,
            "minor": self.minor,
            "processors": self.processors,
            "sxm": bool(self.sxm),
            "clock_rate": self.clock_rate,
            "max_threads_per_processor": self.max_threads_per_processor,
            "concurrent_kernels": bool(self.concurrent_kernels),
            "ecc": bool(self.ecc),
        }


class GraValCiphertext(Structure):
    """
    Ciphertext wrapper.
    """

    _fields_ = [
        ("length", c_size_t),
        ("ciphertext", POINTER(c_ubyte)),
        ("initialization_vector", c_ubyte * 16),
    ]


class GraValError(Exception): ...  # noqa: E701

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
    c_void_p,
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
        ("processors", c_uint),
        ("clock_rate", c_double),
        ("max_threads_per_processor", c_uint),
        ("challenge_matrix", POINTER(c_float)),
        ("context", c_void_p),
        ("queue", c_void_p),
        ("program", c_void_p),
        ("tanh_kernel", c_void_p),
        ("downsample_kernel", c_void_p),
        ("opencl_initialized", c_bool),
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
        device.processors = data["processors"]
        device.clock_rate = data["clock_rate"]
        device.max_threads_per_processor = data["max_threads_per_processor"]
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
            "processors": self.processors,
            "clock_rate": self.clock_rate,
            "max_threads_per_processor": self.max_threads_per_processor,
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

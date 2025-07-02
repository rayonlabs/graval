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
    c_double,
    c_void_p,
    c_ulong,
    c_float,
)
from typing import Dict


class GraValMinerWorkProduct(Structure):
    """
    Miner work product struct.
    """

    _fields_ = [
        ("final_matrix", POINTER(c_float)),
        ("intermediate_hashes", POINTER(POINTER(c_ubyte))),
        ("num_matrices", c_size_t),
        ("total_iterations", c_size_t),
    ]

    def to_dict(self) -> Dict:
        """
        Convert work product to dictionary.
        """
        # Extract intermediate hashes
        hashes = []
        total_hashes = self.total_iterations * self.num_matrices
        if self.intermediate_hashes:
            for i in range(total_hashes):
                if self.intermediate_hashes[i]:
                    # Each hash is 32 bytes (SHA256)
                    hash_bytes = bytes(self.intermediate_hashes[i][j] for j in range(32))
                    hashes.append(hash_bytes.hex())

        return {
            "intermediate_hashes": hashes,
            "num_matrices": self.num_matrices,
            "total_iterations": self.total_iterations,
        }


class GraValDeviceInfo(Structure):
    """
    Device info struct.
    """

    _fields_ = [
        ("name", c_char * 64),
        ("uuid", c_char * 33),
        ("memory", c_size_t),
        ("processors", c_size_t),
        ("clock_rate", c_double),
        ("max_threads_per_processor", c_uint),
        ("work_product", POINTER(GraValMinerWorkProduct)),
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
        device.work_product = None
        device.context = None
        device.queue = None
        device.program = None
        device.tanh_kernel = None
        device.downsample_kernel = None
        return device

    def to_dict(self) -> Dict:
        """
        Convert struct to normal python dict.
        """
        result = {
            "name": self.name.decode("utf-8").rstrip("\x00"),
            "uuid": self.uuid.decode("utf-8").rstrip("\x00"),
            "memory": self.memory,
            "processors": self.processors,
            "clock_rate": self.clock_rate,
            "max_threads_per_processor": self.max_threads_per_processor,
        }
        if self.work_product:
            result["work_product"] = self.work_product.contents.to_dict()

        return result


class GraValCiphertext(Structure):
    """
    Ciphertext wrapper.
    """

    _fields_ = [
        ("length", c_size_t),
        ("seed", c_ulong),
        ("ciphertext", POINTER(c_ubyte)),
        ("initialization_vector", c_ubyte * 16),
    ]


class GraValError(Exception): ...  # noqa: E701

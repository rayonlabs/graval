"""
GraVal - Miner wrapper.
"""

from typing import Dict
from ctypes import (
    POINTER,
    c_char,
    c_ubyte,
    c_ulong,
    c_uint,
    create_string_buffer,
    cast,
    byref,
    c_size_t,
)
from graval.base import BaseGraVal
from graval.structures import GraValCiphertext, GraValError, GraValDeviceInfo


class Miner(BaseGraVal):
    """
    GraVal implementation for miners.
    """

    def __init__(self):
        super().__init__("libgraval-miner.so")
        self._setup_miner_functions()
        count = self._lib.initialize_node()
        if count == 0:
            raise GraValError("Failed to initialize graval node")
        self._initialized = False
        self._device_count = count
        self._seed = None

    def _setup_miner_functions(self):
        """
        Set up miner-specific library function signatures.
        """
        self._lib.initialize_node.argtypes = []
        self._lib.initialize_node.restype = c_uint
        self._lib.generate_challenge_matrices.argtypes = [c_ulong, c_ulong]
        self._lib.generate_challenge_matrices.restype = c_uint
        self._lib.miner_decrypt.argtypes = [POINTER(GraValCiphertext), c_uint]
        self._lib.miner_decrypt.restype = POINTER(c_char)
        self._lib.miner_device_info_challenge.argtypes = [POINTER(c_char)]
        self._lib.miner_device_info_challenge.restype = POINTER(c_char)
        self._lib.gather_device_info.argtypes = [c_uint, POINTER(c_char)]
        self._lib.gather_device_info.restypes = POINTER(GraValDeviceInfo)
        self._lib.miner_filesystem_challenge.argtypes = [
            POINTER(c_char),
            c_size_t,
            c_size_t,
        ]
        self._lib.miner_filesystem_challenge.restype = POINTER(c_char)
        self._lib.shutdown_node.argtypes = []
        self._lib.shutdown_node.restype = None

    def prove(self, seed: int, iterations: int = 1) -> list[dict]:
        """
        Perform PoVW work using the provided seed for N iterations.
        """
        if self._seed != seed:
            if not self._lib.generate_challenge_matrices(c_ulong(seed), c_ulong(iterations)):
                raise GraValError("Failed to generate work product.")
            self._seed = seed
            self._initialized = True

        work_products = {}
        for device_id in range(self._device_count):
            device_info = self.get_device_info(device_id)
            work_products[device_info["uuid"]] = {
                "device_id": device_id,
                "device_uuid": device_info["uuid"],
                "device_name": device_info["name"],
                "work_product": device_info["work_product"],
            }
        return work_products

    def shutdown(self) -> None:
        """
        Shutdown and cleanup.
        """
        self._lib.shutdown_node()

    def decrypt(
        self, seed: int, encrypted_data: bytes, iv: bytes, length: int, device_id: int
    ) -> str:
        """
        Decrypt data as a miner.
        """
        if not self._initialized or self._seed != seed:
            raise GraValError("GraVal node not initialized")
        ct = GraValCiphertext()
        ct.seed = seed
        ct.length = length
        ct_buffer = create_string_buffer(encrypted_data)
        ct.ciphertext = cast(ct_buffer, POINTER(c_ubyte))
        iv_array = (c_ubyte * 16)(*iv)
        ct.initialization_vector = iv_array
        result = self._lib.miner_decrypt(byref(ct), c_uint(device_id))
        if not result:
            raise GraValError("Decryption failed")
        try:
            i = 0
            bytes_list = []
            while result[i] and i < ct.length + 32:
                if (byte_ := ord(result[i])) == 0:
                    break
                bytes_list.append(byte_)
                i += 1
            return bytes(bytes_list).decode("utf-8")
        finally:
            self._free_char_ptr(result)

    def get_device_info(self, device_id: int) -> Dict:
        """
        Load device info by device ID (index).
        """
        if not self._device_count:
            raise GraValError("GraVal node not initialized")
        error_msg = create_string_buffer(1024)
        device_info = self._lib.gather_device_info(c_uint(device_id), error_msg)
        if not device_info:
            raise GraValError(f"Failed to gather device info: {error_msg.value.decode()}")
        return device_info.contents.to_dict()

    def process_device_info_challenge(self, challenge: str) -> str:
        """
        Process device info challenges.
        """
        if not self._device_count:
            raise GraValError("GraVal node not initialized")
        challenge_buffer = create_string_buffer(challenge.encode())
        result = self._lib.miner_device_info_challenge(challenge_buffer)
        if not result:
            raise GraValError("Failed to process challenge")
        try:
            return bytes(result[:64]).decode()
        finally:
            self._free_char_ptr(result)

    def process_filesystem_challenge(self, filename: str, offset: int, length: int) -> str:
        """
        Process a filesystem challenge.
        """
        filename_buffer = create_string_buffer(filename.encode())
        result = self._lib.miner_filesystem_challenge(
            filename_buffer, c_size_t(offset), c_size_t(length)
        )
        if not result:
            raise GraValError("Filesystem challenge processing failed")
        try:
            return bytes(result[:64]).decode()
        finally:
            self._free_char_ptr(result)

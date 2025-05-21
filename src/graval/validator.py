"""
GraVal - Validator wrapper.
"""

from typing import List, Tuple, Dict
from ctypes import (
    pointer,
    POINTER,
    c_char,
    c_uint,
    c_int,
    c_bool,
    c_ubyte,
    c_ulong,
    create_string_buffer,
    cast,
    byref,
)
from .base import BaseGraVal
from .structures import GraValDeviceInfo, GraValCiphertext, GraValError


class Validator(BaseGraVal):
    """
    GraVal implementation for validators.
    """

    def __init__(self):
        super().__init__("libgraval-validator.so")
        self._setup_validator_functions()

    def _setup_validator_functions(self):
        """
        Set up validator-specific library function signatures.
        """
        self._lib.initialize_node.argtypes = []
        self._lib.initialize_node.restype = c_ulong
        self._lib.generate_unique_seed.argtypes = [POINTER(c_char), c_uint]
        self._lib.generate_unique_seed.restype = c_uint
        self._lib.validator_encrypt.argtypes = [
            POINTER(GraValDeviceInfo),
            POINTER(c_char),
            c_ulong,
            c_ulong,
        ]
        self._lib.validator_encrypt.restype = POINTER(GraValCiphertext)
        self._lib.validator_decrypt.argtypes = [
            POINTER(GraValDeviceInfo),
            POINTER(GraValCiphertext),
            c_ulong,
            c_ulong,
        ]
        self._lib.validator_decrypt.restype = POINTER(c_char)
        self._lib.generate_device_info_challenge.argtypes = [c_int]
        self._lib.generate_device_info_challenge.restype = POINTER(c_char)
        self._lib.verify_device_info_challenge.argtypes = [
            POINTER(c_char),
            POINTER(c_char),
            POINTER(POINTER(GraValDeviceInfo)),
            c_uint,
        ]
        self._lib.verify_device_info_challenge.restype = c_bool
        self._lib.generate_matrix_challenge.argtypes = [
            c_ulong,
            c_ulong,
            POINTER(GraValDeviceInfo),
            POINTER(c_char),
        ]
        self._lib.generate_matrix_challenge.restype = POINTER(GraValCiphertext)
        self._lib.validate_matrix_challenge.argtypes = [
            c_ulong,
            c_ulong,
            POINTER(GraValCiphertext),
            POINTER(GraValDeviceInfo),
            POINTER(c_char),
        ]
        self._lib.validate_matrix_challenge.restype = c_bool
        count = self._lib.initialize_node()
        if count == 0:
            raise GraValError("Failed to initialize graval node")
        self._initialized = True
        self._device_count = count
        self._lib.shutdown_node.argtypes = []
        self._lib.shutdown_node.restype = None

    def shutdown(self) -> None:
        """
        Shutdown and cleanup.
        """
        self._lib.shutdown_node()

    def encrypt(
        self, device_info: Dict, plaintext: str, seed: int, iterations: int = 1
    ) -> Tuple[bytes, bytes, int]:
        """
        Encrypt data as a validator.
        """
        device = GraValDeviceInfo.from_dict(device_info)
        text_buffer = create_string_buffer(plaintext.encode())
        result = self._lib.validator_encrypt(
            byref(device), text_buffer, c_ulong(seed), c_ulong(iterations)
        )
        if not result:
            raise GraValError("Encryption failed")
        try:
            ciphertext = bytes(result.contents.ciphertext[: result.contents.length])
            iv = bytes((result.contents.initialization_vector[i] for i in range(16)))
            length = result.contents.length
            return ciphertext, iv, length
        finally:
            self._free_ciphertext(result)

    def decrypt(
        self,
        device_info: Dict,
        encrypted_data: bytes,
        iv: bytes,
        length: int,
        seed: int,
        iterations: int = 1,
    ) -> str:
        """
        Decrypt data as validator.
        """
        device = GraValDeviceInfo.from_dict(device_info)
        ct = GraValCiphertext()
        ct.length = length
        ct_buffer = create_string_buffer(encrypted_data)
        ct.ciphertext = cast(ct_buffer, POINTER(c_ubyte))
        iv_array = (c_ubyte * 16)(*iv)
        ct.initialization_vector = iv_array
        result = self._lib.validator_decrypt(
            byref(device), byref(ct), c_ulong(seed), c_ulong(iterations)
        )
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

    def generate_device_info_challenge(self, device_count: int) -> str:
        """
        Generate a device info challenge.
        """
        result = self._lib.generate_device_info_challenge(device_count)
        if not result:
            raise GraValError("Failed to generate challenge")
        try:
            return bytes(result[:64]).decode()
        finally:
            self._free_char_ptr(result)

    def verify_device_info_challenge(
        self, challenge: str, response: str, devices: List[Dict]
    ) -> bool:
        """
        Verify a device info challenge response.
        """
        device_structs = [GraValDeviceInfo.from_dict(d) for d in devices]
        device_count = len(device_structs)
        device_pointers = (POINTER(GraValDeviceInfo) * device_count)()
        for i, device in enumerate(device_structs):
            device_pointers[i] = pointer(device)
        challenge_buffer = create_string_buffer(challenge.encode())
        response_buffer = create_string_buffer(response.encode())
        return self._lib.verify_device_info_challenge(
            challenge_buffer,
            response_buffer,
            cast(device_pointers, POINTER(POINTER(GraValDeviceInfo))),
            c_uint(device_count),
        )

    def generate_matrix_challenge(
        self,
        seed: int,
        device_info: Dict,
        plaintext: str,
        iterations: int = 1,
    ) -> Tuple[bytes, bytes, int]:
        """
        Generate a fresh matrix challenge for a device.
        """
        device = GraValDeviceInfo.from_dict(device_info)
        text_buffer = create_string_buffer(plaintext.encode())
        result = self._lib.generate_matrix_challenge(
            c_ulong(seed), c_ulong(iterations), byref(device), text_buffer
        )
        if not result:
            raise GraValError("Matrix challenge generation failed")
        try:
            ciphertext = bytes(result.contents.ciphertext[: result.contents.length])
            iv = bytes(result.contents.initialization_vector)
            length = result.contents.length
            return ciphertext, iv, length
        finally:
            self._free_ciphertext(result)

    def validate_matrix_challenge(
        self,
        seed: int,
        encrypted_data: bytes,
        iv: bytes,
        length: int,
        device_info: Dict,
        expected: str,
        iterations: int = 1,
    ) -> bool:
        """
        Validate a matrix challenge response.
        """
        device = GraValDeviceInfo.from_dict(device_info)
        ct = GraValCiphertext()
        ct.length = length
        ct_buffer = create_string_buffer(encrypted_data)
        ct.ciphertext = cast(ct_buffer, POINTER(c_ubyte))
        iv_array = (c_ubyte * 16)(*iv)
        ct.initialization_vector = iv_array
        expected_buffer = create_string_buffer(expected.encode())
        return self._lib.validate_matrix_challenge(
            c_ulong(seed),
            c_ulong(iterations),
            c_ulong(iterations),
            byref(ct),
            byref(device),
            expected_buffer,
        )

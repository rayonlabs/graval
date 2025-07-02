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
    c_ulong,
    c_size_t,
    c_ubyte,
    create_string_buffer,
    cast,
    byref,
)
from .base import BaseGraVal
from .structures import GraValDeviceInfo, GraValCiphertext, GraValMinerWorkProduct, GraValError


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
        self._lib.validator_encrypt.argtypes = [
            POINTER(GraValDeviceInfo),
            POINTER(c_char),
            c_size_t,
            c_ulong,
        ]
        self._lib.validator_encrypt.restype = POINTER(GraValCiphertext)
        self._lib.generate_device_info_challenge.argtypes = [c_int]
        self._lib.generate_device_info_challenge.restype = POINTER(c_char)
        self._lib.verify_device_info_challenge.argtypes = [
            POINTER(c_char),
            POINTER(c_char),
            POINTER(POINTER(GraValDeviceInfo)),
            c_uint,
        ]
        self._lib.verify_device_info_challenge.restype = c_bool
        self._lib.validator_check_proof.argtypes = [
            POINTER(GraValDeviceInfo),
            c_ulong,
            c_size_t,
            POINTER(GraValMinerWorkProduct),
            c_size_t,
        ]
        self._lib.validator_check_proof.restype = c_bool
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
        self, device_info: Dict, plaintext: str, iterations: int = 1, override_seed: int = None
    ) -> Tuple[bytes, bytes, int]:
        """
        Encrypt data as a validator.
        """
        device = GraValDeviceInfo.from_dict(device_info)
        text_buffer = create_string_buffer(plaintext.encode())
        seed_arg = override_seed if isinstance(override_seed, int) and override_seed > 0 else 0
        result = self._lib.validator_encrypt(
            byref(device), text_buffer, c_size_t(iterations), c_ulong(seed_arg)
        )
        if not result:
            raise GraValError("Encryption failed")
        try:
            ciphertext = bytes(result.contents.ciphertext[: result.contents.length])
            iv = bytes((result.contents.initialization_vector[i] for i in range(16)))
            length = result.contents.length
            seed = result.contents.seed
            return ciphertext, iv, length, seed
        finally:
            self._free_ciphertext(result)

    def check_proof(
        self, device_info: Dict, seed: int, check_iteration: int, work_product: Dict, index: int = 0
    ) -> bool:
        """
        Check a miner's proof at a specific iteration.
        """
        device = GraValDeviceInfo.from_dict(device_info)

        wp = GraValMinerWorkProduct()
        wp.num_matrices = work_product["num_matrices"]
        wp.total_iterations = work_product["total_iterations"]
        wp.final_matrix = None

        hashes = work_product["intermediate_hashes"]
        total_hashes = wp.total_iterations * wp.num_matrices
        if len(hashes) != total_hashes:
            raise GraValError(f"Invalid hash count: expected {total_hashes}, got {len(hashes)}")

        hash_pointers = (POINTER(c_ubyte) * total_hashes)()
        hash_arrays = []

        for i, hash_hex in enumerate(hashes):
            hash_bytes = bytes.fromhex(hash_hex)
            if len(hash_bytes) != 32:
                raise GraValError(
                    f"Invalid hash length at index {i}: expected 32, got {len(hash_bytes)}"
                )
            hash_array = (c_ubyte * 32)(*hash_bytes)
            hash_arrays.append(hash_array)  # Keep reference
            hash_pointers[i] = cast(hash_array, POINTER(c_ubyte))
        wp.intermediate_hashes = cast(hash_pointers, POINTER(POINTER(c_ubyte)))
        return self._lib.validator_check_proof(
            byref(device), c_ulong(seed), c_size_t(check_iteration), byref(wp), c_size_t(index)
        )

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

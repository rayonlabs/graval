"""
Base graval class.
"""

import os
from abc import ABC
from ctypes import CDLL, POINTER, c_char, c_uint, c_void_p, cast, c_char_p
from graval.structures import GraValDeviceInfo, GraValCiphertext


class BaseGraVal(ABC):
    """
    Base class for GraVal functionality shared between miners and validators.
    """

    def __init__(self, lib_name: str):
        """
        Constructor, differentiate miner vs validator libs.
        """
        self._initialized = False
        self._device_count = 0
        lib_path = os.path.join(os.path.dirname(__file__), "lib", lib_name)
        self._lib = CDLL(lib_path)
        self._setup_lib_functions()

    def _setup_lib_functions(self):
        """
        Set up library function signatures.
        """
        self._lib.free.argtypes = [c_void_p]
        self._lib.free.restype = None
        self._lib.gather_device_info.argtypes = [c_uint, c_char_p]
        self._lib.gather_device_info.restype = POINTER(GraValDeviceInfo)

    def _free_ciphertext(self, ciphertext_ptr: POINTER(GraValCiphertext)) -> None:
        """
        Free memory allocated for ciphertext structure.
        """
        if not ciphertext_ptr:
            return
        if ciphertext_ptr.contents.ciphertext:
            self._lib.free(cast(ciphertext_ptr.contents.ciphertext, c_void_p))
        self._lib.free(cast(ciphertext_ptr, c_void_p))

    def _free_char_ptr(self, char_ptr: POINTER(c_char)) -> None:
        """
        Free memory allocated for char pointers (e.g. from decrypt).
        """
        if char_ptr:
            self._lib.free(cast(char_ptr, c_void_p))

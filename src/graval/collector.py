"""
GraVal - Collector wrapper.
"""

from typing import Dict
from ctypes import (
    POINTER,
    c_char,
    c_int,
    c_uint,
    create_string_buffer,
)
from graval.base import BaseGraVal
from graval.structures import GraValError, GraValDeviceInfo


class Collector(BaseGraVal):
    """
    GraVal simple device info gatherer -- cannot be used in isolation since dlopen can
    be intercepted and such, but it's a good entrypoint to get the device info to
    generate challenges from, which will then adequately test the system (theoretically).
    """

    def __init__(self):
        super().__init__("libgraval-collector.so")
        self._setup_functions()

    def _setup_functions(self):
        """
        Set up collector-specific library function signatures.
        """
        self._lib.get_device_count.argtypes = []
        self._lib.get_device_count.restype = c_int
        self._lib.gather_device_info.argtypes = [c_uint, POINTER(c_char)]
        self._lib.gather_device_info.restype = POINTER(GraValDeviceInfo)

    def get_device_count(self) -> int:
        """
        Count GPUs.
        """
        return self._lib.get_device_count()

    def get_device_info(self, device_id: int) -> Dict:
        """
        Load device info by device ID (index).
        """
        error_msg = create_string_buffer(1024)
        device_info = self._lib.gather_device_info(c_uint(device_id), error_msg)
        if not device_info:
            raise GraValError(f"Failed to gather device info: {error_msg.value.decode()}")
        return device_info.contents.to_dict()

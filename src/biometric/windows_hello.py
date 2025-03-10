import asyncio
import sys
import base64
from typing import Optional, Tuple
import winreg
import ctypes
from ctypes.wintypes import DWORD, HANDLE
import win32security
import win32api
import win32con
# from win32com.shell import shell, shellcon
import winerror

# Windows Hello API constants
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 1
WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_ID_TYPE_SID = 3

# Windows Hello DLL
WINBIO_API = ctypes.WinDLL("winbio.dll")

class WindowsHelloAuth:
    def __init__(self):
        self.session_handle = HANDLE()
        self.unit_id = DWORD()
        self.is_initialized = False

    def initialize(self) -> bool:
        """Initialize Windows Hello biometric session."""
        try:
            # Check if Windows Hello is available
            if not self._is_windows_hello_available():
                print("Windows Hello is not available on this system")
                return False

            # Open biometric session
            result = WINBIO_API.WinBioOpenSession(
                WINBIO_TYPE_FINGERPRINT,
                WINBIO_POOL_SYSTEM,
                WINBIO_FLAG_DEFAULT,
                None,
                0,
                None,
                ctypes.byref(self.session_handle)
            )

            if result != 0:  # ERROR_SUCCESS = 0
                print(f"Failed to open biometric session. Error: {result}")
                return False

            self.is_initialized = True
            print("Windows Hello biometric session initialized successfully")
            return True

        except Exception as e:
            print(f"Error initializing Windows Hello: {e}")
            return False

    def _is_windows_hello_available(self) -> bool:
        """Check if Windows Hello is available and enabled."""
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Biometric"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                              winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                return True
        except WindowsError:
            return False

    async def scan_fingerprint(self) -> Tuple[bool, Optional[bytes]]:
        """Scan fingerprint using Windows Hello."""
        if not self.is_initialized:
            if not self.initialize():
                return False, None

        try:
            # Get current user SID
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32con.TOKEN_QUERY
            )
            sid = win32security.GetTokenInformation(
                token,
                win32security.TokenUser
            )[0]
            sid_string = win32security.ConvertSidToStringSid(sid)

            # Verify fingerprint
            rejection_detail = DWORD()
            result = WINBIO_API.WinBioVerify(
                self.session_handle,
                sid_string,
                WINBIO_ID_TYPE_SID,
                WINBIO_FLAG_DEFAULT,
                ctypes.byref(self.unit_id),
                ctypes.byref(rejection_detail)
            )

            if result == 0:  # ERROR_SUCCESS
                # Get biometric template
                template_size = DWORD()
                template_buffer = ctypes.c_void_p()

                result = WINBIO_API.WinBioCaptureSample(
                    self.session_handle,
                    ctypes.byref(template_buffer),
                    ctypes.byref(template_size),
                    ctypes.byref(self.unit_id)
                )

                if result == 0:
                    # Convert template to bytes
                    template_data = ctypes.string_at(template_buffer, template_size.value)
                    # Free the template buffer
                    WINBIO_API.WinBioFree(template_buffer)
                    
                    # Encode template for transmission
                    encoded_template = base64.b64encode(template_data)
                    return True, encoded_template

            return False, None

        except Exception as e:
            print(f"Error during fingerprint scan: {e}")
            return False, None
        finally:
            if self.is_initialized:
                WINBIO_API.WinBioCloseSensor(self.session_handle)
                self.is_initialized = False

    def __del__(self):
        """Cleanup Windows Hello session."""
        if self.is_initialized:
            WINBIO_API.WinBioCloseSensor(self.session_handle)

async def get_fingerprint() -> Optional[bytes]:
    """Helper function to get fingerprint data."""
    auth = WindowsHelloAuth()
    success, fingerprint_data = await auth.scan_fingerprint()
    if success and fingerprint_data:
        return fingerprint_data
    return None

if __name__ == "__main__":
    # Test the fingerprint scanner
    async def test_scanner():
        print("Testing Windows Hello fingerprint scanner...")
        fingerprint = await get_fingerprint()
        if fingerprint:
            print("Fingerprint scanned successfully!")
            print(f"Fingerprint data length: {len(fingerprint)} bytes")
        else:
            print("Failed to scan fingerprint")

    asyncio.run(test_scanner())

from .base_check import SecurityCheck
from .root_check import RootCheck
from .selinux_check import SELinuxCheck
from .android_version_check import AndroidVersionCheck
from .usb_debug_check import USBDebugCheck
from .suspicious_apps_check import SuspiciousAppsCheck
from .permissions_check import PermissionsCheck
from .encryption_check import EncryptionCheck
from .screen_lock_check import ScreenLockCheck
from .network_check import NetworkCheck
from .play_protect_check import PlayProtectCheck
from .developer_options_check import DeveloperOptionsCheck
from .backup_check import BackupCheck

__all__ = [
    "SecurityCheck",
    "RootCheck",
    "SELinuxCheck",
    "AndroidVersionCheck",
    "USBDebugCheck",
    "SuspiciousAppsCheck",
    "PermissionsCheck",
    "EncryptionCheck",
    "ScreenLockCheck",
    "NetworkCheck",
    "PlayProtectCheck",
    "DeveloperOptionsCheck",
    "BackupCheck",
]

ANDROID_CHECKS = [
    RootCheck,
    SELinuxCheck,
    AndroidVersionCheck,
    USBDebugCheck,
    SuspiciousAppsCheck,
    PermissionsCheck,
    EncryptionCheck,
    ScreenLockCheck,
    NetworkCheck,
    PlayProtectCheck,
    DeveloperOptionsCheck,
    BackupCheck,
]

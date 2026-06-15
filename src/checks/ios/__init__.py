from .ios_version_check import IOSVersionCheck
from .jailbreak_check import JailbreakCheck
from .icloud_check import ICloudCheck
from .passcode_check import IosPasscodeCheck
from .encryption_check import IosEncryptionCheck
from .app_permissions_check import IosAppPermissionsCheck
from .backup_check import IosBackupCheck

__all__ = [
    "IOSVersionCheck",
    "JailbreakCheck",
    "ICloudCheck",
    "IosPasscodeCheck",
    "IosEncryptionCheck",
    "IosAppPermissionsCheck",
    "IosBackupCheck",
]

IOS_CHECKS = [
    IOSVersionCheck,
    JailbreakCheck,
    ICloudCheck,
    IosPasscodeCheck,
    IosEncryptionCheck,
    IosAppPermissionsCheck,
    IosBackupCheck,
]

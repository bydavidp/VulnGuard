"""
Tests para los checks de seguridad.
"""

from unittest.mock import patch, MagicMock
import subprocess

from src.checks.android.root_check import RootCheck
from src.checks.android.selinux_check import SELinuxCheck
from src.checks.android.android_version_check import AndroidVersionCheck
from src.checks.android.usb_debug_check import USBDebugCheck
from src.core.enums import CheckStatus


class TestRootCheck:
    def test_check_metadata(self):
        check = RootCheck()
        assert check.check_id == "root_detection"
        assert "root" in check.check_name.lower()

    def _make_mock_run(self, which_su_return, test_f_exception, id_return,
                       build_tags_return, pm_return):
        """Crea un side_effect function para simular subprocess.run con múltiples llamadas."""
        from unittest.mock import MagicMock

        # root_check.py llama: which su, test -f x8, id, getprop, pm list
        # = 12 llamadas en total
        su_path_count = 8  # len(SU_PATHS)

        calls = []
        # 1. which su
        calls.append(MagicMock(returncode=which_su_return["rc"], stdout=which_su_return["out"]))
        # 2. test -f (8 paths)
        for _ in range(su_path_count):
            calls.append(test_f_exception)
        # 3. id
        calls.append(MagicMock(returncode=id_return["rc"], stdout=id_return["out"]))
        # 4. getprop ro.build.tags
        calls.append(MagicMock(returncode=build_tags_return["rc"], stdout=build_tags_return["out"]))
        # 5. pm list packages
        calls.append(MagicMock(returncode=pm_return["rc"], stdout=pm_return["out"]))

        return calls

    @patch("subprocess.run")
    def test_no_root_detected(self, mock_run):
        """Simula que no hay root."""
        mock_run.side_effect = self._make_mock_run(
            which_su_return={"rc": 1, "out": ""},
            test_f_exception=FileNotFoundError(),
            id_return={"rc": 0, "out": "uid=1000"},
            build_tags_return={"rc": 0, "out": "release-keys"},
            pm_return={"rc": 0, "out": "package:com.android.chrome"},
        )

        check = RootCheck()
        result = check._run()
        assert result.status == CheckStatus.PASSED

    @patch("subprocess.run")
    def test_root_detected(self, mock_run):
        """Simula que hay root."""
        mock_run.side_effect = self._make_mock_run(
            which_su_return={"rc": 0, "out": "/system/bin/su"},
            test_f_exception=FileNotFoundError(),
            id_return={"rc": 0, "out": "uid=0(root)"},
            build_tags_return={"rc": 0, "out": "test-keys"},
            pm_return={"rc": 0, "out": "package:com.magisk"},
        )

        check = RootCheck()
        result = check._run()
        assert result.status == CheckStatus.FAILED
        assert len(result.vulnerabilities) > 0


class TestSELinuxCheck:
    def test_check_metadata(self):
        check = SELinuxCheck()
        assert check.check_id == "selinux_status"
        assert "selinux" in check.check_name.lower()

    @patch("subprocess.run")
    def test_enforcing(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Enforcing")
        check = SELinuxCheck()
        result = check._run()
        assert result.status == CheckStatus.PASSED
        assert "Enforcing" in result.detail

    @patch("subprocess.run")
    def test_permissive(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Permissive")
        check = SELinuxCheck()
        result = check._run()
        assert result.status == CheckStatus.FAILED
        assert "Permissive" in result.detail

    @patch("subprocess.run")
    def test_disabled(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Disabled")
        check = SELinuxCheck()
        result = check._run()
        assert result.status == CheckStatus.FAILED
        assert result.severity.value == "CRITICAL"


class TestAndroidVersionCheck:
    def test_check_metadata(self):
        check = AndroidVersionCheck()
        assert check.check_id == "android_version"
        assert "versión" in check.check_name.lower()

    @patch("subprocess.run")
    def test_modern_android(self, mock_run):
        """Android 14 con parche reciente."""
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "ro.build.version.release" in cmd:
                return MagicMock(returncode=0, stdout="14")
            elif "ro.build.version.sdk" in cmd:
                return MagicMock(returncode=0, stdout="34")
            elif "ro.build.version.security_patch" in cmd:
                return MagicMock(returncode=0, stdout="2024-01-01")
            elif "ro.build.fingerprint" in cmd:
                return MagicMock(returncode=0, stdout="google/pixel/14")
            return MagicMock(returncode=0, stdout="")
        mock_run.side_effect = side_effect

        check = AndroidVersionCheck()
        result = check._run()
        assert result.status == CheckStatus.PASSED
        assert "14" in result.detail

    @patch("subprocess.run")
    def test_outdated_android(self, mock_run):
        """Android 6 desactualizado."""
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "ro.build.version.release" in cmd:
                return MagicMock(returncode=0, stdout="6.0.1")
            elif "ro.build.version.sdk" in cmd:
                return MagicMock(returncode=0, stdout="23")
            elif "ro.build.version.security_patch" in cmd:
                return MagicMock(returncode=0, stdout="2018-03-01")
            elif "ro.build.fingerprint" in cmd:
                return MagicMock(returncode=0, stdout="htc/m8/6.0")
            return MagicMock(returncode=0, stdout="")
        mock_run.side_effect = side_effect

        check = AndroidVersionCheck()
        result = check._run()
        assert result.status == CheckStatus.FAILED
        assert len(result.vulnerabilities) > 0


class TestUSBDebugCheck:
    def test_check_metadata(self):
        check = USBDebugCheck()
        assert check.check_id == "usb_debugging"
        assert "usb" in check.check_name.lower()

    @patch("subprocess.run")
    def test_debug_disabled(self, mock_run):
        """USB Debugging deshabilitado."""
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "adb_enabled" in cmd:
                return MagicMock(returncode=0, stdout="0")
            elif "persist.adb.tcp.port" in cmd:
                return MagicMock(returncode=0, stdout="")
            elif "netstat" in cmd:
                return MagicMock(returncode=0, stdout="")
            return MagicMock(returncode=0, stdout="")
        mock_run.side_effect = side_effect

        check = USBDebugCheck()
        result = check._run()
        assert result.status == CheckStatus.PASSED


class TestCheckRegistration:
    def test_all_checks_have_unique_ids(self):
        """Todos los checks deben tener IDs únicos."""
        from src.checks import list_all_checks
        ids = [c.check_id for c in list_all_checks()]
        assert len(ids) == len(set(ids)), f"IDs duplicados: {ids}"

    def test_all_checks_have_required_attributes(self):
        """Todos los checks deben tener check_id, check_name, description."""
        from src.checks import list_all_checks
        for check_class in list_all_checks():
            check = check_class()
            assert check.check_id, f"{check_class.__name__} sin check_id"
            assert check.check_name, f"{check_class.__name__} sin check_name"
            assert check.description, f"{check_class.__name__} sin description"
            assert check.severity, f"{check_class.__name__} sin severity"

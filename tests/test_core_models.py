"""
Tests para los modelos de dominio del core.
"""

from src.core.enums import Severity, CheckStatus, RiskLevel
from src.core.models import (
    SecurityCheckResult,
    DeviceInfo,
    AuditReport,
    Vulnerability,
)
from src.core.risk_score import RiskScoreCalculator


class TestSeverity:
    def test_score_values(self):
        assert Severity.CRITICAL.score == 10
        assert Severity.HIGH.score == 7
        assert Severity.MEDIUM.score == 5
        assert Severity.LOW.score == 3
        assert Severity.INFO.score == 1
        assert Severity.OK.score == 0

    def test_color_values(self):
        assert Severity.CRITICAL.color == "red"
        assert Severity.HIGH.color == "orange"
        assert Severity.OK.color == "green"


class TestCheckStatus:
    def test_vulnerable_states(self):
        failed = SecurityCheckResult(
            check_id="test", check_name="Test",
            status=CheckStatus.FAILED,
        )
        assert failed.is_vulnerable

        warning = SecurityCheckResult(
            check_id="test", check_name="Test",
            status=CheckStatus.WARNING,
        )
        assert warning.is_vulnerable

        passed = SecurityCheckResult(
            check_id="test", check_name="Test",
            status=CheckStatus.PASSED,
        )
        assert not passed.is_vulnerable

    def test_risk_score_calculation(self):
        critical = SecurityCheckResult(
            check_id="test", check_name="Test",
            status=CheckStatus.FAILED,
            severity=Severity.CRITICAL,
        )
        assert critical.risk_score == 100  # 10 * 10

        ok = SecurityCheckResult(
            check_id="test", check_name="Test",
            status=CheckStatus.PASSED,
            severity=Severity.OK,
        )
        assert ok.risk_score == 0

    def test_to_dict(self):
        result = SecurityCheckResult(
            check_id="test_root",
            check_name="Root Check",
            status=CheckStatus.PASSED,
            detail="No root found",
        )
        data = result.to_dict()
        assert data["check_id"] == "test_root"
        assert data["status"] == "PASSED"
        assert not data["vulnerable"]


class TestVulnerability:
    def test_create_vulnerability(self):
        vuln = Vulnerability(
            name="Test Vuln",
            severity=Severity.HIGH,
            description="Test description",
            recommendation="Fix it",
            cvss_score=7.5,
            cwe_id="CWE-200",
        )
        assert vuln.name == "Test Vuln"
        assert vuln.severity == Severity.HIGH
        assert vuln.cvss_score == 7.5
        assert vuln.cwe_id == "CWE-200"


class TestDeviceInfo:
    def test_default_values(self):
        info = DeviceInfo()
        assert info.device_id == ""
        assert info.model == ""
        assert info.android_version == ""

    def test_to_dict(self):
        info = DeviceInfo(
            model="Pixel 7",
            manufacturer="Google",
            android_version="14",
        )
        data = info.to_dict()
        assert data["model"] == "Pixel 7"
        assert data["manufacturer"] == "Google"


class TestAuditReport:
    def test_empty_report(self):
        report = AuditReport()
        assert report.total_checks == 0
        assert report.risk_score == 0
        assert report.risk_level == RiskLevel.SAFE

    def test_add_result(self):
        report = AuditReport()
        result = SecurityCheckResult(
            check_id="test", check_name="Test",
            status=CheckStatus.PASSED,
        )
        report.add_result(result)
        assert report.total_checks == 1
        assert report.passed_checks == 1

    def test_calculate_risk_all_safe(self):
        report = AuditReport()
        report.add_result(SecurityCheckResult(
            check_id="test1", check_name="Test1",
            status=CheckStatus.PASSED, severity=Severity.OK,
        ))
        report.add_result(SecurityCheckResult(
            check_id="test2", check_name="Test2",
            status=CheckStatus.PASSED, severity=Severity.OK,
        ))
        report.calculate_risk()
        assert report.risk_score == 0
        assert report.risk_level == RiskLevel.SAFE

    def test_calculate_risk_with_vulnerabilities(self):
        report = AuditReport()
        report.add_result(SecurityCheckResult(
            check_id="critical", check_name="Critical",
            status=CheckStatus.FAILED, severity=Severity.CRITICAL,
        ))
        report.add_result(SecurityCheckResult(
            check_id="safe", check_name="Safe",
            status=CheckStatus.PASSED, severity=Severity.OK,
        ))
        report.calculate_risk()
        assert report.risk_score > 0
        assert report.failed_checks == 1
        assert report.passed_checks == 1


class TestRiskScoreCalculator:
    def test_no_results(self):
        metrics = RiskScoreCalculator.calculate_all([])
        assert metrics["final_score"] == 0
        assert metrics["risk_level"].value == "SEGURO"

    def test_all_secure(self):
        results = [
            SecurityCheckResult(
                check_id="ok1", check_name="OK1",
                status=CheckStatus.PASSED, severity=Severity.OK,
            ),
        ]
        metrics = RiskScoreCalculator.calculate_all(results)
        assert metrics["final_score"] == 0
        assert metrics["base_score"] == 0
        assert metrics["impact_score"] == 0

    def test_critical_finding(self):
        results = [
            SecurityCheckResult(
                check_id="critical", check_name="Critical",
                status=CheckStatus.FAILED, severity=Severity.CRITICAL,
            ),
        ]
        metrics = RiskScoreCalculator.calculate_all(results)
        assert metrics["base_score"] > 0  # Una vulnerabilidad crítica genera puntaje
        assert metrics["final_score"] > 0

    def test_risk_levels(self):
        assert RiskScoreCalculator.get_risk_level(85) == RiskLevel.CRITICAL
        assert RiskScoreCalculator.get_risk_level(70) == RiskLevel.HIGH
        assert RiskScoreCalculator.get_risk_level(50) == RiskLevel.MEDIUM
        assert RiskScoreCalculator.get_risk_level(30) == RiskLevel.LOW
        assert RiskScoreCalculator.get_risk_level(10) == RiskLevel.SAFE

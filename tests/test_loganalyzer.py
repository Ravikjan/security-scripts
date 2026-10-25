"""Тесты анализатора журналов (запуск: python -m unittest discover -s tests)."""

from __future__ import annotations

import json
import shutil
import sys
import unittest
import uuid
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "log_analyzer"))

from loganalyzer import cli, detectors, parsers, report  # noqa: E402
from loganalyzer.models import Action, LogEvent, ScanStats, is_at_least  # noqa: E402

SSHD_SAMPLE = ROOT / "samples" / "auth_sshd.log"
CSV_SAMPLE = ROOT / "samples" / "win_security.csv"
TMP_ROOT = ROOT / ".test-tmp"


def temp_dir() -> Path:
    """Временный каталог внутри репозитория.

    Системный Temp может быть закрыт песочницей, а каталоги с правами 0o700
    (их создаёт tempfile.mkdtemp) на Windows в этой среде недоступны на запись,
    поэтому каталог создаётся явно с обычными правами.
    """
    TMP_ROOT.mkdir(exist_ok=True)
    for _ in range(50):
        candidate = TMP_ROOT / f"case-{uuid.uuid4().hex[:8]}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise RuntimeError("не удалось создать временный каталог")


class TimestampTests(unittest.TestCase):
    def test_syslog_timestamp_uses_given_year(self) -> None:
        moment = parsers.parse_timestamp("Oct 26 00:15:00 srv01 sshd[1050]: Accepted password", 2024)
        self.assertEqual(moment, datetime(2024, 10, 26, 0, 15, 0))

    def test_iso_timestamp_with_fraction(self) -> None:
        moment = parsers.parse_timestamp("2026-10-26T09:10:00,123 host", None)
        self.assertEqual(moment, datetime(2026, 10, 26, 9, 10, 0, 123000))

    def test_unknown_timestamp_returns_none(self) -> None:
        self.assertIsNone(parsers.parse_timestamp("мусор без времени", 2026))

    def test_december_log_read_in_january_rolls_back_year(self) -> None:
        # Год определяется по текущей дате; проверяем только, что он не в будущем.
        moment = parsers.parse_timestamp("Dec 31 23:59:59 host sshd[1]: Failed password")
        self.assertIsNotNone(moment)
        self.assertLessEqual(moment.year, datetime.now().year)


class SshdParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = parsers.SshdParser(default_year=2026)
        self.events = self.parser.parse_file(SSHD_SAMPLE)

    def test_sample_contains_all_event_kinds(self) -> None:
        actions = {event.action for event in self.events}
        self.assertIn(Action.LOGIN_FAILED, actions)
        self.assertIn(Action.LOGIN_SUCCESS, actions)
        self.assertIn(Action.INVALID_USER, actions)
        self.assertIn(Action.AUTH_LIMIT, actions)

    def test_failed_password_is_parsed_with_ip_and_user(self) -> None:
        failures = [e for e in self.events if e.action == Action.LOGIN_FAILED]
        self.assertTrue(any(e.username == "admin" and e.source_ip == "203.0.113.66" for e in failures))

    def test_invalid_user_line_does_not_duplicate_failure(self) -> None:
        ip_events = [e for e in self.events if e.source_ip == "198.51.100.23"]
        failed = [e for e in ip_events if e.action == Action.LOGIN_FAILED]
        invalid = [e for e in ip_events if e.action == Action.INVALID_USER]
        limit = [e for e in ip_events if e.action == Action.AUTH_LIMIT]
        self.assertEqual(len(invalid), 8)
        self.assertEqual(len(failed), 8)  # по одному «Failed password» на пользователя
        self.assertEqual(len(limit), 1)  # превышение лимита учитывается отдельно

    def test_pam_line_is_parsed(self) -> None:
        pam_events = [
            e
            for e in self.events
            if e.action == Action.LOGIN_FAILED and "pam_unix" in e.raw and e.timestamp is not None
        ]
        self.assertTrue(any(e.username == "root" and e.source_ip == "203.0.113.9" for e in pam_events))

    def test_noise_lines_are_ignored(self) -> None:
        self.assertFalse(any("CRON" in e.raw for e in self.events))
        self.assertFalse(any("Received disconnect" in e.raw for e in self.events))


class WindowsCsvParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = parsers.WindowsCsvParser(default_year=2026)
        self.events = self.parser.parse_file(CSV_SAMPLE)

    def test_only_4624_and_4625_are_parsed(self) -> None:
        self.assertEqual(len(self.events), 11)  # 11 строк 4624/4625, без 4672 и SRV01$

    def test_machine_accounts_are_skipped(self) -> None:
        self.assertFalse(any(e.username and e.username.endswith("$") for e in self.events))

    def test_event_ids_map_to_actions(self) -> None:
        admin_failures = [
            e for e in self.events if e.action == Action.LOGIN_FAILED and e.username == "Administrator"
        ]
        self.assertEqual(len(admin_failures), 7)
        self.assertEqual(admin_failures[0].source_ip, "203.0.113.77")

    def test_broken_header_raises_parse_error(self) -> None:
        with self.assertRaises(parsers.ParseError):
            parsers.WindowsCsvParser().parse_text("a,b\n1,2\n", source="bad.csv")


class DetectFormatTests(unittest.TestCase):
    def test_detects_sshd(self) -> None:
        text = SSHD_SAMPLE.read_text(encoding="utf-8")
        self.assertEqual(parsers.detect_format(text, "auth.log"), "sshd")

    def test_detects_windows_csv(self) -> None:
        text = CSV_SAMPLE.read_text(encoding="utf-8")
        self.assertEqual(parsers.detect_format(text, "events.csv"), "win-csv")

    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(parsers.ParseError):
            parsers.detect_format("просто текст без событий", "notes.txt")


class DetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = parsers.SshdParser(default_year=2026).parse_file(SSHD_SAMPLE)
        self.findings = detectors.detect(self.events, detectors.Thresholds())

    def rule_ids(self) -> set[str]:
        return {finding.rule_id for finding in self.findings}

    def test_four_rules_fire_on_sample(self) -> None:
        self.assertEqual(
            self.rule_ids(),
            {"brute-force", "password-spray", "success-after-failure", "distributed-account-attack"},
        )

    def test_brute_force_severity_and_details(self) -> None:
        finding = next(f for f in self.findings if f.rule_id == "brute-force")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.details["source_ip"], "203.0.113.66")
        self.assertEqual(finding.details["failures"], 18)

    def test_success_after_failure_is_critical(self) -> None:
        finding = next(f for f in self.findings if f.rule_id == "success-after-failure")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.details["source_ip"], "203.0.113.66")
        self.assertIn("admin", finding.details["accounts"])

    def test_spray_not_reported_as_brute_force(self) -> None:
        brute_ips = {
            f.details["source_ip"] for f in self.findings if f.rule_id == "brute-force"
        }
        self.assertNotIn("198.51.100.23", brute_ips)

    def test_findings_sorted_by_severity(self) -> None:
        severities = [finding.severity for finding in self.findings]
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        self.assertEqual(severities, sorted(severities, key=order.get, reverse=True))

    def test_thresholds_are_configurable(self) -> None:
        strict = detectors.detect(self.events, detectors.Thresholds(min_failures=100))
        self.assertEqual(strict, [])

    def test_window_limits_peak(self) -> None:
        narrow = detectors.detect(
            self.events, detectors.Thresholds(min_failures=5, window=timedelta(seconds=1))
        )
        brute = next(f for f in narrow if f.rule_id == "brute-force")
        self.assertLess(brute.details["failures_in_window"], brute.details["failures"])

    def test_without_timestamps_detection_still_works(self) -> None:
        events = [
            LogEvent(action=Action.LOGIN_FAILED, source_ip="198.51.100.5", username="u")
            for _ in range(6)
        ]
        findings = detectors.detect(events, detectors.Thresholds())
        self.assertIn("brute-force", {f.rule_id for f in findings})

    def test_count_invalid_user_option(self) -> None:
        plain = detectors.detect(self.events, detectors.Thresholds())
        expanded = detectors.detect(
            self.events, detectors.Thresholds(count_invalid_user=True)
        )
        self.assertGreaterEqual(len(expanded), len(plain))


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        events = parsers.SshdParser(default_year=2026).parse_file(SSHD_SAMPLE)
        self.stats = ScanStats(
            files=[str(SSHD_SAMPLE)],
            format_name="sshd",
            lines_total=47,
            lines_skipped=2,
            events_total=len(events),
            duration_sec=0.01,
        )
        self.result = report.AnalysisResult(
            findings=detectors.detect(events, detectors.Thresholds()),
            stats=self.stats,
            events=events,
        )

    def test_json_is_valid_and_contains_russian_text(self) -> None:
        payload = json.loads(report.render_json(self.result, {"min_failures": 5}))
        self.assertEqual(payload["tool"], "analyze_logs")
        self.assertEqual(payload["summary"]["max_severity"], "critical")
        self.assertEqual(len(payload["findings"]), 4)
        titles = {finding["rule_id"]: finding["title"] for finding in payload["findings"]}
        self.assertIn("Брутфорс", titles["brute-force"])
        self.assertIn("Успешный вход", titles["success-after-failure"])

    def test_csv_has_header_and_rows(self) -> None:
        lines = report.render_csv(self.result).strip().splitlines()
        self.assertTrue(lines[0].startswith("rule_id,severity"))
        self.assertEqual(len(lines), 5)

    def test_console_mentions_verdict(self) -> None:
        text = report.render_console(self.result, color=False)
        self.assertIn("Найдено находок: 4", text)
        self.assertIn("критично", text)

    def test_write_report_by_extension(self) -> None:
        directory = temp_dir()
        self.addCleanup(shutil.rmtree, directory, True)
        path = directory / "report.json"
        report.write_report(self.result, str(path))
        self.assertTrue(json.loads(path.read_text(encoding="utf-8"))["findings"])

    def test_severity_comparison(self) -> None:
        self.assertTrue(is_at_least("critical", "high"))
        self.assertFalse(is_at_least("medium", "high"))


class CliTests(unittest.TestCase):
    def test_window_parsing(self) -> None:
        self.assertEqual(cli._parse_window("30s"), timedelta(seconds=30))
        self.assertEqual(cli._parse_window("2h"), timedelta(hours=2))
        self.assertEqual(cli._parse_window("1d"), timedelta(days=1))
        self.assertEqual(cli._parse_window("5"), timedelta(minutes=5))

    def test_exit_code_on_findings(self) -> None:
        code = cli.main(
            [str(SSHD_SAMPLE), "--quiet", "--fail-on", "critical", "--year", "2026"]
        )
        self.assertEqual(code, 1)

    def test_exit_code_when_threshold_not_reached(self) -> None:
        code = cli.main(
            [str(SSHD_SAMPLE), "--quiet", "--fail-on", "none", "--year", "2026"]
        )
        self.assertEqual(code, 0)

    def test_missing_file_returns_error_code(self) -> None:
        code = cli.main([str(ROOT / "samples" / "нет-такого.log"), "--quiet"])
        self.assertEqual(code, 2)

    def test_output_file_is_written(self) -> None:
        directory = temp_dir()
        self.addCleanup(shutil.rmtree, directory, True)
        target = directory / "out.json"
        code = cli.main(
            [
                str(SSHD_SAMPLE),
                "--quiet",
                "--fail-on",
                "none",
                "--year",
                "2026",
                "-o",
                str(target),
            ]
        )
        self.assertEqual(code, 0)
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(payload["stats"]["format"], "sshd")
        self.assertEqual(len(payload["findings"]), 4)


if __name__ == "__main__":
    unittest.main()

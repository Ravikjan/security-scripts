"""Тесты извлекателя индикаторов компрометации."""

from __future__ import annotations

import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ioc_extractor"))

import extract_iocs  # noqa: E402

SAMPLE = ROOT / "samples" / "threat_report.txt"
TMP_ROOT = ROOT / ".test-tmp"


def temp_dir() -> Path:
    TMP_ROOT.mkdir(exist_ok=True)
    for _ in range(50):
        candidate = TMP_ROOT / f"ioc-{uuid.uuid4().hex[:8]}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise RuntimeError("не удалось создать временный каталог")


class ExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SAMPLE.read_text(encoding="utf-8")
        self.indicators = extract_iocs.extract_indicators(self.text, extract_iocs.Options())

    def test_ipv4_including_private_by_default(self) -> None:
        self.assertEqual(
            self.indicators["ipv4"],
            ["8.8.8.8", "10.20.30.40", "127.0.0.1", "192.168.1.1", "203.0.113.200", "203.0.113.201"],
        )

    def test_ipv6_addresses(self) -> None:
        self.assertEqual(self.indicators["ipv6"], ["2001:db8::42", "fe80::1"])

    def test_domains_exclude_file_extensions(self) -> None:
        self.assertIn("bad-host.test", self.indicators["domain"])
        self.assertIn("login.evil-c2.example", self.indicators["domain"])
        self.assertIn("update-checker.co", self.indicators["domain"])
        self.assertNotIn("implant.bin", self.indicators["domain"])
        self.assertNotIn("report.log", self.indicators["domain"])

    def test_urls(self) -> None:
        self.assertIn("http://203.0.113.200/implant.bin", self.indicators["url"])
        self.assertIn(
            "https://login.evil-c2.example/pay?user=1&token=abc", self.indicators["url"]
        )

    def test_hashes_of_each_length(self) -> None:
        self.assertEqual(self.indicators["md5"], ["d41d8cd98f00b204e9800998ecf8427e"])
        self.assertEqual(self.indicators["sha1"], ["da39a3ee5e6b4b0d3255bfef95601890afd80709"])
        self.assertEqual(
            self.indicators["sha256"],
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        )

    def test_email(self) -> None:
        self.assertEqual(self.indicators["email"], ["attacker@evil-c2.example"])

    def test_guid_is_not_a_hash(self) -> None:
        guids = [
            value
            for name in ("md5", "sha1", "sha256")
            for value in self.indicators[name]
            if value.startswith("550e8400")
        ]
        self.assertEqual(guids, [])

    def test_exclude_private(self) -> None:
        options = extract_iocs.Options(exclude_private=True)
        indicators = extract_iocs.extract_indicators(self.text, options)
        self.assertEqual(indicators["ipv4"], ["8.8.8.8"])
        self.assertEqual(indicators["ipv6"], [])

    def test_allowlist(self) -> None:
        options = extract_iocs.Options(allowlist={"8.8.8.8", "bad-host.test"})
        indicators = extract_iocs.extract_indicators(self.text, options)
        self.assertNotIn("8.8.8.8", indicators["ipv4"])
        self.assertNotIn("bad-host.test", indicators["domain"])

    def test_refang_input_restores_defanged_indicators(self) -> None:
        options = extract_iocs.Options(refang_input=True)
        indicators = extract_iocs.extract_indicators(self.text, options)
        self.assertIn("203.0.113.250", indicators["ipv4"])
        self.assertIn("evil-c2.example", indicators["domain"])
        self.assertIn("https://evil-c2.example/drop", indicators["url"])

    def test_types_filter(self) -> None:
        options = extract_iocs.Options(types=("ipv4",))
        indicators = extract_iocs.extract_indicators(self.text, options)
        self.assertEqual(list(indicators), ["ipv4"])

    def test_empty_text(self) -> None:
        indicators = extract_iocs.extract_indicators("просто текст без индикаторов")
        self.assertEqual(indicators, {name: [] for name in extract_iocs.ALL_TYPES})

    def test_defang_and_refang_helpers(self) -> None:
        self.assertEqual(extract_iocs.defang("203.0.113.5"), "203[.]0[.]113[.]5")
        self.assertEqual(extract_iocs.defang("https://evil.example"), "hxxps://evil[.]example")
        self.assertEqual(
            extract_iocs.refang("hxxps://evil[.]example/1[.]2[.]3[.]4"),
            "https://evil.example/1.2.3.4",
        )


class CliTests(unittest.TestCase):
    def test_json_output(self) -> None:
        directory = temp_dir()
        self.addCleanup(shutil.rmtree, directory, True)
        target = directory / "iocs.json"
        code = extract_iocs.main([str(SAMPLE), "--quiet", "-o", str(target)])
        self.assertEqual(code, 0)
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "extract_iocs")
        self.assertGreater(payload["stats"]["indicators"], 10)

    def test_csv_output(self) -> None:
        directory = temp_dir()
        self.addCleanup(shutil.rmtree, directory, True)
        target = directory / "iocs.csv"
        extract_iocs.main([str(SAMPLE), "--quiet", "-o", str(target), "--types", "ipv4"])
        lines = target.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(lines[0], "type,value")
        self.assertEqual(len(lines), 7)  # заголовок + 6 IPv4

    def test_fail_on_ioc(self) -> None:
        self.assertEqual(extract_iocs.main([str(SAMPLE), "--quiet", "--fail-on-ioc"]), 1)

    def test_missing_file(self) -> None:
        self.assertEqual(
            extract_iocs.main([str(ROOT / "samples" / "нет.txt"), "--quiet"]), 2
        )

    def test_unknown_type_is_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            extract_iocs.main([str(SAMPLE), "--types", "ipv4,домены", "--quiet"])


if __name__ == "__main__":
    unittest.main()

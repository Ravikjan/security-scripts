#!/usr/bin/env python3
"""Извлечение индикаторов компрометации (IOC) из текста.

Скрипт находит IPv4/IPv6-адреса, домены, URL, хеши файлов и адреса почты,
умеет отбрасывать приватные адреса, применять белый список и «дефанжить»
результат перед публикацией отчёта.

Примеры:
    python extract_iocs.py samples/threat_report.txt
    python extract_iocs.py report.txt --exclude-private --defang -o iocs.json
    python extract_iocs.py "reports/*.txt" --json iocs.json --fail-on-ioc

Подробности — в docs/04-ИНДИКАТОРЫ.md.
"""

from __future__ import annotations

import argparse
import csv
import glob
import io
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

__version__ = "0.1.0"

ALL_TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email")

TYPE_RU = {
    "ipv4": "IPv4-адреса",
    "ipv6": "IPv6-адреса",
    "domain": "домены",
    "url": "URL",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "email": "адреса почты",
}

# Расширения файлов и служебные «домены», которые не являются индикаторами.
FALSE_TLDS = {
    "exe", "dll", "sys", "drv", "msi", "bat", "cmd", "ps1", "psm1", "vbs", "js",
    "py", "pyc", "jar", "war", "class", "so", "o", "a", "lib", "obj", "pdb",
    "txt", "log", "md", "rst", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
    "csv", "tsv", "xls", "xlsx", "doc", "docx", "ppt", "pptx", "pdf", "rtf",
    "html", "htm", "css", "scss", "less", "vue", "ts", "tsx", "jsx", "map",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
    "zip", "rar", "7z", "gz", "tar", "bz2", "xz", "cab", "iso", "img",
    "db", "sql", "bak", "tmp", "temp", "old", "orig", "rej", "swp", "pid",
    "lock", "cache", "part", "crdownload", "download", "out", "err", "dat",
    "bin", "hex", "dmp", "etl", "evtx", "pcap", "rules", "sig", "key", "crt",
    "pem", "pfx", "p12", "cer", "der",
}

DOMAIN_STOPLIST = {"localhost", "localhost.localdomain", "local"}

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:.])")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\[\]{}|\\^]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)

HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


@dataclass
class Options:
    """Настройки извлечения."""

    exclude_private: bool = False
    refang_input: bool = False
    defang: bool = False
    types: tuple[str, ...] = ALL_TYPES
    allowlist: set[str] = field(default_factory=set)


@dataclass
class Report:
    """Результат извлечения."""

    indicators: dict[str, list[str]]
    sources: list[str]
    text_size: int

    @property
    def total(self) -> int:
        return sum(len(values) for values in self.indicators.values())


def refang(text: str) -> str:
    """Возвращает текст с «раздефанженными» индикаторами."""
    text = re.sub(r"hxxps?", lambda m: m.group(0).replace("xx", "tt"), text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    text = text.replace("[@]", "@").replace("[at]", "@")
    return text


def defang(value: str) -> str:
    """Делает индикатор безопасным для публикации в отчёте."""
    result = value.replace(".", "[.]")
    result = re.sub(r"^http", "hxxp", result, flags=re.IGNORECASE)
    result = result.replace("@", "[@]")
    return result


def _is_public_ip(address: ipaddress._BaseAddress) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _clean_url(url: str) -> str:
    """Обрезает хвостовую пунктуацию, не являющуюся частью URL."""
    return url.rstrip(".,;:!?»\"')")


def _looks_like_domain(value: str) -> bool:
    lowered = value.lower().rstrip(".")
    if lowered in DOMAIN_STOPLIST:
        return False
    tld = lowered.rsplit(".", 1)[-1]
    if tld in FALSE_TLDS:
        return False
    if len(lowered.split(".")[0]) == 0:
        return False
    return True


def _sorted_ips(values: Iterable[str]) -> list[str]:
    def key(value: str) -> tuple[int, ipaddress._BaseAddress]:
        address = ipaddress.ip_address(value)
        return (address.version, address)

    unique = {ipaddress.ip_address(value) for value in values}
    return [str(address) for address in sorted(unique, key=key)]


def extract_indicators(text: str, options: Options | None = None) -> dict[str, list[str]]:
    """Находит индикаторы в тексте и возвращает словарь «тип → отсортированные значения»."""
    options = options or Options()
    if options.refang_input:
        text = refang(text)

    result: dict[str, list[str]] = {name: [] for name in ALL_TYPES}

    # IPv4
    if "ipv4" in options.types:
        found = set()
        for match in IPV4_RE.finditer(text):
            candidate = match.group(0)
            try:
                address = ipaddress.IPv4Address(candidate)
            except ValueError:
                continue
            if options.exclude_private and not _is_public_ip(address):
                continue
            found.add(str(address))
        result["ipv4"] = _sorted_ips(found)

    # IPv6
    if "ipv6" in options.types:
        found = set()
        for match in IPV6_CANDIDATE_RE.finditer(text):
            candidate = match.group(0).strip(":")
            if ":" not in candidate:
                continue
            try:
                address = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            if options.exclude_private and not _is_public_ip(address):
                continue
            found.add(str(address))
        result["ipv6"] = _sorted_ips(found)

    # URL — до доменов, чтобы не разрывать ссылки
    if "url" in options.types:
        urls = set()
        for match in URL_RE.finditer(text):
            url = _clean_url(match.group(0))
            if url and len(url) > 8:
                urls.add(url)
        result["url"] = sorted(urls)

    # Домены
    if "domain" in options.types:
        domains = set()
        for match in DOMAIN_RE.finditer(text):
            domain = match.group(0).lower().rstrip(".")
            if _looks_like_domain(domain):
                domains.add(domain)
        result["domain"] = sorted(domains)

    # Адреса почты
    if "email" in options.types:
        emails = set()
        for match in EMAIL_RE.finditer(text):
            email = match.group(0).lower()
            if _looks_like_domain(email.rsplit("@", 1)[-1]):
                emails.add(email)
        result["email"] = sorted(emails)

    # Хеши: сначала длинные, чтобы 64-символьный не попал в MD5
    working = text
    for name in ("sha256", "sha1", "md5"):
        if name not in options.types:
            continue
        length = HASH_LENGTHS[name]
        pattern = re.compile(
            rf"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{{{length}}})(?![0-9A-Fa-f])"
        )
        found = set()
        for match in pattern.finditer(working):
            found.add(match.group(0).lower())
        result[name] = sorted(found)
        working = pattern.sub(" ", working)

    # Белый список применяется к любым типам
    if options.allowlist:
        allowed = {item.lower() for item in options.allowlist}
        for name, values in result.items():
            result[name] = [value for value in values if value.lower() not in allowed]

    return {name: values for name, values in result.items() if name in options.types}


def read_source(path: str) -> str:
    """Читает файл или stdin с подбором кодировки."""
    if path == "-":
        return sys.stdin.read()
    data = Path(path).read_bytes()
    for encoding in ("utf-8-sig", "cp1251", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def render_console(report: Report, use_defang: bool) -> str:
    """Текстовый отчёт для человека."""
    lines = ["=" * 70, " Извлечение индикаторов компрометации", "=" * 70]
    lines.append(f"Источники:  {', '.join(report.sources) or '—'}")
    lines.append(f"Объём:      {report.text_size} байт")
    lines.append(f"Индикаторов: {report.total}")
    lines.append("")

    if report.total == 0:
        lines.append("Индикаторов не найдено.")
        return "\n".join(lines)

    for name in ALL_TYPES:
        values = report.indicators.get(name) or []
        if not values:
            continue
        lines.append(f"{TYPE_RU[name]} ({len(values)}):")
        for value in values:
            lines.append(f"  {defang(value) if use_defang else value}")
        lines.append("")
    return "\n".join(lines).rstrip()


def build_payload(report: Report) -> dict:
    """Структура JSON-отчёта."""
    return {
        "tool": "extract_iocs",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "sources": report.sources,
        "stats": {
            "bytes": report.text_size,
            "indicators": report.total,
            "by_type": {name: len(values) for name, values in report.indicators.items()},
        },
        "indicators": report.indicators,
    }


def render_csv(report: Report) -> str:
    """CSV-отчёт: одна строка на индикатор."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["type", "value"])
    for name in ALL_TYPES:
        for value in report.indicators.get(name) or []:
            writer.writerow([name, value])
    return buffer.getvalue()


def _expand_paths(patterns: list[str]) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        if pattern == "-":
            paths.append(pattern)
            continue
        if any(char in pattern for char in "*?["):
            matches = sorted(name for name in glob.glob(pattern, recursive=True) if Path(name).is_file())
            if not matches:
                raise FileNotFoundError(f"по шаблону «{pattern}» не найдено ни одного файла")
            paths.extend(matches)
            continue
        if not Path(pattern).is_file():
            raise FileNotFoundError(f"файл не найден: {pattern}")
        paths.append(pattern)
    unique: list[str] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="extract_iocs.py",
        description="Извлечение индикаторов компрометации (IP, домены, URL, хеши, почта).",
        epilog=(
            "Примеры:\n"
            "  python extract_iocs.py samples/threat_report.txt\n"
            "  python extract_iocs.py report.txt --exclude-private --defang -o iocs.json\n"
            '  python extract_iocs.py "reports/*.txt" -o iocs.csv --fail-on-ioc\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="+", metavar="ФАЙЛ", help="файл(ы) с текстом; «-» — stdin")
    parser.add_argument(
        "--types",
        default=",".join(ALL_TYPES),
        help=f"какие типы извлекать (по умолчанию все: {','.join(ALL_TYPES)})",
    )
    parser.add_argument(
        "--exclude-private",
        action="store_true",
        help="не включать приватные, петлевые и служебные адреса",
    )
    parser.add_argument(
        "--refang-input",
        action="store_true",
        help="сначала восстановить индикаторы вида 1[.]2[.]3[.]4 и hxxps://",
    )
    parser.add_argument(
        "--defang",
        action="store_true",
        help="выводить индикаторы в «безопасном» виде (1[.]2[.]3[.]4, hxxps://)",
    )
    parser.add_argument(
        "--allow",
        metavar="ФАЙЛ",
        help="файл со списком исключений (по одному индикатору в строке)",
    )
    parser.add_argument("-o", "--output", metavar="ФАЙЛ", help="сохранить отчёт: .json или .csv")
    parser.add_argument("--fail-on-ioc", action="store_true", help="код возврата 1, если что-то найдено")
    parser.add_argument("--quiet", action="store_true", help="не печатать отчёт в консоль")
    parser.add_argument("--no-color", action="store_true", help="отключить цвета")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    requested = tuple(part.strip().lower() for part in args.types.split(",") if part.strip())
    unknown = [name for name in requested if name not in ALL_TYPES]
    if unknown or not requested:
        parser.error(
            f"неизвестные типы: {', '.join(unknown) or '—'}. Доступны: {', '.join(ALL_TYPES)}"
        )

    allowlist: set[str] = set()
    if args.allow:
        try:
            allowlist = {
                line.strip()
                for line in read_source(args.allow).splitlines()
                if line.strip() and not line.strip().startswith("#")
            }
        except FileNotFoundError:
            print(f"Ошибка: файл исключений не найден: {args.allow}", file=sys.stderr)
            return 2

    try:
        paths = _expand_paths(args.paths)
    except FileNotFoundError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2

    options = Options(
        exclude_private=args.exclude_private,
        refang_input=args.refang_input,
        defang=args.defang,
        types=requested,
        allowlist=allowlist,
    )

    sources: list[str] = []
    chunks: list[str] = []
    size = 0
    try:
        for path in paths:
            text = read_source(path)
            chunks.append(text)
            size += len(text.encode("utf-8", errors="replace"))
            sources.append("<stdin>" if path == "-" else path)
    except OSError as error:
        print(f"Ошибка ввода-вывода: {error}", file=sys.stderr)
        return 2

    indicators = extract_indicators("\n".join(chunks), options)
    report = Report(indicators=indicators, sources=sources, text_size=size)

    if not args.quiet:
        print(render_console(report, args.defang))

    if args.output:
        try:
            if args.output.lower().endswith(".json"):
                content = json.dumps(build_payload(report), ensure_ascii=False, indent=2)
            elif args.output.lower().endswith(".csv"):
                content = render_csv(report)
            else:
                content = render_console(report, args.defang)
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content if content.endswith("\n") else content + "\n")
        except OSError as error:
            print(f"Не удалось записать отчёт: {error}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"Отчёт сохранён: {args.output}")

    if args.fail_on_ioc and report.total > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

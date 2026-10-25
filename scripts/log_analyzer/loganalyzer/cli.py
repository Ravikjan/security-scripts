"""Командная строка анализатора журналов."""

from __future__ import annotations

import argparse
import glob
import re
import sys
import time
from datetime import timedelta
from pathlib import Path

from . import __version__
from .detectors import Thresholds, detect
from .models import SEVERITY_ORDER, ScanStats, is_at_least
from .parsers import SUPPORTED_FORMATS, ParseError, get_parser, read_text
from .report import AnalysisResult, render_console, write_report

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

EPILOG = """\
Примеры:
  # разобрать журнал sshd и вывести отчёт в консоль
  python analyze_logs.py samples/auth_sshd.log

  # сохранить JSON и упасть с кодом 1 при находках уровня high и выше
  python analyze_logs.py /var/log/auth.log -o report.json --fail-on high

  # CSV-выгрузка журнала безопасности Windows, порог 3 отказа за 5 минут
  python analyze_logs.py events.csv --format win-csv --min-failures 3 --window 5m

  # все журналы из каталога
  python analyze_logs.py "logs/*.log"
"""


def _parse_window(value: str) -> timedelta:
    match = re.fullmatch(r"\s*(\d+)\s*([smhdw]?)\s*", value, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError(
            f"не удалось разобрать окно «{value}». Примеры: 30s, 10m, 2h, 1d"
        )
    amount = int(match.group(1))
    unit = (match.group(2) or "m").lower()
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return timedelta(seconds=amount * factor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze_logs.py",
        description="Поиск брутфорса и подозрительных входов в журналах аутентификации.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="ЖУРНАЛ",
        help="файл(ы) журнала; поддерживаются шаблоны вроде logs/*.log и «-» для stdin",
    )
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default="auto",
        help="формат журнала (по умолчанию определяется автоматически)",
    )
    parser.add_argument(
        "--year",
        type=int,
        help="год для syslog-строк без года (по умолчанию текущий)",
    )
    parser.add_argument(
        "--min-failures",
        type=int,
        default=5,
        metavar="N",
        help="сколько отказов считать атакой (по умолчанию 5)",
    )
    parser.add_argument(
        "--window",
        type=_parse_window,
        default=timedelta(minutes=10),
        metavar="ИНТЕРВАЛ",
        help="окно для подсчёта пика, примеры: 30s, 10m, 2h; 0 — без окна (по умолчанию 10m)",
    )
    parser.add_argument(
        "--spray-min-users",
        type=int,
        default=5,
        metavar="N",
        help="сколько разных учётных записей считать распылом паролей (по умолчанию 5)",
    )
    parser.add_argument(
        "--count-invalid-user",
        action="store_true",
        help="учитывать строки «Invalid user» как отказ (по умолчанию не учитываются, "
        "чтобы не удваивать счёт из-за пар «Invalid user» + «Failed password»)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="ФАЙЛ",
        help="сохранить отчёт в файл: .json, .csv или .txt (определяется по расширению)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", *SEVERITY_ORDER),
        default="high",
        help="код возврата 1, если есть находки этого уровня или выше (по умолчанию high)",
    )
    parser.add_argument("--quiet", action="store_true", help="не печатать отчёт в консоль")
    parser.add_argument("--no-color", action="store_true", help="отключить цвета в консоли")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _expand_paths(patterns: list[str]) -> list[str]:
    """Раскрывает шаблоны и проверяет, что файлы существуют."""
    expanded: list[str] = []
    for pattern in patterns:
        if pattern == "-":
            expanded.append(pattern)
            continue
        if any(char in pattern for char in "*?["):
            matches = sorted(name for name in glob.glob(pattern, recursive=True) if Path(name).is_file())
            if not matches:
                raise FileNotFoundError(f"по шаблону «{pattern}» не найдено ни одного файла")
            expanded.extend(matches)
            continue
        path = Path(pattern)
        if not path.is_file():
            raise FileNotFoundError(f"файл не найден: {pattern}")
        expanded.append(str(path))

    unique: list[str] = []
    for path in expanded:
        if path not in unique:
            unique.append(path)
    return unique


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return read_text(Path(path))


def run(args: argparse.Namespace) -> int:
    try:
        paths = _expand_paths(args.paths)
    except FileNotFoundError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return EXIT_ERROR

    thresholds = Thresholds(
        min_failures=args.min_failures,
        window=args.window,
        spray_min_users=args.spray_min_users,
        count_invalid_user=args.count_invalid_user,
    )

    started = time.perf_counter()
    events: list = []
    files: list[str] = []
    lines_total = 0
    formats: list[str] = []

    try:
        for path in paths:
            text = _read_source(path)
            lines_total += len(text.splitlines())
            parser = get_parser(args.format, text, path, default_year=args.year)
            if parser.name not in formats:
                formats.append(parser.name)
            source_events = parser.parse_text(text, source="<stdin>" if path == "-" else path)
            events.extend(source_events)
            files.append("<stdin>" if path == "-" else path)
    except ParseError as error:
        print(f"Ошибка разбора: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f"Ошибка ввода-вывода: {error}", file=sys.stderr)
        return EXIT_ERROR

    duration = time.perf_counter() - started
    findings = detect(events, thresholds)

    stats = ScanStats(
        files=files,
        format_name="+".join(formats) or "—",
        lines_total=lines_total,
        lines_skipped=max(0, lines_total - len(events)),
        events_total=len(events),
        duration_sec=duration,
    )
    result = AnalysisResult(findings=findings, stats=stats, events=events)

    params = {
        "format": args.format,
        "min_failures": args.min_failures,
        "window_sec": int(args.window.total_seconds()),
        "spray_min_users": args.spray_min_users,
        "count_invalid_user": args.count_invalid_user,
        "fail_on": args.fail_on,
    }

    if not args.quiet:
        print(render_console(result, color=False if args.no_color else None))

    if args.output:
        try:
            write_report(result, args.output, params)
        except OSError as error:
            print(f"Не удалось записать отчёт: {error}", file=sys.stderr)
            return EXIT_ERROR
        if not args.quiet:
            print(f"Отчёт сохранён: {args.output}")

    if args.fail_on == "none":
        return EXIT_OK
    if any(is_at_least(finding.severity, args.fail_on) for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _configure_stdio() -> None:
    """UTF-8 для stdout/stderr, чтобы кириллица не ломалась при перенаправлении."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover - нестандартный поток
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.min_failures < 1:
        parser.error("--min-failures должно быть не меньше 1")
    if args.spray_min_users < 2:
        parser.error("--spray-min-users должно быть не меньше 2")
    return run(args)

"""Формирование отчётов: консоль, JSON, CSV."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import __version__
from .models import SEVERITY_ORDER, SEVERITY_RU, ACTION_RU, LogEvent, ScanStats

COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

VERDICT_RU = {
    "none": "подозрительной активности не обнаружено",
    "low": "обнаружена активность низкого риска",
    "medium": "требуется внимание администратора",
    "high": "высокий риск: вероятна атака на аутентификацию",
    "critical": "критично: возможна компрометация учётных записей",
}


@dataclass
class AnalysisResult:
    """Результат работы анализатора."""

    findings: list
    stats: ScanStats
    events: list[LogEvent] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        rank = {severity: position for position, severity in enumerate(SEVERITY_ORDER)}
        best = "none"
        for finding in self.findings:
            if best == "none" or rank[finding.severity] > rank[best]:
                best = finding.severity
        return best

    def by_severity(self) -> dict[str, int]:
        counters = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counters[finding.severity] += 1
        return counters


def use_color(stream=None) -> bool:
    """Цветной вывод только в терминал и только если пользователь не запретил."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def render_console(result: AnalysisResult, color: bool | None = None) -> str:
    """Текстовый отчёт для человека."""
    color = use_color() if color is None else color
    stats = result.stats
    by_action = stats.by_action(result.events)

    lines: list[str] = []
    lines.append(_paint("=" * 70, "bold", color))
    lines.append(_paint(" Анализ журналов аутентификации", "bold", color))
    lines.append(_paint("=" * 70, "bold", color))
    lines.append(f"Файлы:            {', '.join(stats.files) or '—'}")
    lines.append(f"Формат:           {stats.format_name}")
    lines.append(f"Прочитано строк:  {stats.lines_total}")
    lines.append(f"Распознано:       {stats.events_total} событий")
    parts = [
        f"{ACTION_RU[action]}: {count}"
        for action, count in (
            (action, by_action.get(action.value, 0))
            for action in (ACTION_RU)
        )
        if count
    ]
    if parts:
        lines.append(f"  из них:         {'; '.join(parts)}")
    lines.append(f"Время разбора:    {stats.duration_sec:.3f} с")
    lines.append("")

    counters = result.by_severity()
    if not result.findings:
        lines.append(_paint("Находок нет: признаков брутфорса не обнаружено.", "bold", color))
        lines.append("")
        return "\n".join(lines)

    summary = ", ".join(
        f"{SEVERITY_RU[severity]}: {counters[severity]}"
        for severity in reversed(SEVERITY_ORDER)
        if counters[severity]
    )
    lines.append(_paint(f"Найдено находок: {len(result.findings)} ({summary})", "bold", color))
    lines.append(_paint(f"Вердикт: {VERDICT_RU[result.max_severity]}", result.max_severity, color))
    lines.append("")

    for number, finding in enumerate(result.findings, start=1):
        label = finding.severity_ru.upper()
        head = f"[{number}] {label}: {finding.title}"
        lines.append(_paint(head, finding.severity, color))
        lines.append(f"    {finding.summary}")
        details = finding.details
        if details.get("first_seen") or details.get("last_seen"):
            lines.append(
                f"    Период: {details.get('first_seen') or '—'} — {details.get('last_seen') or '—'}"
            )
        if details.get("failures_in_window") and details.get("window_sec"):
            lines.append(
                f"    Пик в окне {details['window_sec']} с: {details['failures_in_window']} отказов"
            )
        for evidence in finding.evidence[:3]:
            lines.append(_paint(f"    > {evidence}", "dim", color))
        lines.append("")
    return "\n".join(lines)


def to_dict(result: AnalysisResult, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Машиночитаемое представление результата."""
    stats = result.stats
    return {
        "tool": "analyze_logs",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "params": params or {},
        "stats": {
            "files": stats.files,
            "format": stats.format_name,
            "lines_total": stats.lines_total,
            "lines_skipped": stats.lines_skipped,
            "events_total": stats.events_total,
            "events_by_action": stats.by_action(result.events),
            "duration_sec": round(stats.duration_sec, 3),
        },
        "summary": {
            "findings": len(result.findings),
            "by_severity": result.by_severity(),
            "max_severity": result.max_severity,
            "verdict": VERDICT_RU[result.max_severity],
        },
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "severity_ru": finding.severity_ru,
                "summary": finding.summary,
                "details": finding.details,
                "evidence": finding.evidence,
            }
            for finding in result.findings
        ],
    }


def render_json(result: AnalysisResult, params: dict[str, Any] | None = None) -> str:
    """JSON-отчёт в UTF-8 без ASCII-экранирования."""
    return json.dumps(to_dict(result, params), ensure_ascii=False, indent=2)


def render_csv(result: AnalysisResult) -> str:
    """CSV-отчёт: одна строка на находку."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "rule_id",
            "severity",
            "severity_ru",
            "title",
            "summary",
            "source_ip",
            "username",
            "count",
            "first_seen",
            "last_seen",
        ]
    )
    for finding in result.findings:
        details = finding.details
        writer.writerow(
            [
                finding.rule_id,
                finding.severity,
                finding.severity_ru,
                finding.title,
                finding.summary,
                details.get("source_ip") or "",
                details.get("username") or ", ".join(details.get("users") or details.get("accounts") or []),
                details.get("failures") or details.get("successes") or "",
                details.get("first_seen") or details.get("first_failure") or "",
                details.get("last_seen") or details.get("success_time") or "",
            ]
        )
    return buffer.getvalue()


def write_report(result: AnalysisResult, path: str, params: dict[str, Any] | None = None) -> str:
    """Записывает отчёт в файл, выбирая формат по расширению."""
    lowered = path.lower()
    if lowered.endswith(".json"):
        content = render_json(result, params)
    elif lowered.endswith(".csv"):
        content = render_csv(result)
    else:
        content = render_console(result, color=False)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        if not content.endswith("\n"):
            handle.write("\n")
    return path

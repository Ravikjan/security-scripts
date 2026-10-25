"""Правила обнаружения: брутфорс, распыл паролей, вход после серии отказов."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Action, Finding, LogEvent


@dataclass
class Thresholds:
    """Пороги срабатывания правил."""

    min_failures: int = 5
    window: timedelta | None = timedelta(minutes=10)
    spray_min_users: int = 5
    distributed_min_ips: int = 3
    count_invalid_user: bool = False
    max_evidence: int = 5


def _failure_actions(thresholds: Thresholds) -> set[Action]:
    actions = {Action.LOGIN_FAILED, Action.AUTH_LIMIT}
    if thresholds.count_invalid_user:
        actions.add(Action.INVALID_USER)
    return actions


def _format_time(moment: datetime | None) -> str | None:
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else None


def _peak_in_window(times: list[datetime], window: timedelta | None) -> int:
    """Максимальное число событий в скользящем окне `window`."""
    if not times:
        return 0
    if window is None or window.total_seconds() <= 0 or len(times) == 1:
        return len(times)

    times = sorted(times)
    best = 0
    left = 0
    for right, current in enumerate(times):
        while current - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def _evidence(events: list[LogEvent], limit: int) -> list[str]:
    return [f"{event.source}:{event.line_no}: {event.raw}" for event in events[:limit]]


def _brute_force(failures: list[LogEvent], thresholds: Thresholds) -> list[Finding]:
    """Много отказов с одного IP-адреса."""
    findings: list[Finding] = []
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in failures:
        if event.source_ip:
            by_ip[event.source_ip].append(event)

    for ip, events in sorted(by_ip.items()):
        total = len(events)
        if total < thresholds.min_failures:
            continue

        users = sorted({event.username for event in events if event.username})
        # Если попытки размазаны по многим учётным записям поровну — это распыл
        # паролей, его отчитает отдельное правило. Не дублируем находку.
        if len(users) >= thresholds.spray_min_users:
            per_user: dict[str, int] = defaultdict(int)
            for event in events:
                per_user[event.username or "—"] += 1
            if max(per_user.values()) < thresholds.min_failures:
                continue

        timestamps = [event.timestamp for event in events if event.timestamp]
        peak = _peak_in_window(timestamps, thresholds.window)

        if total >= thresholds.min_failures * 10:
            severity = "critical"
        elif total >= thresholds.min_failures * 3:
            severity = "high"
        else:
            severity = "medium"

        summary = (
            f"{total} отказов во входе с {ip}"
            + (f" (до {peak} за окно)" if timestamps and thresholds.window else "")
            + (f", цели: {', '.join(users[:5])}" if users else "")
        )
        findings.append(
            Finding(
                rule_id="brute-force",
                title="Брутфорс: серия отказов во входе с одного адреса",
                severity=severity,
                summary=summary,
                details={
                    "source_ip": ip,
                    "failures": total,
                    "failures_in_window": peak,
                    "window_sec": int(thresholds.window.total_seconds()) if thresholds.window else 0,
                    "users": users,
                    "first_seen": _format_time(min(timestamps)) if timestamps else None,
                    "last_seen": _format_time(max(timestamps)) if timestamps else None,
                },
                evidence=_evidence(events, thresholds.max_evidence),
            )
        )
    return findings


def _password_spray(failures: list[LogEvent], thresholds: Thresholds) -> list[Finding]:
    """Много разных учётных записей с одного IP при малом числе попыток на каждую."""
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in failures:
        if event.source_ip:
            by_ip[event.source_ip].append(event)

    findings: list[Finding] = []
    for ip, events in sorted(by_ip.items()):
        total = len(events)
        if total < thresholds.min_failures:
            continue
        per_user: dict[str, int] = defaultdict(int)
        for event in events:
            per_user[event.username or "—"] += 1
        if len(per_user) < thresholds.spray_min_users:
            continue
        if max(per_user.values()) >= thresholds.min_failures:
            # Это уже перебор одной учётной записи, а не распыл.
            continue

        severity = "critical" if len(per_user) >= thresholds.spray_min_users * 2 else "high"
        users = sorted(per_user)
        timestamps = [event.timestamp for event in events if event.timestamp]
        findings.append(
            Finding(
                rule_id="password-spray",
                title="Распыл паролей: перебор многих учётных записей с одного адреса",
                severity=severity,
                summary=f"{len(users)} учётных записей, {total} отказов с {ip}",
                details={
                    "source_ip": ip,
                    "failures": total,
                    "accounts": len(users),
                    "users": users[:20],
                    "first_seen": _format_time(min(timestamps)) if timestamps else None,
                    "last_seen": _format_time(max(timestamps)) if timestamps else None,
                },
                evidence=_evidence(events, thresholds.max_evidence),
            )
        )
    return findings


def _success_after_failure(
    all_failures: list[LogEvent], successes: list[LogEvent], thresholds: Thresholds
) -> list[Finding]:
    """Успешный вход с адреса, с которого шёл перебор."""
    findings: list[Finding] = []
    failed_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in all_failures:
        if event.source_ip:
            failed_by_ip[event.source_ip].append(event)

    success_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in successes:
        if event.source_ip:
            success_by_ip[event.source_ip].append(event)

    for ip in sorted(set(failed_by_ip) & set(success_by_ip)):
        failed = failed_by_ip[ip]
        succeeded = success_by_ip[ip]
        if len(failed) < thresholds.min_failures:
            # Единичная опечатка в пароле — не повод для критичной находки.
            continue
        names = sorted({event.username for event in succeeded if event.username})
        findings.append(
            Finding(
                rule_id="success-after-failure",
                title="Успешный вход после серии отказов — возможная компрометация",
                severity="critical",
                summary=(
                    f"{len(failed)} отказов, затем успешный вход с {ip}"
                    + (f" под учётной записью {', '.join(names)}" if names else "")
                ),
                details={
                    "source_ip": ip,
                    "failures": len(failed),
                    "successes": len(succeeded),
                    "accounts": names,
                    "first_failure": _format_time(
                        min((e.timestamp for e in failed if e.timestamp), default=None)
                    ),
                    "success_time": _format_time(
                        max((e.timestamp for e in succeeded if e.timestamp), default=None)
                    ),
                },
                evidence=_evidence(failed, 3) + _evidence(succeeded, 2),
            )
        )
    return findings


def _distributed_account_attack(failures: list[LogEvent], thresholds: Thresholds) -> list[Finding]:
    """Перебор одной учётной записи с множества адресов."""
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for event in failures:
        if event.username:
            by_user[event.username].append(event)

    findings: list[Finding] = []
    for user, events in sorted(by_user.items()):
        ips = sorted({event.source_ip for event in events if event.source_ip})
        if len(events) < thresholds.min_failures or len(ips) < thresholds.distributed_min_ips:
            continue
        timestamps = [event.timestamp for event in events if event.timestamp]
        findings.append(
            Finding(
                rule_id="distributed-account-attack",
                title="Распределённый перебор учётной записи с нескольких адресов",
                severity="high",
                summary=f"{len(events)} отказов для «{user}» с {len(ips)} адресов",
                details={
                    "username": user,
                    "failures": len(events),
                    "source_ips": ips[:20],
                    "first_seen": _format_time(min(timestamps)) if timestamps else None,
                    "last_seen": _format_time(max(timestamps)) if timestamps else None,
                },
                evidence=_evidence(events, thresholds.max_evidence),
            )
        )
    return findings


def detect(events: list[LogEvent], thresholds: Thresholds | None = None) -> list[Finding]:
    """Запускает все правила и возвращает находки, отсортированные по важности."""
    thresholds = thresholds or Thresholds()
    failure_actions = _failure_actions(thresholds)

    failures = [event for event in events if event.action in failure_actions]
    successes = [event for event in events if event.action == Action.LOGIN_SUCCESS]

    findings: list[Finding] = []
    findings.extend(_brute_force(failures, thresholds))
    findings.extend(_password_spray(failures, thresholds))
    findings.extend(_success_after_failure(failures, successes, thresholds))
    findings.extend(_distributed_account_attack(failures, thresholds))

    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    findings.sort(key=lambda item: (-rank[item.severity], item.rule_id))
    return findings

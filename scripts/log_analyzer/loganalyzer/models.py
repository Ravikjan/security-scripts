"""Модели данных анализатора: события, находки, уровни важности."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# Порядок уровней важен: индекс используется как ранг при сравнении.
SEVERITY_ORDER = ("low", "medium", "high", "critical")

SEVERITY_RU = {
    "low": "низкая",
    "medium": "средняя",
    "high": "высокая",
    "critical": "критическая",
}


def severity_rank(severity: str) -> int:
    """Числовой ранг важности: 0 — низкая, 3 — критическая."""
    return SEVERITY_ORDER.index(severity)


def is_at_least(severity: str, threshold: str) -> bool:
    """True, если важность `severity` не ниже порога `threshold`."""
    return severity_rank(severity) >= severity_rank(threshold)


class Action(str, Enum):
    """Тип события аутентификации."""

    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    INVALID_USER = "invalid_user"
    AUTH_LIMIT = "auth_limit"


ACTION_RU = {
    Action.LOGIN_FAILED: "отказ во входе",
    Action.LOGIN_SUCCESS: "успешный вход",
    Action.INVALID_USER: "несуществующий пользователь",
    Action.AUTH_LIMIT: "превышен лимит попыток",
}


@dataclass
class LogEvent:
    """Одно событие аутентификации, извлечённое из журнала."""

    action: Action
    timestamp: datetime | None = None
    source_ip: str | None = None
    username: str | None = None
    source: str = ""
    line_no: int = 0
    raw: str = ""

    def describe(self) -> str:
        """Короткое описание события для отчёта."""
        when = self.timestamp.strftime("%d.%m %H:%M:%S") if self.timestamp else "время неизвестно"
        user = self.username or "—"
        ip = self.source_ip or "—"
        return f"{when} | {ip} | {user} | {ACTION_RU[self.action]}"


@dataclass
class Finding:
    """Найденная подозрительная активность."""

    rule_id: str
    title: str
    severity: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    @property
    def severity_ru(self) -> str:
        return SEVERITY_RU[self.severity]


@dataclass
class ScanStats:
    """Счётчики обработки журналов."""

    files: list[str] = field(default_factory=list)
    format_name: str = "auto"
    lines_total: int = 0
    lines_skipped: int = 0
    events_total: int = 0
    duration_sec: float = 0.0

    def by_action(self, events: list[LogEvent]) -> dict[str, int]:
        """Количество событий по типам (для сводки в отчёте)."""
        result: dict[str, int] = {}
        for event in events:
            result[event.action.value] = result.get(event.action.value, 0) + 1
        return result

"""Разбор журналов: syslog-формат sshd и CSV-выгрузка журнала Windows."""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from pathlib import Path

from .models import Action, LogEvent


class ParseError(Exception):
    """Журнал не удалось разобрать или формат не поддерживается."""


MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{1,2}:\d{2}:\d{2})(?:\s|$)"
)
ISO_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?:[.,](?P<frac>\d{1,6}))?"
)

# Дополнительные форматы даты: используются, если не подошли ISO и syslog.
EXTRA_FORMATS = (
    "%d.%m.%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
)


def parse_timestamp(text: str, default_year: int | None = None) -> datetime | None:
    """Извлекает время из начала строки журнала.

    Поддерживаются ISO-формат (в том числе с миллисекундами) и syslog-формат
    без года — для него год берётся из `default_year` или подставляется текущий
    с поправкой на переход через Новый год.
    """
    if not text:
        return None

    text = text.strip()

    match = ISO_RE.match(text)
    if match:
        fraction = (match.group("frac") or "").ljust(6, "0")
        base = f"{match.group('date')} {match.group('time')}"
        try:
            return datetime.strptime(base, "%Y-%m-%d %H:%M:%S").replace(
                microsecond=int(fraction)
            )
        except (ValueError, TypeError):
            return None

    match = SYSLOG_RE.match(text)
    if match:
        month = MONTHS.get(match.group("mon").lower())
        if month is None:
            return None
        hour, minute, second = (int(part) for part in match.group("time").split(":"))
        day = int(match.group("day"))
        if default_year:
            year = default_year
        else:
            now = datetime.now()
            # Журнал за декабрь, прочитанный в январе, относится к прошлому году.
            year = now.year - 1 if month - now.month > 6 else now.year
        try:
            return datetime(year, month, day, hour, minute, second)
        except ValueError:
            return None

    for fmt in EXTRA_FORMATS:
        try:
            return datetime.strptime(text[: len(fmt) + 4].strip(), fmt)
        except ValueError:
            continue
    return None


def read_text(path: Path) -> str:
    """Читает файл журнала, подбирая кодировку (UTF-8, затем Windows-1251)."""
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1251", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def normalize_header(name: str) -> str:
    """Приводит название колонки к сравнимому виду."""
    return re.sub(r"[\s_\-]+", "", name.strip().lower())


class BaseParser:
    """Базовый класс парсера журнала."""

    name = "base"

    def __init__(self, default_year: int | None = None) -> None:
        self.default_year = default_year

    def parse_file(self, path: Path) -> list[LogEvent]:
        return self.parse_text(read_text(path), source=str(path))

    def parse_text(self, text: str, source: str = "<stdin>") -> list[LogEvent]:
        raise NotImplementedError


class SshdParser(BaseParser):
    """Парсер журнала OpenSSH (/var/log/auth.log, journalctl -u sshd)."""

    name = "sshd"

    # Порядок важен: более специфичные шаблоны проверяются раньше.
    _PATTERNS = (
        (
            re.compile(
                r"Accepted\s+(?:password|publickey|keyboard-interactive/pam|gssapi-with-mic)"
                r"\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\w.:\-]+)\s+port\s+\d+"
            ),
            Action.LOGIN_SUCCESS,
        ),
        (
            re.compile(
                r"Failed\s+(?:password|publickey|none|keyboard-interactive/pam)"
                r"\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\w.:\-]+)\s+port\s+\d+"
            ),
            Action.LOGIN_FAILED,
        ),
        (
            re.compile(r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\w.:\-]+)"),
            Action.INVALID_USER,
        ),
        (
            re.compile(
                r"maximum authentication attempts exceeded for\s+(?:invalid user\s+)?"
                r"(?P<user>\S+)\s+from\s+(?P<ip>[\w.:\-]+)"
            ),
            Action.AUTH_LIMIT,
        ),
        (
            re.compile(
                r"PAM:\s*Authentication failure for illegal user\s+(?P<user>\S+)"
                r"\s+from\s+(?P<ip>[\w.:\-]+)"
            ),
            Action.LOGIN_FAILED,
        ),
        (
            re.compile(
                r"pam_unix\(sshd:auth\):\s*authentication failure;.*?"
                r"rhost=(?P<ip>\S+).*?user=(?P<user>\S+)"
            ),
            Action.LOGIN_FAILED,
        ),
    )

    def parse_text(self, text: str, source: str = "<stdin>") -> list[LogEvent]:
        events: list[LogEvent] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            timestamp = parse_timestamp(line, self.default_year)
            for pattern, action in self._PATTERNS:
                match = pattern.search(line)
                if match:
                    events.append(
                        LogEvent(
                            action=action,
                            timestamp=timestamp,
                            source_ip=match.group("ip").rstrip(","),
                            username=match.group("user"),
                            source=source,
                            line_no=line_no,
                            raw=line.strip(),
                        )
                    )
                    break
        return events


class WindowsCsvParser(BaseParser):
    """Парсер CSV-выгрузки журнала безопасности Windows (события 4624/4625)."""

    name = "win-csv"

    _EVENT_ACTIONS = {
        "4625": Action.LOGIN_FAILED,
        "4624": Action.LOGIN_SUCCESS,
    }

    _COLUMN_ALIASES = {
        "time": {"timecreated", "время", "датаивремя", "timestamp", "time", "дата"},
        "event": {"eventid", "event_id", "eventcode", "код", "id"},
        "user": {"targetusername", "subjectusername", "username", "user", "пользователь"},
        "ip": {"ipaddress", "sourceip", "source_network_address", "ip", "адрес"},
        "logon_type": {"logontype", "типвхода"},
    }

    def parse_text(self, text: str, source: str = "<stdin>") -> list[LogEvent]:
        reader = csv.reader(io.StringIO(text))
        events: list[LogEvent] = []
        indexes: dict[str, int] | None = None
        header_seen = False

        for line_no, row in enumerate(reader, start=1):
            if not any(cell.strip() for cell in row):
                continue
            if not header_seen:
                indexes = self._map_columns(row, source)
                header_seen = True
                continue
            if indexes is None:  # pragma: no cover - защита от пустого заголовка
                raise ParseError("Не удалось прочитать заголовок CSV")

            event_id = self._cell(row, indexes.get("event"))
            action = self._EVENT_ACTIONS.get(event_id)
            if action is None:
                continue

            username = self._clean(self._cell(row, indexes.get("user")))
            if username and username.endswith("$"):
                # Машинные учётные записи (COMPUTER$) не интересуют.
                continue

            timestamp = parse_timestamp(self._cell(row, indexes.get("time")) or "", self.default_year)
            events.append(
                LogEvent(
                    action=action,
                    timestamp=timestamp,
                    source_ip=self._clean(self._cell(row, indexes.get("ip"))),
                    username=username,
                    source=source,
                    line_no=line_no,
                    raw=",".join(row).strip(),
                )
            )
        return events

    def _map_columns(self, header: list[str], source: str) -> dict[str, int]:
        normalized = [normalize_header(cell) for cell in header]
        indexes: dict[str, int] = {}
        for key, aliases in self._COLUMN_ALIASES.items():
            for position, name in enumerate(normalized):
                if name in aliases:
                    indexes[key] = position
                    break

        missing = [key for key in ("time", "event") if key not in indexes]
        if missing:
            raise ParseError(
                f"В заголовке CSV ({source}) не найдены обязательные колонки: {', '.join(missing)}. "
                "Ожидаются колонки вида TimeCreated и EventID."
            )
        if "user" not in indexes or "ip" not in indexes:
            raise ParseError(
                f"В заголовке CSV ({source}) нет колонки пользователя или IP-адреса. "
                "Добавьте TargetUserName и IpAddress в выгрузку."
            )
        return indexes

    @staticmethod
    def _cell(row: list[str], index: int | None) -> str | None:
        if index is None or index >= len(row):
            return None
        value = row[index].strip()
        return value or None

    @staticmethod
    def _clean(value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return None if value in {"", "-", "—"} else value


PARSERS = {
    "sshd": SshdParser,
    "win-csv": WindowsCsvParser,
}

SUPPORTED_FORMATS = ("auto", "sshd", "win-csv")


def detect_format(text: str, filename: str = "") -> str:
    """Определяет формат журнала по содержимому и расширению файла."""
    sample = text[:8192].lower()
    lowered_name = filename.lower()

    sshd_markers = ("failed password", "accepted password", "accepted publickey", "sshd[", "invalid user")
    if any(marker in sample for marker in sshd_markers):
        return "sshd"

    if lowered_name.endswith(".csv") or ("timecreated" in sample and "eventid" in sample):
        return "win-csv"

    raise ParseError(
        "Не удалось определить формат журнала. Укажите его явно: --format sshd или --format win-csv."
    )


def get_parser(format_name: str, text: str, filename: str, default_year: int | None = None) -> BaseParser:
    """Создаёт парсер для указанного или автоматически определённого формата."""
    if format_name == "auto":
        format_name = detect_format(text, filename)
    parser_class = PARSERS.get(format_name)
    if parser_class is None:
        raise ParseError(
            f"Неизвестный формат «{format_name}». Доступны: {', '.join(SUPPORTED_FORMATS)}."
        )
    return parser_class(default_year=default_year)

#!/usr/bin/env python3
"""Анализатор журналов аутентификации: поиск брутфорса и подозрительных входов.

Запуск:
    python analyze_logs.py samples/auth_sshd.log
    python analyze_logs.py events.csv --format win-csv -o report.json

Подробности — в docs/02-АНАЛИЗ-ЛОГОВ.md.
"""

from __future__ import annotations

import sys

from loganalyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())

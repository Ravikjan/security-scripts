# Анализатор журналов аутентификации

Поиск брутфорса, распыла паролей и входов после серии отказов в журналах
OpenSSH и в CSV-выгрузке журнала безопасности Windows.

```powershell
python scripts/log_analyzer/analyze_logs.py samples/auth_sshd.log
python scripts/log_analyzer/analyze_logs.py events.csv --format win-csv -o report.json
```

- Формат определяется автоматически (`--format auto`), но его можно задать явно.
- Четыре правила: `brute-force`, `password-spray`, `success-after-failure`,
  `distributed-account-attack`.
- Отчёты: консоль, JSON, CSV. Код возврата 1 при находках — для cron и CI.

Полное описание параметров, порогов и JSON-схемы —
в [docs/02-АНАЛИЗ-ЛОГОВ.md](../../docs/02-АНАЛИЗ-ЛОГОВ.md).

Модули: `loganalyzer/parsers.py` (разбор), `detectors.py` (правила),
`report.py` (вывод), `cli.py` (командная строка).

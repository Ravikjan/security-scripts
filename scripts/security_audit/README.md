# Аудит базовых настроек безопасности Windows

18 проверок настроек Windows с оценкой защищённости и отчётами в консоль,
JSON, CSV и HTML. Скрипт ничего не меняет в системе — только читает.

```powershell
# Консольный отчёт
pwsh scripts/security_audit/Test-SecurityBaseline.ps1

# HTML для архива
pwsh scripts/security_audit/Test-SecurityBaseline.ps1 -OutputPath report.html

# Только выбранные проверки, код 1 при нарушениях уровня Critical
pwsh scripts/security_audit/Test-SecurityBaseline.ps1 -Only SEC-006,SEC-008 -FailOn Critical
```

- Полноценный результат — при запуске от имени администратора: проверки без
  прав аккуратно помечаются как пропущенные.
- Список проверок: `-List`.
- Оценка 0–100 считается по выполненным проверкам, поэтому пропуски её не
  завышают.

Таблица всех проверок, статусы и коды возврата —
в [docs/03-АУДИТ-БЕЗОПАСНОСТИ.md](../../docs/03-АУДИТ-БЕЗОПАСНОСТИ.md).

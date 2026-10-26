# Частые вопросы и проблемы

## Python не запускается, печатает просто «Python»

Это заглушка Microsoft Store, а не интерпретатор. Установите настоящий Python
и откройте новый терминал — подробности в
[01-УСТАНОВКА](01-УСТАНОВКА.md#python-на-windows-ловушка-microsoft-store).

## `python -m unittest discover` пишет «Start directory is not importable»

Запускайте из корня репозитория с указанием top-level каталога:

```powershell
python -m unittest discover -s tests -t . -v
```

В каталоге `tests/` есть `__init__.py`, поэтому вариант с `-t .` работает.
Если запустить `discover` из другого каталога, корень не найдётся.

## Кириллица выводится «кракозябрами»

Скрипты пишут UTF-8. В старой консоли с кодовой страницей 866:

```powershell
chcp 65001
$env:PYTHONUTF8 = "1"
```

В PowerShell 7 обычно достаточно открыть новое окно.

## Анализатор пишет «Не удалось определить формат журнала»

Укажите формат явно:

```powershell
python scripts/log_analyzer/analyze_logs.py auth.log --format sshd
python scripts/log_analyzer/analyze_logs.py events.csv --format win-csv
```

Автоопределение ищет характерные строки (`Failed password`, `sshd[`,
`TimeCreated,EventID`) в первых 8 КБ файла. Если журнал начинается с длинной
шапки, автоматика может не сработать.

## CSV из Windows не разбирается

Проверьте заголовок: должны быть колонки времени, идентификатора события,
пользователя и IP-адреса. Скрипт понимает варианты:

- время: `TimeCreated`, `Time`, `Время`, `Дата и время`
- событие: `EventID`, `EventId`, `Id`, `Код`
- пользователь: `TargetUserName`, `SubjectUserName`, `UserName`, `Пользователь`
- адрес: `IpAddress`, `SourceIp`, `SourceNetworkAddress`, `IP`

Разделитель — запятая. Выгрузка `wevtutil epl` делает XML — её нужно сначала
преобразовать в CSV (пример команды есть в
[02-АНАЛИЗ-ЛОГОВ](02-АНАЛИЗ-ЛОГОВ.md#как-получить-csv-из-журнала-windows)).

## Почему «Invalid user» не считается отказом?

sshd пишет на одну неудачную попытку две строки: `Invalid user X from IP` и
затем `Failed password for invalid user X from IP`. Если считать обе, счётчики
удвоятся. Поэтому по умолчанию учитывается только `Failed password`, а флаг
`--count-invalid-user` включает учёт строк `Invalid user` — он нужен для
журналов, где аутентификация идёт только по ключам.

## Аудит показывает много «ПРОПУЩЕНО»

Проверки, которым нужны права администратора (брандмауэр, Defender, SMB,
BitLocker, Secure Boot, журнал безопасности), без них не выполняются.
Запустите PowerShell от имени администратора:

```powershell
Start-Process pwsh -Verb RunAs -ArgumentList '-NoExit','-File','.\scripts\security_audit\Test-SecurityBaseline.ps1'
```

## Код возврата 2 после `-Only`

Если в `-Only` указан неизвестный идентификатор, выполнять нечего — скрипт
сообщает об этом и возвращает 2. Полный список:

```powershell
pwsh scripts/security_audit/Test-SecurityBaseline.ps1 -List
```

## Оценка защищённости кажется завышенной

Пропущенные и упавшие проверки не входят в расчёт, поэтому оценка описывает
только те настройки, которые удалось проверить. Смотрите счётчики
`пропущено` и `ошибок` в отчёте: если они велики, оценке верить рано.

## `--exclude-private` убрал почти все адреса

Библиотека `ipaddress` считает непубличными не только RFC 1918, но и
диапазоны документации (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
В учебных образцах все адреса именно оттуда — это ожидаемо.

## Дефанг не применяется к входному тексту

`--defang` меняет только **вывод**. Чтобы найти индикаторы, которые в тексте
уже обезврежены (`1[.]2[.]3[.]4`, `hxxps://`), добавьте `--refang-input`.

## Как использовать в cron или Планировщике задач?

```bash
# cron: ежедневно ищем атаки, JSON в архив
0 3 * * * python /opt/security-scripts/scripts/log_analyzer/analyze_logs.py \
    /var/log/auth.log -o /var/reports/auth-$(date +\%F).json --quiet --fail-on medium \
    || logger -t sec-scripts "Обнаружены подозрительные входы"
```

```powershell
# Планировщик Windows: еженедельный аудит в HTML
$action = New-ScheduledTaskAction -Execute 'pwsh' -Argument '-File C:\scripts\security_audit\Test-SecurityBaseline.ps1 -OutputPath C:\reports\baseline.html -Quiet'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am
Register-ScheduledTask -TaskName 'SecurityBaseline' -Action $action -Trigger $trigger -RunLevel Highest
```

`-RunLevel Highest` нужен, чтобы проверки с правами администратора не
пропускались.

## Где взять тестовые данные?

В каталоге `samples/` — синтетический журнал sshd с атакой, CSV журнала
Windows и текст отчёта с индикаторами. Все адреса вымышленные, домены из
зарезервированных зон `.example` и `.test`.

## Как сообщить об ошибке?

См. [CONTRIBUTING.md](../CONTRIBUTING.md). Для уязвимостей — [SECURITY.md](../SECURITY.md).

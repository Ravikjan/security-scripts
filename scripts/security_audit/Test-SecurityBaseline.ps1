#Requires -Version 7.0
<#
.SYNOPSIS
    Проверка базовых настроек безопасности Windows по 18 правилам.

.DESCRIPTION
    Скрипт проверяет брандмауэр, антивирус, SMB, UAC, RDP, BitLocker,
    парольную политику, журнал безопасности и другие настройки, считает
    оценку защищённости и формирует отчёт в консоль, JSON, CSV или HTML.

    Проверки выполняются по одной и изолированы друг от друга: если одна
    не может быть выполнена (нет прав, нет компонента), остальные работают,
    а в отчёте появляется статус «ПРОПУЩЕНО» или «ОШИБКА» с причиной.

    Часть проверок требует прав администратора. Без них они помечаются
    как пропущенные — об этом сообщает итоговая строка отчёта.

.PARAMETER OutputFormat
    Формат отчёта: Console (по умолчанию), Json, Csv, Html.
    Если указан -OutputPath без -OutputFormat, формат берётся из расширения.

.PARAMETER OutputPath
    Путь, по которому сохранить отчёт.

.PARAMETER FailOn
    Уровень важности, при котором скрипт вернёт код 1 (None, Low, Medium,
    High, Critical). По умолчанию High.

.PARAMETER Skip
    Идентификаторы проверок, которые нужно исключить, например SEC-004.

.PARAMETER Only
    Выполнить только перечисленные проверки.

.PARAMETER List
    Показать список проверок и выйти.

.PARAMETER Quiet
    Не выводить отчёт в консоль (полезно вместе с -OutputPath).

.PARAMETER IncludeUnknown
    Показывать в разделе «Что исправить» проверки со статусом
    «ПРОПУЩЕНО» и «ОШИБКА» вместе с причиной.

.PARAMETER NoColor
    Отключить цветной вывод.

.EXAMPLE
    .\Test-SecurityBaseline.ps1

.EXAMPLE
    .\Test-SecurityBaseline.ps1 -OutputFormat Html -OutputPath .\security-report.html

.EXAMPLE
    .\Test-SecurityBaseline.ps1 -Only SEC-001,SEC-006,SEC-008 -FailOn Critical

.EXAMPLE
    .\Test-SecurityBaseline.ps1 -List

.NOTES
    Требуется PowerShell 7+. Скрипт ничего не меняет в системе: только читает
    настройки. Проверки с RequiresAdministrator без прав администратора
    пропускаются.
#>
[CmdletBinding()]
param(
    [ValidateSet('Console', 'Json', 'Csv', 'Html')]
    [string]$OutputFormat = 'Console',

    [string]$OutputPath,

    [ValidateSet('None', 'Low', 'Medium', 'High', 'Critical')]
    [string]$FailOn = 'High',

    [string[]]$Skip = @(),

    [string[]]$Only = @(),

    [switch]$List,

    [switch]$Quiet,

    [switch]$IncludeUnknown,

    [switch]$NoColor
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Version = '0.1.0'
$script:SeverityWeight = @{ Low = 1; Medium = 3; High = 5; Critical = 10 }
$script:SeverityRank = @{ None = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
$script:StatusRu = @{
    Pass  = 'ПРОЙДЕНО'
    Fail  = 'НАРУШЕНО'
    Warn  = 'ВНИМАНИЕ'
    Skip  = 'ПРОПУЩЕНО'
    Error = 'ОШИБКА'
}

$script:StatusAnsi = @{
    Pass  = '32'
    Fail  = '31'
    Warn  = '33'
    Skip  = '90'
    Error = '35'
}
$script:NetAccountsText = $null


# --------------------------------------------------------------------------
# Вспомогательные функции
# --------------------------------------------------------------------------

function New-CheckResult {
    <#
    .SYNOPSIS
        Создаёт результат одной проверки.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warn', 'Skip', 'Error')]
        [string]$Status,

        [string]$Detail = '',

        [string]$Fix = ''
    )

    [pscustomobject]@{
        Status = $Status
        Detail = $Detail
        Fix    = $Fix
    }
}

function Get-ObjectProperty {
    <# Безопасно читает свойство объекта; $null, если свойства нет. #>
    param($Object, [string]$Name)

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-RegistryValue {
    <# Читает значение из реестра; $null, если ключа или значения нет. #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return Get-ObjectProperty -Object $item -Name $Name
    }
    catch {
        return $null
    }
}

function Test-IsAdministrator {
    <# True, если процесс запущен с повышенными правами. #>
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-NetAccountsText {
    <# Кэшированный вывод `net accounts` (не требует прав администратора). #>
    if ($null -eq $script:NetAccountsText) {
        try {
            $script:NetAccountsText = (net accounts 2>&1 | Out-String)
        }
        catch {
            $script:NetAccountsText = ''
        }
    }
    return $script:NetAccountsText
}

function Get-NetAccountsNumber {
    <#
    .SYNOPSIS
        Достаёт числовое значение из вывода `net accounts` по названию строки.
    .DESCRIPTION
        Названия строк в выводе зависят от локали, поэтому поддерживаются
        несколько вариантов. Возвращает $null, если строку найти не удалось.
    #>
    param([Parameter(Mandatory)][string[]]$Keys)

    $text = Get-NetAccountsText
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    foreach ($key in $Keys) {
        $pattern = '(?im)^\s*' + [regex]::Escape($key) + '\s*:\s*(\S+)'
        $match = [regex]::Match($text, $pattern)
        if (-not $match.Success) {
            continue
        }
        $raw = $match.Groups[1].Value
        $number = 0
        if ([int]::TryParse($raw, [ref]$number)) {
            return $number
        }
        if ($raw -match '^(?i)(never|none|никогда|нет)$') {
            return 0
        }
        return $null
    }
    return $null
}


function Get-PluralForm {
    <# Русская форма слова для числа: 1 проверка, 3 проверки, 18 проверок. #>
    param(
        [Parameter(Mandatory)][int]$Number,
        [Parameter(Mandatory)][string]$One,
        [Parameter(Mandatory)][string]$Few,
        [Parameter(Mandatory)][string]$Many
    )

    $mod100 = $Number % 100
    $mod10 = $Number % 10
    if ($mod100 -ge 11 -and $mod100 -le 14) { return $Many }
    if ($mod10 -eq 1) { return $One }
    if ($mod10 -ge 2 -and $mod10 -le 4) { return $Few }
    return $Many
}


# --------------------------------------------------------------------------
# Описание проверок
# --------------------------------------------------------------------------

function Get-SecurityCheckDefinition {
    <#
    .SYNOPSIS
        Возвращает список проверок: метаданные и сценарий выполнения.
    #>
    @(
        [pscustomobject]@{
            Id                    = 'SEC-001'
            Title                 = 'Брандмауэр включён для всех профилей'
            Category              = 'Сеть'
            Severity              = 'High'
            RequiresAdministrator = $true
            Fix                   = 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'
            Check                 = {
                $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
                $disabled = @($profiles | Where-Object { -not $_.Enabled })
                if ($disabled.Count -gt 0) {
                    $names = (@($disabled | ForEach-Object { $_.Name }) -join ', ')
                    return New-CheckResult -Status Fail -Detail "Отключены профили: $names"
                }
                $enabledNames = (@($profiles | ForEach-Object { $_.Name }) -join ', ')
                return New-CheckResult -Status Pass -Detail "Включены профили: $enabledNames"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-002'
            Title                 = 'Защита в реальном времени Microsoft Defender включена'
            Category              = 'Антивирус'
            Severity              = 'High'
            RequiresAdministrator = $true
            Fix                   = 'Set-MpPreference -DisableRealtimeMonitoring $false'
            Check                 = {
                $status = Get-MpComputerStatus -ErrorAction Stop
                $enabled = Get-ObjectProperty -Object $status -Name 'RealTimeProtectionEnabled'
                if ($null -eq $enabled) {
                    return New-CheckResult -Status Warn -Detail 'Состояние защиты в реальном времени недоступно'
                }
                if ($enabled) {
                    return New-CheckResult -Status Pass -Detail 'Защита в реальном времени работает'
                }
                return New-CheckResult -Status Fail -Detail 'Защита в реальном времени отключена'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-003'
            Title                 = 'Базы антивируса обновлены (не старше 3 дней)'
            Category              = 'Антивирус'
            Severity              = 'Medium'
            RequiresAdministrator = $true
            Fix                   = 'Update-MpSignature'
            Check                 = {
                $status = Get-MpComputerStatus -ErrorAction Stop
                $age = Get-ObjectProperty -Object $status -Name 'AntivirusSignatureAge'
                if ($null -eq $age) {
                    return New-CheckResult -Status Warn -Detail 'Возраст баз не определяется'
                }
                $age = [int]$age
                if ($age -le 3) {
                    return New-CheckResult -Status Pass -Detail "Базы обновлены $age дн. назад"
                }
                return New-CheckResult -Status Warn -Detail "Базы устарели: $age дн."
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-004'
            Title                 = 'Протокол SMBv1 отключён'
            Category              = 'Сеть'
            Severity              = 'High'
            RequiresAdministrator = $true
            Fix                   = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
            Check                 = {
                $config = Get-SmbServerConfiguration -ErrorAction Stop
                $enabled = Get-ObjectProperty -Object $config -Name 'EnableSMB1Protocol'
                if ($enabled) {
                    return New-CheckResult -Status Fail -Detail 'SMBv1 включён (уязвим к EternalBlue/WannaCry)'
                }
                return New-CheckResult -Status Pass -Detail 'SMBv1 отключён'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-005'
            Title                 = 'Обязательная подпись SMB включена'
            Category              = 'Сеть'
            Severity              = 'Medium'
            RequiresAdministrator = $true
            Fix                   = 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
            Check                 = {
                $config = Get-SmbServerConfiguration -ErrorAction Stop
                $required = Get-ObjectProperty -Object $config -Name 'RequireSecuritySignature'
                if ($required) {
                    return New-CheckResult -Status Pass -Detail 'Подпись SMB обязательна'
                }
                return New-CheckResult -Status Fail -Detail 'Подпись SMB не обязательна (возможна подмена трафика)'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-006'
            Title                 = 'Контроль учётных записей (UAC) включён'
            Category              = 'Учётные записи'
            Severity              = 'High'
            RequiresAdministrator = $false
            Fix                   = 'Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1; перезагрузка'
            Check                 = {
                $value = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
                if ($null -eq $value) {
                    return New-CheckResult -Status Error -Detail 'Параметр EnableLUA не найден в реестре'
                }
                if ([int]$value -eq 1) {
                    return New-CheckResult -Status Pass -Detail 'UAC включён'
                }
                return New-CheckResult -Status Fail -Detail 'UAC отключён: программы получают полные права без подтверждения'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-007'
            Title                 = 'Встроенная учётная запись «Гость» отключена'
            Category              = 'Учётные записи'
            Severity              = 'Medium'
            RequiresAdministrator = $false
            Fix                   = 'Disable-LocalUser -Name Guest'
            Check                 = {
                $guests = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' })
                if ($guests.Count -eq 0) {
                    return New-CheckResult -Status Pass -Detail 'Учётная запись гостя отсутствует'
                }
                $enabled = @($guests | Where-Object { $_.Enabled })
                if ($enabled.Count -gt 0) {
                    return New-CheckResult -Status Fail -Detail 'Учётная запись гостя включена'
                }
                return New-CheckResult -Status Pass -Detail 'Учётная запись гостя отключена'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-008'
            Title                 = 'Пароль автовхода не хранится в реестре'
            Category              = 'Учётные записи'
            Severity              = 'Critical'
            RequiresAdministrator = $false
            Fix                   = 'Удалить значение DefaultPassword в HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon и отключить автовход'
            Check                 = {
                $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                $item = $null
                try {
                    $item = Get-ItemProperty -Path $path -ErrorAction Stop
                }
                catch {
                    $item = $null
                }
                if ($null -eq $item) {
                    return New-CheckResult -Status Error -Detail 'Не удалось прочитать раздел Winlogon'
                }
                if ($null -ne (Get-ObjectProperty -Object $item -Name 'DefaultPassword')) {
                    return New-CheckResult -Status Fail -Detail 'Пароль автовхода хранится в открытом виде (DefaultPassword)'
                }
                return New-CheckResult -Status Pass -Detail 'Пароль автовхода в реестре не найден'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-009'
            Title                 = 'Удалённый рабочий стол защищён NLA'
            Category              = 'Сеть'
            Severity              = 'High'
            RequiresAdministrator = $false
            Fix                   = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1'
            Check                 = {
                $deny = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
                if ($null -eq $deny) {
                    return New-CheckResult -Status Error -Detail 'Не удалось прочитать настройки терминальной службы'
                }
                if ([int]$deny -eq 1) {
                    return New-CheckResult -Status Pass -Detail 'Удалённый рабочий стол отключён'
                }
                $nla = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
                if ($null -ne $nla -and [int]$nla -eq 1) {
                    return New-CheckResult -Status Pass -Detail 'RDP включён, проверка подлинности на уровне сети требуется'
                }
                return New-CheckResult -Status Fail -Detail 'RDP включён без NLA: возможен перебор паролей'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-010'
            Title                 = 'Системный диск зашифрован BitLocker'
            Category              = 'Данные'
            Severity              = 'High'
            RequiresAdministrator = $true
            Fix                   = 'Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector'
            Check                 = {
                $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
                $protection = Get-ObjectProperty -Object $volume -Name 'ProtectionStatus'
                if ("$protection" -eq 'On') {
                    return New-CheckResult -Status Pass -Detail 'Защита BitLocker включена'
                }
                return New-CheckResult -Status Fail -Detail "Защита BitLocker не включена (статус: $protection)"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-011'
            Title                 = 'Windows получает обновления (последнее — не старше 30 дней)'
            Category              = 'Обновления'
            Severity              = 'Medium'
            RequiresAdministrator = $true
            Fix                   = 'Установить обновления: Settings > Windows Update > Check for updates'
            Check                 = {
                $hotfixes = @(Get-HotFix -ErrorAction Stop)
                $dated = @($hotfixes | Where-Object { $null -ne (Get-ObjectProperty -Object $_ -Name 'InstalledOn') })
                if ($dated.Count -eq 0) {
                    return New-CheckResult -Status Warn -Detail 'Даты установки обновлений недоступны'
                }
                $latest = $dated | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
                $days = [int]((Get-Date) - $latest.InstalledOn).TotalDays
                if ($days -le 30) {
                    return New-CheckResult -Status Pass -Detail "Последнее обновление $days дн. назад ($($latest.HotFixID))"
                }
                return New-CheckResult -Status Warn -Detail "Последнее обновление $days дн. назад ($($latest.HotFixID))"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-012'
            Title                 = 'Минимальная длина пароля не меньше 12 символов'
            Category              = 'Политика паролей'
            Severity              = 'Medium'
            RequiresAdministrator = $false
            Fix                   = 'net accounts /minpwlen:12'
            Check                 = {
                $value = Get-NetAccountsNumber -Keys @('Minimum password length', 'Минимальная длина пароля')
                if ($null -eq $value) {
                    return New-CheckResult -Status Warn -Detail 'Не удалось разобрать вывод net accounts'
                }
                if ($value -ge 12) {
                    return New-CheckResult -Status Pass -Detail "Минимальная длина пароля: $value"
                }
                return New-CheckResult -Status Fail -Detail "Слишком короткий минимум: $value символов"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-013'
            Title                 = 'Блокировка учётной записи после неудачных входов'
            Category              = 'Политика паролей'
            Severity              = 'Medium'
            RequiresAdministrator = $false
            Fix                   = 'net accounts /lockoutthreshold:10'
            Check                 = {
                $threshold = Get-NetAccountsNumber -Keys @('Lockout threshold', 'Порог блокировки')
                if ($null -eq $threshold) {
                    return New-CheckResult -Status Warn -Detail 'Не удалось разобрать вывод net accounts'
                }
                if ($threshold -eq 0) {
                    return New-CheckResult -Status Fail -Detail 'Блокировка не настроена: пароли можно перебирать бесконечно'
                }
                if ($threshold -le 10) {
                    return New-CheckResult -Status Pass -Detail "Блокировка после $threshold неудачных попыток"
                }
                return New-CheckResult -Status Warn -Detail "Слишком мягкий порог блокировки: $threshold попыток"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-014'
            Title                 = 'Журнал безопасности включён и достаточно велик'
            Category              = 'Аудит'
            Severity              = 'Low'
            RequiresAdministrator = $true
            Fix                   = 'wevtutil sl Security /ms:134217728'
            Check                 = {
                $log = Get-WinEvent -ListLog Security -ErrorAction Stop
                $enabled = Get-ObjectProperty -Object $log -Name 'IsEnabled'
                $maxBytes = Get-ObjectProperty -Object $log -Name 'MaximumSizeInBytes'
                if (-not $enabled) {
                    return New-CheckResult -Status Fail -Detail 'Журнал безопасности отключён'
                }
                $maxMb = [int][math]::Round(([double]$maxBytes) / 1MB)
                if ($maxMb -ge 64) {
                    return New-CheckResult -Status Pass -Detail "Журнал включён, максимальный размер $maxMb МБ"
                }
                return New-CheckResult -Status Warn -Detail "Журнал включён, но мал: $maxMb МБ (рекомендуется от 64 МБ)"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-015'
            Title                 = 'Безопасная загрузка (Secure Boot) включена'
            Category              = 'Загрузка'
            Severity              = 'Medium'
            RequiresAdministrator = $true
            Fix                   = 'Включить Secure Boot в настройках UEFI'
            Check                 = {
                $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
                if ($enabled) {
                    return New-CheckResult -Status Pass -Detail 'Secure Boot включён'
                }
                return New-CheckResult -Status Fail -Detail 'Secure Boot выключен'
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-016'
            Title                 = 'Локальных администраторов немного'
            Category              = 'Учётные записи'
            Severity              = 'Low'
            RequiresAdministrator = $false
            Fix                   = 'Remove-LocalGroupMember -Group Administrators -Member <лишний пользователь>'
            Check                 = {
                $group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
                $members = @(Get-LocalGroupMember -Group $group -ErrorAction Stop)
                if ($members.Count -le 3) {
                    return New-CheckResult -Status Pass -Detail "Участников: $($members.Count)"
                }
                $names = (@($members | ForEach-Object { $_.Name }) -join ', ')
                return New-CheckResult -Status Warn -Detail "Участников: $($members.Count) — $names"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-017'
            Title                 = 'Защита LSA (RunAsPPL) включена'
            Category              = 'Защита процессов'
            Severity              = 'Medium'
            RequiresAdministrator = $false
            Fix                   = 'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1; перезагрузка'
            Check                 = {
                $value = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
                if ($null -eq $value) {
                    return New-CheckResult -Status Fail -Detail 'RunAsPPL не задан: LSASS можно читать дампами'
                }
                if ([int]$value -eq 1) {
                    return New-CheckResult -Status Pass -Detail 'LSASS работает как защищённый процесс'
                }
                return New-CheckResult -Status Warn -Detail "Нестандартное значение RunAsPPL: $value"
            }
        }

        [pscustomobject]@{
            Id                    = 'SEC-018'
            Title                 = 'Журналирование блоков сценариев PowerShell включено'
            Category              = 'Аудит'
            Severity              = 'Low'
            RequiresAdministrator = $false
            Fix                   = 'Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1'
            Check                 = {
                $value = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
                if ($null -ne $value -and [int]$value -eq 1) {
                    return New-CheckResult -Status Pass -Detail 'Script Block Logging включён'
                }
                return New-CheckResult -Status Warn -Detail 'Script Block Logging не включён: действия злоумышленника в PowerShell не пишутся в журнал'
            }
        }
    )
}


# --------------------------------------------------------------------------
# Выполнение проверок
# --------------------------------------------------------------------------

function Invoke-SecurityCheck {
    <#
    .SYNOPSIS
        Выполняет одну проверку и оборачивает её результат в единую структуру.
    #>
    param(
        [Parameter(Mandatory)]$Definition,
        [bool]$IsAdministrator
    )

    $started = Get-Date
    $status = 'Error'
    $detail = ''
    $fix = [string]$Definition.Fix

    if ($Definition.RequiresAdministrator -and -not $IsAdministrator) {
        $status = 'Skip'
        $detail = 'Нужны права администратора'
    }
    else {
        try {
            $result = & $Definition.Check
            if ($null -eq $result) {
                $status = 'Error'
                $detail = 'Проверка не вернула результат'
            }
            else {
                $status = [string]$result.Status
                $detail = [string]$result.Detail
                $resultFix = [string](Get-ObjectProperty -Object $result -Name 'Fix')
                if (-not [string]::IsNullOrWhiteSpace($resultFix)) {
                    $fix = $resultFix
                }
            }
        }
        catch {
            $status = 'Error'
            $detail = $_.Exception.Message
        }
    }

    [pscustomobject]@{
        Id                    = $Definition.Id
        Title                 = $Definition.Title
        Category              = $Definition.Category
        Severity              = $Definition.Severity
        RequiresAdministrator = $Definition.RequiresAdministrator
        Status                = $status
        Detail                = $detail
        Fix                   = $fix
        DurationMs            = [math]::Round(((Get-Date) - $started).TotalMilliseconds, 1)
    }
}

function Get-SecuritySummary {
    <#
    .SYNOPSIS
        Считает статистику и оценку защищённости по результатам проверок.
    #>
    param([object[]]$Results)

    $counts = [ordered]@{ Pass = 0; Fail = 0; Warn = 0; Skip = 0; Error = 0 }
    $severityCounts = [ordered]@{ Low = 0; Medium = 0; High = 0; Critical = 0 }
    foreach ($result in $Results) {
        $counts[$result.Status] = $counts[$result.Status] + 1
        if ($result.Status -eq 'Fail') {
            $severityCounts[$result.Severity] = $severityCounts[$result.Severity] + 1
        }
    }

    $earned = 0.0
    $possible = 0.0
    foreach ($result in $Results) {
        if ($result.Status -eq 'Skip' -or $result.Status -eq 'Error') {
            continue
        }
        $weight = [double]$script:SeverityWeight[$result.Severity]
        $possible += $weight
        if ($result.Status -eq 'Pass') {
            $earned += $weight
        }
        elseif ($result.Status -eq 'Warn') {
            $earned += $weight * 0.5
        }
    }

    if ($possible -gt 0) {
        $score = [int][math]::Round(100 * $earned / $possible)
    }
    else {
        $score = 0
    }

    if ($possible -eq 0) {
        $verdict = 'недостаточно данных'
    }
    elseif ($score -ge 90) {
        $verdict = 'отлично'
    }
    elseif ($score -ge 75) {
        $verdict = 'хорошо'
    }
    elseif ($score -ge 50) {
        $verdict = 'удовлетворительно'
    }
    else {
        $verdict = 'плохо'
    }

    [pscustomobject]@{
        Total              = $Results.Count
        Pass               = $counts['Pass']
        Fail               = $counts['Fail']
        Warn               = $counts['Warn']
        Skip               = $counts['Skip']
        Error              = $counts['Error']
        FailBySeverity     = $severityCounts
        Score              = $score
        Verdict            = $verdict
        SkippedForRights   = @($Results | Where-Object {
                $_.Status -eq 'Skip' -and $_.Detail -eq 'Нужны права администратора'
            }).Count
    }
}


# --------------------------------------------------------------------------
# Формирование отчётов
# --------------------------------------------------------------------------

function Format-SecurityConsoleReport {
    <# Текстовый отчёт для консоли. #>
    param(
        [object[]]$Results,
        $Summary,
        [hashtable]$Metadata,
        [bool]$UseColor,
        [bool]$ShowUnknown
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('=' * 74)
    $lines.Add(' Аудит базовых настроек безопасности Windows')
    $lines.Add('=' * 74)
    $lines.Add(('Компьютер:     {0}' -f $Metadata.Computer))
    $rights = if ($Metadata.IsAdministrator) { 'есть' } else { 'нет' }
    $lines.Add(('Пользователь:  {0} (права администратора: {1})' -f $Metadata.User, $rights))
    $lines.Add(('Версия ОС:     {0}' -f $Metadata.OsVersion))
    $lines.Add(('Дата:          {0}' -f $Metadata.Timestamp))
    $lines.Add('')
    $checksWord = Get-PluralForm -Number $Summary.Total -One 'проверка' -Few 'проверки' -Many 'проверок'
    $lines.Add(('Итог: {0} {1} — пройдено {2}, нарушено {3}, внимание {4}, пропущено {5}, ошибок {6}' -f `
                $Summary.Total, $checksWord, $Summary.Pass, $Summary.Fail, $Summary.Warn, $Summary.Skip, $Summary.Error))
    $lines.Add(('Оценка защищённости: {0}/100 — {1}' -f $Summary.Score, $Summary.Verdict))
    if ($Summary.SkippedForRights -gt 0) {
        $lines.Add(('Запустите PowerShell от имени администратора, чтобы проверить ещё {0}.' -f $Summary.SkippedForRights))
    }
    $lines.Add('')
    $lines.Add(('{0}  {1}  {2}  {3}' -f 'ID'.PadRight(9), 'СТАТУС'.PadRight(11), 'ВАЖНОСТЬ'.PadRight(9), 'ПРОВЕРКА'))
    $lines.Add('-' * 74)

    foreach ($result in $Results) {
        $statusText = $script:StatusRu[$result.Status].PadRight(11)
        if ($UseColor) {
            $code = $script:StatusAnsi[$result.Status]
            $statusText = "`e[${code}m$statusText`e[0m"
        }
        $title = [string]$result.Title
        if ($title.Length -gt 44) {
            $title = $title.Substring(0, 43) + '…'
        }
        $lines.Add(('{0}  {1}  {2}  {3}' -f $result.Id.PadRight(9), $statusText, $result.Severity.PadRight(9), $title))
    }

    $toFix = @($Results | Where-Object { $_.Status -eq 'Fail' })
    if ($toFix.Count -gt 0) {
        $lines.Add('')
        $lines.Add(('Что исправить ({0}):' -f $toFix.Count))
        $number = 0
        foreach ($result in $toFix) {
            $number++
            $lines.Add(('{0}. {1} [{2}] {3}' -f $number, $result.Id, $result.Severity, $result.Title))
            if (-not [string]::IsNullOrWhiteSpace($result.Detail)) {
                $lines.Add(('   Сейчас: {0}' -f $result.Detail))
            }
            if (-not [string]::IsNullOrWhiteSpace($result.Fix)) {
                $lines.Add(('   Как исправить: {0}' -f $result.Fix))
            }
        }
    }

    if ($ShowUnknown) {
        $unknown = @($Results | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Skip' })
        if ($unknown.Count -gt 0) {
            $lines.Add('')
            $lines.Add(('Не удалось проверить ({0}):' -f $unknown.Count))
            foreach ($result in $unknown) {
                $lines.Add(('   {0} [{1}] {2}' -f $result.Id, $script:StatusRu[$result.Status], $result.Detail))
            }
        }
    }

    return ($lines -join [Environment]::NewLine)
}

function ConvertTo-SecurityHtml {
    <# Самодостаточный HTML-отчёт без внешних зависимостей. #>
    param(
        [object[]]$Results,
        $Summary,
        [hashtable]$Metadata
    )

    $encode = { param($text) [System.Net.WebUtility]::HtmlEncode([string]$text) }
    $colors = @{ Pass = '#1a7f37'; Fail = '#cf222e'; Warn = '#9a6700'; Skip = '#6e7781'; Error = '#8250df' }
    $backgrounds = @{ Pass = '#e6f4ea'; Fail = '#ffebe9'; Warn = '#fff8c5'; Skip = '#f6f8fa'; Error = '#fbefff' }

    $rows = foreach ($result in $Results) {
        $color = $colors[$result.Status]
        $background = $backgrounds[$result.Status]
        $line = '<tr>' +
                "<td class=""mono"">$(& $encode $result.Id)</td>" +
                "<td><span class=""badge"" style=""color:$color;background:$background"">$(& $encode $script:StatusRu[$result.Status])</span></td>" +
                "<td>$( & $encode $result.Severity )</td>" +
                "<td>$( & $encode $result.Title )<div class=""detail"">$( & $encode $result.Detail )</div></td>" +
                "<td class=""fix"">$( & $encode $result.Fix )</td>" +
                '</tr>'
        $line
    }

    $style = @'
body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; padding: 32px; color: #1f2328; background: #ffffff; }
h1 { font-size: 22px; margin: 0 0 4px; }
.meta { color: #59636e; font-size: 13px; margin-bottom: 20px; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
.card { border: 1px solid #d1d9e0; border-radius: 8px; padding: 12px 18px; min-width: 120px; }
.card .value { font-size: 24px; font-weight: 600; }
.card .label { font-size: 12px; color: #59636e; text-transform: uppercase; letter-spacing: 0.04em; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eaeef2; vertical-align: top; }
th { background: #f6f8fa; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #59636e; }
.mono { font-family: Consolas, monospace; white-space: nowrap; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.detail { color: #59636e; font-size: 12px; margin-top: 2px; }
.fix { font-family: Consolas, monospace; font-size: 12px; color: #0a3069; }
.footer { margin-top: 24px; color: #59636e; font-size: 12px; }
'@

    $rowsHtml = ($rows -join [Environment]::NewLine)
    $generated = & $encode $Metadata.Timestamp
    $score = $Summary.Score
    $verdict = & $encode $Summary.Verdict

    return @"
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Аудит безопасности — $(& $encode $Metadata.Computer)</title>
<style>
$style
</style>
</head>
<body>
<h1>Аудит базовых настроек безопасности Windows</h1>
<div class="meta">
Компьютер: $(& $encode $Metadata.Computer) · Пользователь: $(& $encode $Metadata.User) ·
Права администратора: $(if ($Metadata.IsAdministrator) { 'есть' } else { 'нет' }) ·
ОС: $(& $encode $Metadata.OsVersion) · Отчёт создан: $generated
</div>
<div class="cards">
  <div class="card"><div class="value">$score/100</div><div class="label">Оценка</div></div>
  <div class="card"><div class="value">$verdict</div><div class="label">Вердикт</div></div>
  <div class="card"><div class="value">$($Summary.Pass)</div><div class="label">Пройдено</div></div>
  <div class="card"><div class="value">$($Summary.Fail)</div><div class="label">Нарушено</div></div>
  <div class="card"><div class="value">$($Summary.Warn)</div><div class="label">Внимание</div></div>
  <div class="card"><div class="value">$($Summary.Skip)</div><div class="label">Пропущено</div></div>
  <div class="card"><div class="value">$($Summary.Error)</div><div class="label">Ошибок</div></div>
</div>
<table>
<thead>
<tr><th>ID</th><th>Статус</th><th>Важность</th><th>Проверка</th><th>Как исправить</th></tr>
</thead>
<tbody>
$rowsHtml
</tbody>
</table>
<div class="footer">
Всего проверок: $($Summary.Total). Оценка считается по выполненным проверкам:
пропущенные и завершившиеся ошибкой не входят в расчёт.
</div>
</body>
</html>
"@
}


# --------------------------------------------------------------------------
# Основной сценарий
# --------------------------------------------------------------------------

$definitions = @(Get-SecurityCheckDefinition)

if ($List) {
    $definitions |
        Select-Object Id, Severity, Category, Title, RequiresAdministrator |
        Format-Table -AutoSize |
        Out-String |
        Write-Output
    exit 0
}

if ($Only.Count -gt 0) {
    $knownIds = @($definitions | ForEach-Object { $_.Id })
    $unknownIds = @($Only | Where-Object { $_ -notin $knownIds })
    if ($unknownIds.Count -gt 0) {
        Write-Warning ("Неизвестные идентификаторы проверок: {0}" -f ($unknownIds -join ', '))
    }
    $definitions = @($definitions | Where-Object { $_.Id -in $Only })
}

if ($Skip.Count -gt 0) {
    $definitions = @($definitions | Where-Object { $_.Id -notin $Skip })
}

if ($definitions.Count -eq 0) {
    [Console]::Error.WriteLine('Не выбрано ни одной проверки: проверьте параметры -Only и -Skip.')
    exit 2
}

$isAdministrator = Test-IsAdministrator
$results = foreach ($definition in $definitions) {
    Invoke-SecurityCheck -Definition $definition -IsAdministrator $isAdministrator
}
$results = @($results)
$summary = Get-SecuritySummary -Results $results

$osVersion = 'неизвестно'
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osVersion = ('{0} {1}' -f $os.Caption, $os.Version).Trim()
}
catch {
    $osVersion = [System.Environment]::OSVersion.VersionString
}

$metadata = @{
    Computer        = $env:COMPUTERNAME
    User            = [Environment]::UserName
    IsAdministrator = $isAdministrator
    OsVersion       = $osVersion
    Timestamp       = (Get-Date).ToString('dd.MM.yyyy HH:mm:ss')
    IsoTimestamp    = (Get-Date).ToString('s')
}

# Формат: явный параметр важнее расширения файла.
$format = $OutputFormat
if (-not $PSBoundParameters.ContainsKey('OutputFormat') -and -not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $extension = [IO.Path]::GetExtension($OutputPath).ToLowerInvariant()
    $format = switch ($extension) {
        '.json' { 'Json' }
        '.csv' { 'Csv' }
        '.html' { 'Html' }
        '.htm' { 'Html' }
        default { 'Console' }
    }
}

$useColor = -not $NoColor -and -not [Console]::IsOutputRedirected

$consoleReport = Format-SecurityConsoleReport -Results $results -Summary $summary `
    -Metadata $metadata -UseColor $useColor -ShowUnknown ([bool]$IncludeUnknown)

$payload = [ordered]@{
    tool             = 'Test-SecurityBaseline'
    version          = $script:Version
    generated_at     = $metadata.IsoTimestamp
    computer         = $metadata.Computer
    user             = $metadata.User
    os_version       = $metadata.OsVersion
    is_administrator = $metadata.IsAdministrator
    fail_on          = $FailOn
    summary          = [ordered]@{
        total            = $summary.Total
        pass             = $summary.Pass
        fail             = $summary.Fail
        warn             = $summary.Warn
        skip             = $summary.Skip
        error            = $summary.Error
        fail_by_severity = $summary.FailBySeverity
        score            = $summary.Score
        verdict          = $summary.Verdict
    }
    checks           = $results
}

if (-not $Quiet) {
    if ($format -eq 'Console') {
        Write-Output $consoleReport
    }
    elseif ($format -eq 'Json') {
        Write-Output ($payload | ConvertTo-Json -Depth 6)
    }
    elseif ($format -eq 'Csv') {
        Write-Output ($results |
            Select-Object Id, Title, Category, Severity, Status, RequiresAdministrator, Detail, Fix |
            ConvertTo-Csv -NoTypeInformation)
    }
    elseif ($format -eq 'Html') {
        Write-Output (ConvertTo-SecurityHtml -Results $results -Summary $summary -Metadata $metadata)
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $content = switch ($format) {
        'Json' { $payload | ConvertTo-Json -Depth 6 }
        'Csv' { $results | Select-Object Id, Title, Category, Severity, Status, RequiresAdministrator, Detail, Fix | ConvertTo-Csv -NoTypeInformation }
        'Html' { ConvertTo-SecurityHtml -Results $results -Summary $summary -Metadata $metadata }
        default { $consoleReport }
    }
    try {
        $parent = Split-Path -Path $OutputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Set-Content -LiteralPath $OutputPath -Value $content -Encoding utf8
        if (-not $Quiet) {
            Write-Output ''
            Write-Output ("Отчёт сохранён: {0}" -f (Resolve-Path -LiteralPath $OutputPath))
        }
    }
    catch {
        [Console]::Error.WriteLine(("Не удалось записать отчёт: {0}" -f $_.Exception.Message))
        exit 2
    }
}

if ($FailOn -ne 'None') {
    $rank = $script:SeverityRank[$FailOn]
    $blocking = @($results | Where-Object {
            $_.Status -eq 'Fail' -and $script:SeverityRank[$_.Severity] -ge $rank
        })
    if ($blocking.Count -gt 0) {
        exit 1
    }
}

exit 0

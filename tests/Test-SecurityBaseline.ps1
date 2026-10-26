#Requires -Version 7.0
<#
.SYNOPSIS
    Тесты для Test-SecurityBaseline.ps1.

.DESCRIPTION
    Проверяют список проверок, фильтры -Only/-Skip, форматы отчётов
    (JSON, CSV, HTML) и коды возврата. Pester не требуется: только
    встроенные средства PowerShell, поэтому тесты запускаются где угодно.

    Запуск:
        pwsh -File tests/Test-SecurityBaseline.ps1

    Код возврата: 0 — все проверки прошли, 1 — есть провалы.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$auditScript = Join-Path $root 'scripts/security_audit/Test-SecurityBaseline.ps1'
$tmp = Join-Path $root '.test-tmp'
if (-not (Test-Path -LiteralPath $tmp)) {
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
}

$script:Passed = 0
$script:Failed = 0
$LASTEXITCODE = 0

function Write-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
}

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Condition) {
        $script:Passed++
        Write-Host "  ok   $Message" -ForegroundColor DarkGray
    }
    else {
        $script:Failed++
        Write-Host "  FAIL $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    param(
        $Expected,
        $Actual,
        [Parameter(Mandatory)][string]$Message
    )
    $same = $false
    if ($null -eq $Expected -and $null -eq $Actual) {
        $same = $true
    }
    elseif ($null -ne $Expected -and $null -ne $Actual) {
        $same = [string]$Expected -eq [string]$Actual
    }
    Assert-True -Condition $same -Message "$Message (ожидалось «$Expected», получено «$Actual»)"
}

# --- 1. Список проверок -----------------------------------------------------
Write-Header 'Список проверок'
$listOutput = (& $auditScript -List 2>&1 | Out-String)
Assert-True -Condition ($LASTEXITCODE -eq 0) -Message '-List завершается с кодом 0'
Assert-True -Condition ($listOutput -match 'SEC-001' -and $listOutput -match 'SEC-018') `
    -Message 'в списке есть первая и последняя проверки'
Assert-Equal -Expected 18 -Actual ([regex]::Matches($listOutput, 'SEC-\d{3}').Count) `
    -Message 'в списке ровно 18 проверок'

# --- 2. JSON-отчёт ----------------------------------------------------------
Write-Header 'JSON-отчёт'
$jsonPath = Join-Path $tmp 'baseline.json'
& $auditScript -OutputFormat Json -OutputPath $jsonPath -FailOn None -Quiet
Assert-True -Condition ($LASTEXITCODE -eq 0) -Message 'JSON-отчёт создаётся без ошибок'
$report = Get-Content -LiteralPath $jsonPath -Raw -Encoding utf8 | ConvertFrom-Json

Assert-Equal -Expected 'Test-SecurityBaseline' -Actual $report.tool -Message 'поле tool'
Assert-Equal -Expected 18 -Actual $report.summary.total -Message 'в сводке 18 проверок'
Assert-Equal -Expected 18 -Actual $report.checks.Count -Message 'в checks 18 записей'
Assert-True -Condition ($report.summary.score -ge 0 -and $report.summary.score -le 100) `
    -Message 'оценка в диапазоне 0..100'
Assert-True -Condition ($report.summary.verdict -match '^(отлично|хорошо|удовлетворительно|плохо|недостаточно данных)$') `
    -Message 'вердикт из допустимого набора'
Assert-True -Condition ($report.is_administrator -is [bool]) -Message 'флаг администратора — логическое значение'
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($report.generated_at)) -Message 'есть дата создания'

$allowedStatuses = @('Pass', 'Fail', 'Warn', 'Skip', 'Error')
$unexpected = @($report.checks | Where-Object { $_.Status -notin $allowedStatuses })
Assert-Equal -Expected 0 -Actual $unexpected.Count -Message 'все статусы допустимы'
$withoutDetail = @($report.checks | Where-Object { $null -eq $_.PSObject.Properties['Detail'] })
Assert-Equal -Expected 0 -Actual $withoutDetail.Count -Message 'у каждой проверки есть поле Detail'

# --- 3. Фильтры -------------------------------------------------------------
Write-Header 'Фильтры -Only и -Skip'
$skipPath = Join-Path $tmp 'baseline-skip.json'
& $auditScript -OutputFormat Json -OutputPath $skipPath -FailOn None -Quiet -Skip 'SEC-001', 'SEC-002'
$skipReport = Get-Content -LiteralPath $skipPath -Raw -Encoding utf8 | ConvertFrom-Json
Assert-Equal -Expected 16 -Actual $skipReport.checks.Count -Message '-Skip убирает две проверки'
Assert-True -Condition (-not ($skipReport.checks.Id -contains 'SEC-001')) -Message 'SEC-001 отсутствует'

$onlyPath = Join-Path $tmp 'baseline-only.json'
& $auditScript -OutputFormat Json -OutputPath $onlyPath -FailOn None -Quiet -Only 'SEC-006', 'SEC-008'
$onlyReport = Get-Content -LiteralPath $onlyPath -Raw -Encoding utf8 | ConvertFrom-Json
Assert-Equal -Expected 2 -Actual $onlyReport.checks.Count -Message '-Only оставляет две проверки'
Assert-Equal -Expected 'SEC-006,SEC-008' -Actual (@($onlyReport.checks.Id) -join ',') -Message 'порядок проверок сохранён'

# --- 4. CSV -----------------------------------------------------------------
Write-Header 'CSV-отчёт'
$csvPath = Join-Path $tmp 'baseline.csv'
& $auditScript -OutputFormat Csv -OutputPath $csvPath -FailOn None -Quiet
$csvLines = @(Get-Content -LiteralPath $csvPath -Encoding utf8)
Assert-True -Condition ($csvLines[0] -like '"Id","Title"*') -Message 'заголовок CSV на месте'
Assert-Equal -Expected 19 -Actual $csvLines.Count -Message '18 строк данных + заголовок'

# --- 5. HTML ----------------------------------------------------------------
Write-Header 'HTML-отчёт'
$htmlPath = Join-Path $tmp 'baseline.html'
& $auditScript -OutputFormat Html -OutputPath $htmlPath -FailOn None -Quiet
$html = Get-Content -LiteralPath $htmlPath -Raw -Encoding utf8
Assert-True -Condition ($html -match '<!DOCTYPE html>') -Message 'HTML-документ начинается с DOCTYPE'
Assert-True -Condition ($html -match 'SEC-018') -Message 'HTML содержит проверки'
Assert-True -Condition ($html -match 'Оценка') -Message 'HTML содержит оценку защищённости'
Assert-True -Condition ($html -match 'charset="utf-8"') -Message 'HTML объявляет кодировку UTF-8'

# --- 6. Консоль и коды возврата --------------------------------------------
Write-Header 'Консоль и коды возврата'
$consoleOutput = (& $auditScript -FailOn None -NoColor | Out-String)
Assert-True -Condition ($consoleOutput -match 'Аудит базовых настроек') -Message 'консольный отчёт содержит заголовок'
Assert-True -Condition ($consoleOutput -match 'Оценка защищённости') -Message 'консольный отчёт содержит оценку'

& $auditScript -FailOn None -Quiet
Assert-Equal -Expected 0 -Actual $LASTEXITCODE -Message 'FailOn None даёт код 0'

$null = & $auditScript -Only 'SEC-999' -Quiet 2>&1
Assert-Equal -Expected 2 -Actual $LASTEXITCODE -Message 'неизвестная проверка даёт код 2'

$unknownOutput = (& $auditScript -FailOn None -NoColor -IncludeUnknown | Out-String)
Assert-True -Condition ($unknownOutput.Length -gt 0) -Message '-IncludeUnknown не ломает отчёт'

# --- Итог -------------------------------------------------------------------
Write-Host ''
if ($script:Failed -gt 0) {
    Write-Host ("Провалено: {0}, пройдено: {1}" -f $script:Failed, $script:Passed) -ForegroundColor Red
    exit 1
}
Write-Host ("Все {0} проверок пройдены." -f $script:Passed) -ForegroundColor Green
exit 0

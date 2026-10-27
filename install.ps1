# Установщик «Стража»: собирает Strazh.exe, ставит в Program Files,
# создаёт ярлыки (рабочий стол + меню Пуск) и автозапуск с правами администратора.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# --- права администратора -------------------------------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit
}
Set-Location $PSScriptRoot
$Host.UI.RawUI.WindowTitle = 'Установка Стража'
function Step($t) { Write-Host "`n==> $t" -ForegroundColor Cyan }

# --- окно выбора параметров ------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Установка Стража'
$form.Size = New-Object System.Drawing.Size(520, 400)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(14, 17, 22)
$form.ForeColor = [System.Drawing.Color]::FromArgb(230, 237, 243)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$form.TopMost = $true
if (Test-Path "$PSScriptRoot\icon.ico") { $form.Icon = New-Object System.Drawing.Icon("$PSScriptRoot\icon.ico") }

$title = New-Object System.Windows.Forms.Label
$title.Text = '◆ СТРАЖ'; $title.Font = New-Object System.Drawing.Font('Segoe UI', 20, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(79, 140, 255); $title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(24, 18); $form.Controls.Add($title)
$sub = New-Object System.Windows.Forms.Label
$sub.Text = 'Выберите, как будет работать программа:'; $sub.AutoSize = $true
$sub.ForeColor = [System.Drawing.Color]::FromArgb(139, 150, 165)
$sub.Location = New-Object System.Drawing.Point(26, 64); $form.Controls.Add($sub)

$y = 100
function New-Check($text, $hint) {
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $text; $c.Checked = $true; $c.AutoSize = $true
    $c.Location = New-Object System.Drawing.Point(28, $script:y); $form.Controls.Add($c)
    $h = New-Object System.Windows.Forms.Label
    $h.Text = $hint; $h.AutoSize = $true; $h.ForeColor = [System.Drawing.Color]::FromArgb(139, 150, 165)
    $h.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
    $h.Location = New-Object System.Drawing.Point(46, ($script:y + 24)); $form.Controls.Add($h)
    $script:y += 56
    return $c
}
$cbAdmin = New-Check 'Всегда запускать от имени администратора' 'Без окна «Разрешить?» каждый раз. Нужно, чтобы видеть все процессы.'
$cbAuto  = New-Check 'Запускать при включении компьютера' 'Страж тихо стартует и следит за системой из трея возле часов.'
$cbDesk  = New-Check 'Ярлык на рабочем столе' 'Ярлык в меню Пуск создаётся всегда — Страж можно найти поиском.'

$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Установить'; $ok.Size = New-Object System.Drawing.Size(150, 38)
$ok.Location = New-Object System.Drawing.Point(334, 300)
$ok.FlatStyle = 'Flat'; $ok.FlatAppearance.BorderSize = 0
$ok.BackColor = [System.Drawing.Color]::FromArgb(79, 140, 255); $ok.ForeColor = [System.Drawing.Color]::White
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.AcceptButton = $ok; $form.Controls.Add($ok)
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Отмена'; $cancel.Size = New-Object System.Drawing.Size(110, 38)
$cancel.Location = New-Object System.Drawing.Point(214, 300)
$cancel.FlatStyle = 'Flat'; $cancel.FlatAppearance.BorderSize = 0
$cancel.BackColor = [System.Drawing.Color]::FromArgb(28, 35, 48)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.CancelButton = $cancel; $form.Controls.Add($cancel)

if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { exit }
$wantAdmin = $cbAdmin.Checked; $wantAuto = $cbAuto.Checked; $wantDesk = $cbDesk.Checked

try {
    Write-Host '=============================================' -ForegroundColor Blue
    Write-Host '        СТРАЖ — установка приложения' -ForegroundColor White
    Write-Host '=============================================' -ForegroundColor Blue

    Step 'Ищу Python'
    $py = (Get-Command py -ErrorAction SilentlyContinue).Source
    if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue).Source }
    if (-not $py) { throw 'Python не найден. Установите его с python.org (галочка "Add python.exe to PATH").' }
    $pyexe = (& $py -c "import sys; print(sys.executable)").Trim()
    Write-Host "Python: $pyexe"

    Step 'Устанавливаю библиотеки (psutil, pystray, pillow, pyinstaller)'
    & $pyexe -m pip install --upgrade --disable-pip-version-check psutil pystray pillow pyinstaller
    if ($LASTEXITCODE) { throw 'pip не смог установить библиотеки (нужен интернет).' }

    $dir = Join-Path $env:ProgramFiles 'Strazh'
    Get-Process Strazh -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*antivirus.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item icon.ico $dir -Force

    Step 'Собираю Strazh.exe (1-3 минуты)'
    $uac = @(); if ($wantAdmin) { $uac = @('--uac-admin') }
    & $pyexe -m PyInstaller --noconfirm --clean --onefile --windowed @uac `
        --name Strazh --icon icon.ico --add-data "icon.ico;." `
        --hidden-import pystray._win32 --hidden-import PIL._tkinter_finder antivirus.py
    if (-not $LASTEXITCODE -and (Test-Path 'dist\Strazh.exe')) {
        Copy-Item 'dist\Strazh.exe' $dir -Force
        $exe  = Join-Path $dir 'Strazh.exe'
        $args0 = ''
        Write-Host 'Strazh.exe собран.' -ForegroundColor Green
    } else {
        Write-Warning 'Собрать .exe не получилось — ставлю версию, которая работает через Python. Работать будет так же.'
        Copy-Item antivirus.py $dir -Force
        $pyw = Join-Path (Split-Path $pyexe) 'pythonw.exe'
        if (-not (Test-Path $pyw)) { $pyw = $pyexe }
        $exe  = $pyw
        $args0 = "`"$(Join-Path $dir 'antivirus.py')`""
    }
    if (-not $wantAdmin) { $args0 = "$args0 --no-admin".Trim() }

    Step 'Создаю задания Планировщика'
    $user = "$env:USERDOMAIN\$env:USERNAME"
    $level = if ($wantAdmin) { 'Highest' } else { 'Limited' }
    $prin = New-ScheduledTaskPrincipal -UserId $user -RunLevel $level -LogonType Interactive
    $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel

    # 1) запуск по ярлыку
    if ($args0) { $actRun = New-ScheduledTaskAction -Execute $exe -Argument $args0 -WorkingDirectory $dir }
    else        { $actRun = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $dir }
    Register-ScheduledTask -TaskName 'Strazh-Launch' -Action $actRun -Principal $prin -Settings $set -Force | Out-Null

    # 2) автозапуск при входе в Windows (сразу в трей)
    $actAuto = New-ScheduledTaskAction -Execute $exe -Argument ("$args0 --tray".Trim()) -WorkingDirectory $dir
    $trig = New-ScheduledTaskTrigger -AtLogOn -User $user
    $trig.Delay = 'PT10S'
    if ($wantAuto) {
        Register-ScheduledTask -TaskName 'Strazh' -Action $actAuto -Trigger $trig -Principal $prin -Settings $set -Force | Out-Null
    } else {
        Unregister-ScheduledTask -TaskName 'Strazh' -Confirm:$false -ErrorAction SilentlyContinue
    }

    Step 'Создаю ярлыки на рабочем столе и в меню Пуск'
    $ws = New-Object -ComObject WScript.Shell
    $iconPath = Join-Path $dir 'icon.ico'
    function New-Lnk($path) {
        $s = $ws.CreateShortcut($path)
        $s.TargetPath = Join-Path $env:WINDIR 'System32\schtasks.exe'
        $s.Arguments = '/run /tn "Strazh-Launch"'
        $s.WorkingDirectory = $dir
        $s.IconLocation = "$iconPath,0"
        $s.WindowStyle = 7
        $s.Description = 'Страж — монитор процессов и антивирус'
        $s.Save()
    }
    $deskLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Страж.lnk'
    if ($wantDesk) { New-Lnk $deskLnk } else { Remove-Item $deskLnk -ErrorAction SilentlyContinue }
    New-Lnk (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Страж.lnk')

    Copy-Item uninstall.ps1 $dir -Force
    Remove-Item build, dist, Strazh.spec -Recurse -Force -ErrorAction SilentlyContinue

    Step 'Запускаю Страж'
    Start-ScheduledTask -TaskName 'Strazh-Launch'

    Write-Host "`nГОТОВО!" -ForegroundColor Green
    Write-Host ' • Ярлык «Страж» — на рабочем столе и в меню Пуск (можно найти поиском).'
    Write-Host ' • Запускается сразу с правами администратора, без окна «Разрешить?».'
    Write-Host ' • Стартует вместе с Windows и сидит в трее возле часов.'
    Write-Host ' • Отключить автозапуск: Страж → Настройки.'
} catch {
    Write-Host "`nОШИБКА: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host "`nНажмите Enter, чтобы закрыть окно..."
[void](Read-Host)

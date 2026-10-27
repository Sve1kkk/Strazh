# Удаление «Стража»
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit
}
Get-Process Strazh -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*antivirus.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName 'Strazh' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Strazh-Launch' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Страж.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Страж.lnk') -Force -ErrorAction SilentlyContinue
Set-Location $env:TEMP
Remove-Item (Join-Path $env:ProgramFiles 'Strazh') -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Страж удалён. Карантин и настройки остались в папке .strazh в вашем профиле.' -ForegroundColor Green
Write-Host 'Нажмите Enter...'; [void](Read-Host)

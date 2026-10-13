<#
Installs FlowScope on Windows as a scheduled task that starts at boot and runs as SYSTEM, and opens the firewall.
Run from an elevated PowerShell in a built checkout:  npm install ; npm run build ; .\packaging\windows\install.ps1
Settings go in %ProgramData%\FlowScope\flowscope.env (one KEY=value per line).
#>
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated (Administrator) PowerShell.' }
$here = Resolve-Path (Join-Path $PSScriptRoot '..\..')
if (-not (Test-Path (Join-Path $here 'dist\src'))) { throw 'dist\ not found. Run: npm install ; npm run build' }
$node = (Get-Command node -ErrorAction Stop).Source
$ver = [version]((& $node -p 'process.versions.node'))
if ($ver -lt [version]'22.13.0') { throw "Node.js 22.13 or newer is required (found $ver)." }

$app  = Join-Path $env:ProgramFiles 'FlowScope'
$data = Join-Path $env:ProgramData 'FlowScope'
New-Item -ItemType Directory -Force $app, $data | Out-Null
Copy-Item (Join-Path $here 'dist') $app -Recurse -Force
Copy-Item (Join-Path $here 'package.json') $app -Force
if (Test-Path (Join-Path $here 'node_modules')) { Copy-Item (Join-Path $here 'node_modules') $app -Recurse -Force }
else { Push-Location $app; npm install --omit=dev --no-audit --no-fund; Pop-Location }

$envFile = Join-Path $data 'flowscope.env'
if (-not (Test-Path $envFile)) {
  "# One KEY=value per line. Example:`r`n# FLOWSCOPE_ADMIN_PASSWORD=change-me-please-12+`r`n" | Set-Content -Encoding ascii $envFile
}
# Wrapper: loads flowscope.env, then runs the server and appends its output to flowscope.log
$wrapper = Join-Path $app 'run.ps1'
@"
`$ErrorActionPreference = 'Continue'
`$env:FLOWSCOPE_DATA_DIR = '$data'
Get-Content '$envFile' | ForEach-Object { if (`$_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') { Set-Item -Path "Env:`$(`$Matches[1])" -Value `$Matches[2] } }
& '$node' --disable-warning=ExperimentalWarning '$app\dist\src\cli.js' start *>> '$data\flowscope.log'
"@ | Set-Content -Encoding ascii $wrapper

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`""
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'FlowScope' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

foreach ($r in @(@{n='FlowScope web (TCP 8443)';p='TCP';port=8443}, @{n='FlowScope flow export (UDP 2055)';p='UDP';port=2055}, @{n='FlowScope IPFIX (UDP 4739)';p='UDP';port=4739})) {
  if (-not (Get-NetFirewallRule -DisplayName $r.n -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName $r.n -Direction Inbound -Protocol $r.p -LocalPort $r.port -Action Allow | Out-Null }
}
Start-ScheduledTask -TaskName 'FlowScope'
Write-Host "FlowScope is starting: https://localhost:8443/"
Write-Host "Log: $data\flowscope.log  (the first-run admin password is printed there if none was set)"

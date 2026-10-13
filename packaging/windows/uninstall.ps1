# Removes the FlowScope scheduled task and firewall rules. Program files and data are left in place; delete them yourself if you want.
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName 'FlowScope'
Unregister-ScheduledTask -TaskName 'FlowScope' -Confirm:$false
Get-NetFirewallRule -DisplayName 'FlowScope*' | Remove-NetFirewallRule
Write-Host 'Removed. Data is kept in %ProgramData%\FlowScope.'

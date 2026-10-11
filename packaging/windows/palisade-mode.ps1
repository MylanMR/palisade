<#
.SYNOPSIS
  Choose how Palisade runs on this computer. The installer runs this for the mode you pick;
  run it yourself later (in an elevated PowerShell) to switch.

.EXAMPLE
  palisade-mode.ps1 -Mode service -Reviewer CONTOSO\mike   # locked-down service; mike reviews the audit log
  palisade-mode.ps1 -Mode desktop                          # each person runs Palisade under their own login
  palisade-mode.ps1 -Mode status
  palisade-mode.ps1 -Mode remove                           # used by uninstall; keeps all data

.NOTES
  Service mode
    - The Windows service "Palisade" runs as the virtual account NT SERVICE\Palisade: no
      password, no interactive logon, its own security identifier.
    - The scheduled task "Palisade Setup" runs as SYSTEM at startup. It downloads and verifies
      the models, which the service account cannot write, and exits in seconds when nothing is missing.
    - Members of the local group "Palisade Audit" can read the audit log and the reviewer
      token. Changing either requires an elevated (UAC) session, which Windows records.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('service', 'desktop', 'status', 'remove')][string]$Mode,
  [string]$Reviewer = '',
  [string]$InstallDir = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'

$ServiceName = 'Palisade'
$ServiceSid  = "NT SERVICE\$ServiceName"
$TaskName    = 'Palisade Setup'
$AuditGroup  = 'Palisade Audit'
$Base        = Join-Path $env:ProgramData 'Palisade'
$Conf        = Join-Path $Base 'config'
$Data        = Join-Path $Base 'data'
$ModeFile    = Join-Path $InstallDir 'install-mode'
$Python      = Join-Path $InstallDir 'runtime\python.exe'
$PythonW     = Join-Path $InstallDir 'runtime\pythonw.exe'
$WinSW       = Join-Path $InstallDir 'service\Palisade.exe'
$StartupLnk  = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Palisade.lnk'
$Writable    = 'audit', 'logs', 'state', 'eval', 'compliance'

function Say($m) { Write-Host "==> $m" }
function Test-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-Icacls([string[]]$IcaclsArgs) {
  & icacls.exe @IcaclsArgs | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls $($IcaclsArgs -join ' ') failed ($LASTEXITCODE)" }
}

function Stop-Palisade {
  if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue }
  # Desktop-mode copies run as each signed-in person; stop anything started from this folder.
  Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, 'OrdinalIgnoreCase') } |
    Stop-Process -Force -ErrorAction SilentlyContinue
}

function Remove-ServiceParts {
  Stop-Palisade
  if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { & $WinSW uninstall | Out-Null }
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
}

function Set-ServiceMode {
  Say 'Audit group'
  if (-not (Get-LocalGroup -Name $AuditGroup -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $AuditGroup -Description 'Can read the Palisade audit log; cannot change it' | Out-Null
  }
  if ($Reviewer) {
    $admins = Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name }
    if ($admins -contains $Reviewer) {
      if (-not (Get-LocalGroupMember -Group $AuditGroup | Where-Object Name -eq $Reviewer)) {
        Add-LocalGroupMember -Group $AuditGroup -Member $Reviewer
      }
      Write-Host "reviewer: $Reviewer"
    } else {
      Write-Host "$Reviewer is not a member of Administrators, so it was not added as a reviewer."
    }
  }

  Say 'Service (runs as NT SERVICE\Palisade)'
  Remove-DesktopParts
  $logDir = Join-Path $Data 'logs'
  New-Item -ItemType Directory -Force -Path $Conf, $Data, (Join-Path $Data 'models') | Out-Null
  foreach ($d in $Writable) { New-Item -ItemType Directory -Force -Path (Join-Path $Data $d) | Out-Null }
  $xml = @"
<service>
  <id>$ServiceName</id>
  <name>Palisade</name>
  <description>Policy-enforced local AI assistant with a tamper-evident audit log.</description>
  <executable>$Python</executable>
  <arguments>-I -m palisade run</arguments>
  <env name="PALISADE_MODE" value="service"/>
  <workingdirectory>$Data</workingdirectory>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <onfailure action="restart" delay="10 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>15 sec</stoptimeout>
  <logpath>$logDir</logpath>
  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>5</keepFiles></log>
</service>
"@
  Set-Content -Path (Join-Path $InstallDir 'service\Palisade.xml') -Value $xml -Encoding UTF8
  if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { & $WinSW uninstall | Out-Null; Start-Sleep -Seconds 2 }
  & $WinSW install | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not install the Palisade service" }
  # A virtual account needs no password; Windows manages it. Set after creation, as WinSW installs as LocalSystem.
  & sc.exe config $ServiceName obj= $ServiceSid password= "" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not set the service account to $ServiceSid" }

  Say 'Folder permissions'
  # Root folders: inheritance off. SYSTEM and Administrators keep full control (an elevated,
  # logged action), the service and the audit group read.
  foreach ($root in $Base, $Conf, $Data) {
    Invoke-Icacls @($root, '/inheritance:r', '/grant:r', 'SYSTEM:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
                    "${AuditGroup}:(OI)(CI)RX", "${ServiceSid}:(OI)(CI)RX")
  }
  foreach ($d in $Writable) {
    Invoke-Icacls @((Join-Path $Data $d), '/grant', "${ServiceSid}:(OI)(CI)M")
  }

  Say 'Setup task (runs as SYSTEM at startup)'
  $action = New-ScheduledTaskAction -Execute $Python -Argument '-I -m palisade setup --if-needed' -WorkingDirectory $Data
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  # The task and any administrator's `palisade` command read the mode from this file.
  Set-Content -Path $ModeFile -Value 'service' -Encoding ASCII
  Start-ScheduledTask -TaskName $TaskName
  Start-Service $ServiceName
  Write-Host 'Palisade is starting. Open http://127.0.0.1:8080/ to watch setup download the models (about 10 GB).'
}

function Remove-DesktopParts {
  if (Test-Path $StartupLnk) { Remove-Item $StartupLnk -Force }
}

function Set-DesktopMode {
  Remove-ServiceParts
  Set-Content -Path $ModeFile -Value 'desktop' -Encoding ASCII
  # Start Palisade at sign-in for everyone who uses this computer; each gets their own data.
  $shell = New-Object -ComObject WScript.Shell
  $lnk = $shell.CreateShortcut($StartupLnk)
  $lnk.TargetPath = $PythonW
  $lnk.Arguments = '-I -m palisade open --no-browser'
  $lnk.WorkingDirectory = $InstallDir
  $lnk.Description = 'Start Palisade'
  $lnk.Save()
  if (Test-Path $Data) { Write-Host "Service-mode data stays in $Base." }
  Write-Host 'Desktop mode chosen. Open Palisade from the Start menu.'
}

switch ($Mode) {
  'status' {
    $m = if (Test-Path $ModeFile) { (Get-Content $ModeFile -Raw).Trim() } else { 'not chosen yet' }
    Write-Host "mode: $m"
    Get-Service $ServiceName -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Format-Table TaskName, State -AutoSize
    $st = Join-Path $Data 'setup-status.json'
    if (Test-Path $st) { (Get-Content $st -Raw | ConvertFrom-Json) | Select-Object state, message | Format-List }
  }
  'service' { if (-not (Test-Admin)) { throw 'Run this in an elevated PowerShell.' }; Set-ServiceMode }
  'desktop' { if (-not (Test-Admin)) { throw 'Run this in an elevated PowerShell.' }; Set-DesktopMode }
  'remove'  {
    Remove-ServiceParts; Remove-DesktopParts
    # Files this script created inside the install folder, so uninstall can remove the folder.
    foreach ($f in $ModeFile, (Join-Path $InstallDir 'service\Palisade.xml')) {
      if (Test-Path $f) { Remove-Item $f -Force }
    }
    Write-Host "Palisade removed. Settings and the audit log remain in $Base."
  }
}

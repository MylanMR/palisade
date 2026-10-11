<#
.SYNOPSIS
  Build the Windows installers: Palisade-<version>-windows-x64.msi and .exe.

.DESCRIPTION
  Run the stages in order. Code signing happens between stages (the release workflow signs
  with Azure Artifact Signing); for an unsigned test build, run them back to back.

    .\build.ps1 -Stage Payload    assemble build\payload-windows-x64 (Python, app, model server, WinSW, VC++ runtime)
    <sign every .exe, .dll, .pyd, .ps1 in the payload>
    .\build.ps1 -Stage Rehash     add Microsoft's VC++ runtime DLLs, record the model-server files' hashes
    .\build.ps1 -Stage Msi        build dist\Palisade-<v>-windows-x64.msi
    <sign the .msi>
    .\build.ps1 -Stage Bundle     build the .exe around the signed .msi and detach its engine
    <sign build\windows\engine.exe>
    .\build.ps1 -Stage Reattach   reattach the signed engine: dist\Palisade-<v>-windows-x64.exe
    <sign the .exe>

  Needs: Python 3.9+ with PyYAML, the WiX .NET tool (pinned version in packaging\inputs.yaml),
  and Visual Studio Build Tools (for the app-local Visual C++ runtime the model server needs).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Payload', 'Rehash', 'Msi', 'Bundle', 'Reattach')][string]$Stage,
  [string]$OutDir
)
$ErrorActionPreference = 'Stop'
$Here    = $PSScriptRoot
$Repo    = (Resolve-Path (Join-Path $Here '..\..')).Path
$Payload = Join-Path $Repo 'build\payload-windows-x64'
$Work    = Join-Path $Repo 'build\windows'
if (-not $OutDir) { $OutDir = Join-Path $Repo 'dist' }
New-Item -ItemType Directory -Force -Path $Work, $OutDir, (Join-Path $Repo 'build\cache') | Out-Null

function Get-Inputs { python -c "import json,yaml,sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))" (Join-Path $Repo 'packaging\inputs.yaml') | ConvertFrom-Json }
function Get-Version { (Get-Content (Join-Path $Payload 'install.json') -Raw | ConvertFrom-Json).version }
function Invoke-Checked([scriptblock]$Block, [string]$What) { & $Block; if ($LASTEXITCODE -ne 0) { throw "$What failed ($LASTEXITCODE)" } }

switch ($Stage) {
  'Payload' {
    Invoke-Checked { python (Join-Path $Repo 'packaging\build_payload.py') --platform windows-x64 --out $Payload --cache (Join-Path $Repo 'build\cache') } 'payload'

    # WinSW service wrapper, pinned and verified.
    $in = Get-Inputs
    $winsw = Join-Path $Repo 'build\cache\WinSW-x64.exe'
    if (-not (Test-Path $winsw)) { Invoke-WebRequest -Uri $in.winsw.url -OutFile $winsw -UseBasicParsing }
    $got = (Get-FileHash $winsw -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $in.winsw.sha256) { Remove-Item $winsw; throw "WinSW hash mismatch: expected $($in.winsw.sha256), got $got" }
    New-Item -ItemType Directory -Force -Path (Join-Path $Payload 'service'), (Join-Path $Payload 'libexec') | Out-Null
    Copy-Item $winsw (Join-Path $Payload 'service\Palisade.exe')
    Copy-Item (Join-Path $Here 'palisade-mode.ps1') (Join-Path $Payload 'libexec\palisade-mode.ps1')

    Invoke-Checked { & (Join-Path $Payload 'llama\llama-server.exe') --version } 'llama-server smoke test'
    Write-Host "payload ready to sign: $Payload"
  }

  'Rehash' {
    # The model server links the Visual C++ runtime (MSVCP140, VCRUNTIME140, VCRUNTIME140_1).
    # Ship Microsoft's redistributable DLLs next to it (app-local deployment), so the MSI has no
    # prerequisite and works under Intune and Group Policy. Added after signing so they keep
    # Microsoft's own signatures.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Visual Studio Build Tools with the C++ workload are required for the VC++ runtime DLLs' }
    $crt = Get-ChildItem (Join-Path $vs 'VC\Redist\MSVC\*\x64\Microsoft.VC14*.CRT') -Directory | Sort-Object FullName | Select-Object -Last 1
    foreach ($dll in 'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll') {
      $src = Join-Path $crt.FullName $dll
      if ((Get-AuthenticodeSignature $src).SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw "$dll is not signed by Microsoft" }
      Copy-Item $src (Join-Path $Payload "llama\$dll")
    }
    Invoke-Checked { python (Join-Path $Repo 'packaging\build_payload.py') --rehash-bin $Payload } 'rehash'
    $bad = Get-ChildItem $Payload -Recurse -Include *.exe, *.dll, *.pyd, *.ps1 |
      Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne 'Valid' }
    if ($bad) { Write-Warning "$($bad.Count) files are not signed (expected only for an unsigned test build)" }
  }

  'Msi' {
    $v = Get-Version
    # License page: the Apache license as minimal RTF.
    python -c @"
import sys
t = open(sys.argv[1], encoding='utf-8').read().replace('\\', '\\\\').replace('{', '\\{').replace('}', '\\}')
open(sys.argv[2], 'w', encoding='ascii', errors='replace').write('{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Tahoma;}}\\fs16 ' + t.replace('\n', '\\par\n') + '}')
"@ (Join-Path $Repo 'LICENSE') (Join-Path $Here 'License.rtf')
    $msi = Join-Path $OutDir "Palisade-$v-windows-x64.msi"
    Push-Location $Here
    try {
      Invoke-Checked { wix build Palisade.wxs -arch x64 -acceptEula wix7 -d "Version=$v" -d "PayloadDir=$Payload" `
          -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -o $msi } 'wix build (msi)'
    } finally { Pop-Location }
    Write-Host "msi: $msi"
  }

  'Bundle' {
    $v = Get-Version
    $msi = Join-Path $OutDir "Palisade-$v-windows-x64.msi"
    Push-Location $Here
    try {
      Invoke-Checked { wix build Bundle.wxs -arch x64 -acceptEula wix7 -d "Version=$v" -d "MsiPath=$msi" `
          -ext WixToolset.BootstrapperApplications.wixext -o (Join-Path $Work 'bundle.exe') } 'wix build (bundle)'
      # A bundle's engine must be signed separately from the bundle that carries it.
      Invoke-Checked { wix burn detach (Join-Path $Work 'bundle.exe') -engine (Join-Path $Work 'engine.exe') } 'burn detach'
    } finally { Pop-Location }
    Write-Host "engine to sign: $(Join-Path $Work 'engine.exe')"
  }

  'Reattach' {
    $v = Get-Version
    $exe = Join-Path $OutDir "Palisade-$v-windows-x64.exe"
    Invoke-Checked { wix burn reattach (Join-Path $Work 'bundle.exe') -engine (Join-Path $Work 'engine.exe') -o $exe } 'burn reattach'
    Write-Host "exe: $exe"
  }
}

# Windows installers

`build.ps1` produces two files from the same install logic:

- **Palisade-<version>-windows-x64.msi** for Intune, Group Policy, and `msiexec`.
- **Palisade-<version>-windows-x64.exe**, a WiX bundle that shows the MSI's own dialogs. Easier for individuals; installs identically.

## What the installer does

- Installs to `C:\Program Files\Palisade` (Python runtime, Palisade, the llama.cpp model server, WinSW, and the Visual C++ runtime DLLs the model server needs).
- Asks for the mode (silent installs: `PALISADE_MODE=service|desktop`; the choice is remembered across upgrades).
- Runs `libexec\palisade-mode.ps1` as SYSTEM to set the mode up. In service mode it creates:
  - the service **Palisade**, running as the virtual account `NT SERVICE\Palisade` (no password, no interactive logon);
  - the scheduled task **Palisade Setup**, running as SYSTEM at startup to download and verify models;
  - the local group **Palisade Audit**, with read access to `C:\ProgramData\Palisade`. The installing administrator is added (silent installs: `PALISADE_REVIEWER=DOMAIN\user`).
- Adds `C:\Program Files\Palisade\bin` to the system PATH so `palisade audit verify` works in a terminal.
- Uninstalling removes the service, task, and shortcuts, and keeps `C:\ProgramData\Palisade` (settings and the audit log).

## WiX licensing

The installers are built with WiX Toolset 7, which ships under an Open Source Maintenance Fee EULA. The build accepts it with `-acceptEula wix7`. Under the terms published at https://docs.firegiant.com/wix/osmf/, projects whose use of WiX brings in less than US$10,000 a year owe no fee. Check the current terms before relying on this, and before shipping Palisade commercially.

## Testing without signing

Run the stages back to back. Windows SmartScreen warns about unsigned installers; that is expected for a test build and must not happen for a release.

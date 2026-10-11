# Signing and releasing the installers

The release workflow (`.github/workflows/release.yml`) builds every installer on GitHub's runners, installs each one on a clean machine to prove it works, signs it, and publishes a **draft** GitHub release for you to review. Nothing is signed on a personal computer, and no signing key is stored in the repository.

| Platform | Signed with | Verified by |
|---|---|---|
| macOS `.pkg` and `.dmg` | Apple Developer ID (Application and Installer certificates), then notarized by Apple and stapled | Gatekeeper, on every install |
| Windows `.msi` and `.exe` | Azure Artifact Signing (formerly Trusted Signing), Authenticode with an RFC 3161 timestamp | SmartScreen and Windows Installer |
| Linux `.deb` and `.rpm` | A release OpenPGP key, as detached `.asc` signatures | The person installing, with `gpg --verify` |
| Every file | `SHA256SUMS`, plus a GitHub build-provenance attestation | `sha256sum -c`, `gh attestation verify` |

Inside the installers, every executable and library is signed too: on macOS each Mach-O file is signed with the hardened runtime before packaging; on Windows every `.exe`, `.dll`, `.pyd`, and `.ps1` is signed (Microsoft's Visual C++ runtime DLLs keep Microsoft's own signatures). Palisade then records the signed model-server files' hashes, so its startup check covers the signed bytes.

## One-time setup

Put every value below in the repository's **Settings > Secrets and variables > Actions** as a repository secret. For extra protection, create an environment named `release` with yourself as a required reviewer, move the secrets there, and add `environment: release` to the `linux`, `macos`, and `windows` jobs; every signed build then waits for your approval.

### macOS (Apple Developer Program, US$99 a year)

1. Enroll in the Apple Developer Program. Creating Developer ID certificates requires the Account Holder role.
2. In Certificates, Identifiers & Profiles, create a **Developer ID Application** certificate and a **Developer ID Installer** certificate. Install both in Keychain Access on a Mac.
3. In Keychain Access, select both certificates with their private keys and export them together as one `.p12` file with a strong password.
4. In App Store Connect, under Users and Access > Integrations, create a Team API key with the Developer role. Download the `.p8` file (it can be downloaded only once) and note the Key ID and Issuer ID.

| Secret | Value |
|---|---|
| `MACOS_CERTS_P12_BASE64` | `base64 -i certs.p12` |
| `MACOS_CERTS_PASSWORD` | the `.p12` password |
| `MACOS_APP_IDENTITY` | `Developer ID Application: Your Name (TEAMID)`, exactly as Keychain shows it |
| `MACOS_INSTALLER_IDENTITY` | `Developer ID Installer: Your Name (TEAMID)` |
| `NOTARY_KEY_P8_BASE64` | `base64 -i AuthKey_XXXX.p8` |
| `NOTARY_KEY_ID` | the API key's Key ID |
| `NOTARY_ISSUER` | the Issuer ID |

After the secrets are stored, delete the local `.p12` and `.p8` copies or keep them offline.

### Windows (Azure Artifact Signing)

1. In an Azure subscription, create an Artifact Signing account and complete identity validation. Check Microsoft's current eligibility rules for individual developers before starting.
2. Create a **Public Trust** certificate profile. Note the account name, the profile name, and the account's regional endpoint (for example `https://eus.codesigning.azure.net/`).
3. In Microsoft Entra ID, register an application for GitHub Actions. Add a **federated credential** for GitHub Actions with the entity type set to tag, so only workflow runs for this repository's tags can sign. No client secret is created: the workflow signs in with a short-lived OpenID Connect token.
4. On the certificate profile, assign that application the role that allows signing with the profile (named "Artifact Signing Certificate Profile Signer", or "Trusted Signing Certificate Profile Signer" in older documentation).

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | the Entra tenant ID |
| `AZURE_CLIENT_ID` | the application (client) ID |
| `AZURE_SIGNING_ENDPOINT` | the account's endpoint URL |
| `AZURE_SIGNING_ACCOUNT` | the Artifact Signing account name |
| `AZURE_CERT_PROFILE` | the certificate profile name |

A traditional code-signing certificate also works, but since June 2023 their private keys must live on a hardware security module, so the signing steps would change to that vendor's tool.

### Linux (OpenPGP release key)

1. Create a key used only for signing releases: `gpg --quick-gen-key "Palisade releases <you@example.com>" ed25519 sign 2y`.
2. Publish the public key: add `gpg --armor --export KEYID` to the repository as `KEYS`, and link it from the README.
3. Store the private key: `gpg --armor --export-secret-keys KEYID`.

| Secret | Value |
|---|---|
| `LINUX_GPG_PRIVATE_KEY` | the armored private key |
| `LINUX_GPG_PASSPHRASE` | its passphrase |

## Releasing a version

1. Update `__version__` in `palisade/__init__.py` and add a `CHANGELOG.md` entry.
2. Fill in any missing model hashes from Hugging Face, on a machine that can reach it, and review the diff:

   ```
   python packaging/hf_hashes.py --write
   ```

   The release workflow runs the same check without `--write` and refuses to release if any default model's hash is missing or differs from what Hugging Face publishes.
3. Commit, tag, and push:

   ```
   git tag -a v0.3.0 -m "Palisade 0.3.0"
   git push origin main v0.3.0
   ```

4. Watch the run under **Actions > release**. Each platform job installs its installer on a clean runner, checks that the service starts under its locked-down account and that the account cannot write models or policy, then uninstalls it and checks that the audit data survived.
5. Open the draft under **Releases**, download one installer per platform, and try it. Then publish the draft.

## Unsigned test builds

**Actions > release > Run workflow** with "Sign and notarize" cleared builds every installer unsigned, runs the same install tests, and leaves the results as workflow artifacts named `*-UNSIGNED`. Use these to try changes before you have certificates. macOS blocks unsigned packages when opened from Finder (right-click > Open, or `sudo installer -pkg ... -target /`), and Windows SmartScreen warns. Never publish them.

## How someone verifies a download

```
sha256sum -c SHA256SUMS --ignore-missing                       # any platform with coreutils
gh attestation verify Palisade-0.3.0-macos-arm64.dmg -R MylanMR/palisade
pkgutil --check-signature Palisade-0.3.0-macos-arm64.pkg        # macOS
spctl --assess --type install -v Palisade-0.3.0-macos-arm64.pkg # macOS, includes notarization
Get-AuthenticodeSignature .\Palisade-0.3.0-windows-x64.msi      # Windows PowerShell
gpg --verify palisade_0.3.0-1_amd64.deb.asc palisade_0.3.0-1_amd64.deb   # Linux, after importing KEYS
```

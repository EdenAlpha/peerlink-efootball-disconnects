# eFootball APK acquisition notes (evidence-only, 2026-09-26 UTC)

## Host state
- Disk C: free **18.64 GB** (total 59.5 GB) — passes 5 GB requirement.
  - `fsutil volume diskfree C:` Total free bytes 20,019,048,448.
- Target dir created: `efootball-apk\` (empty, no APK downloaded yet).

## Tool availability (this Windows host)
| tool | status |
|---|---|
| apktool | NOT FOUND (no `apktool` on PATH). winget search only shows `AlexanderGorishnyak.APKEditorStudio`; apktool itself installable via `winget install -e --id Konami... ` NO — use official apktool: download `apktool.jar` + wrapper, requires Java. Java 17 present so it will run once installed. |
| jadx | NOT FOUND. Available via winget: `winget install -e --id Skylot.jadx` (v1.5.6). Needs Java 17 (present: Temurin 17.0.20.1). |
| 7z | NOT FOUND (no `7z`, no `C:\Program Files\7-Zip\`). Available: `winget install -e --id 7zip.7zip` (v26.03). |
| unzip | NOT FOUND as binary. Built-ins available: PowerShell `Expand-Archive` (Microsoft.PowerShell.Archive 1.0.1.0) and `tar.exe` (bsdtar 3.8.4). APK = zip so both work for unzip-only steps. |
| strings | NOT FOUND (Sysinternals/BinUtils not installed). Alternative: `winget install -e --id Microsoft.Sysinternals.Strings` or use jadx/apktool output instead. |
| java | FOUND: OpenJDK 17.0.20.1 (Temurin-17.0.20.1+1). |
| python | FOUND: Python 3.12.10 (`python`, not `python3`). |
| winget | FOUND: v1.29.380. |
| curl.exe | FOUND: curl 8.16.0 Windows. |
| adb | NOT FOUND. |

## APKMirror findings (fetched 2026-09-26)
- Listing: https://www.apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/
- Release page: https://www.apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/efootball-11-0-1-release/
- **11.0.1 is the newest** (uploaded 2026-08-20 07:10 UTC, 5,475 downloads at time of fetch). No newer version exists. Both 11.0.1 variants carry versionCode **311000101** = target build.
- Two arm64-v8a 480-640dpi variants, both BUNDLE (`.apkm`, needs APKMirror Installer):

### Variant A (RECOMMENDED — full game, matches arm64-v8a target)
- Page: https://www.apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/efootball-11-0-1-release/efootball-11-0-1-2-android-apk-download/
- Spec: arm64-v8a, 480+640dpi, Min Android 7.0 (API 24), Target Android 16 (API 36), package `jp.konami.pesam`, 11.0.1 (311000101), Base APK + **29 splits**, 24 languages.
- Size: **780.92 MB (818,850,656 bytes)**.
- Expected `.apkm` filename: `jp.konami.pesam_11.0.1-311000101_1arch_2dpi_24lang_2feat_c6d2e20f574faf385f484fd3fb950f4e_apkmirror.com.apkm`
- Bundle file hashes (from page `safeDownload` modal):
  - MD5: `11919543cd8566c36aa434ed0ce2deee`
  - SHA-1: `9e7347a73f4ba83aba045d7f32856ab6d11498ec`
  - SHA-256: `c73900269fb4129a1b841ce3776e78aa8b3e92c2c9d9992cbf239ec412f81977`
- APK cert fingerprints: SHA-1 `5a13965ff84ee9e59df081671272ab0d430e385f`, SHA-256 `d29e0251ecf7e15e06ad1874ee1c08213dfef3d4bce03032b181667f7389c4d2`, CN=`Konami Digital Entertainment Co., Ltd.`
- Contents: Base 8.87 MB + arm64-v8a 54.50 MB + dpi 480/640 + 24 lang splits + **pad_it_0 368.48 MB + pad_it_1 377.10 MB** (game assets — this is why it is ~781 MB).
- Downloads at fetch: 3,852.

### Variant B (slim, Android 10+, NO asset packs — NOT the full game)
- Page: https://www.apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/efootball-11-0-1-release/efootball-11-0-1-android-apk-download/
- Spec: arm64-v8a, 480+640dpi, Min Android 10 (API 29), Base APK + **27 splits**.
- Size: **63.82 MB (66,919,693 bytes)**. Downloads at fetch: 1,623.

## Download status: NOT DOWNLOADED (blocked, evidence below)
- `curl.exe -I` and `Invoke-WebRequest -Method Head` against both `/download/?key=...` interstitial URLs from this host return **HTTP 403, `Cf-Mitigated: challenge`**, Cloudflare `Server: cloudflare`, `CF-RAY` present (observed 2026-09-26 18:30 UTC).
- The `download.php?id=15517153&key=f91615d3ce614afd08cf17926e46267a24cede5b` direct link (minted during page fetch) likewise returns 403+challenge from this host. Keys are **time-limited / IP-bound** — the example key above is already stale and MUST NOT be reused; derive a fresh one in a real browser.
- APKPure mirror check also 403 from fetch egress.
- Play Store (`https://play.google.com/store/apps/details?id=jp.konami.pesam`) was not attempted (needs Google auth for direct APK; use Aurora Store / `gplaycli` instead — not installed here).

## EXACT manual steps (do in a real desktop browser on an unblocked network)
1. Open Variant A page (URL above). Click `Download APK Bundle`.
2. Wait through the interstitial (disable ad-blocker for apkmirror.com or wait 15 s), then click the `here` / auto-started download. Save as `efootball-apk\jp.konami.pesam_11.0.1-311000101_..._apkmirror.com.apkm`.
3. Resume-capable CLI alternative (PowerShell, run in `efootball-apk\`; replace URL with the FRESH link your browser lands on — DevTools > Network > `download.php?id=...&key=...`):
   ```powershell
   curl.exe -L -C - -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" -e "https://www.apkmirror.com/apk/konami/pes2017-pro-evolution-soccer/efootball-11-0-1-release/efootball-11-0-1-2-android-apk-download/download/" -o "jp.konami.pesam_11.0.1-311000101_full.apkm" "<PASTE-FRESH-download.php-URL>"
   ```
   (`-C -` = resume. Re-run same command to resume.)
4. Verify (PowerShell):
   ```powershell
   (Get-Item .\*.apkm).Length                         # expect 818850656
   Get-FileHash .\*.apkm -Algorithm MD5               # expect 11919543cd8566c36aa434ed0ce2deee
   Get-FileHash .\*.apkm -Algorithm SHA256            # expect c73900269fb4129a1b841ce3776e78aa8b3e92c2c9d9992cbf239ec412f81977
   ```
5. Open the bundle (`.apkm` is a zip): `Expand-Archive .\*.apkm .\apkm_unzip\` or install 7-Zip and open. Expect base APK + 29 splits including `pad_it_0` / `pad_it_1` asset packs.
6. Install tooling before analysis:
   ```powershell
   winget install -e --id 7zip.7zip
   winget install -e --id Skylot.jadx
   # apktool: download apktool.jar from https://apktool.org + wrapper script (needs Java 17, present)
   ```

## Play Store alternative (if APKMirror stays blocked)
- Package `jp.konami.pesam`, Play listing: https://play.google.com/store/apps/details?id=jp.konami.pesam
- Options: physical Android device + `adb pull`, or Aurora Store (anonymous Play login) to download 11.0.1 (311000101) arm64-v8a split set. Not attempted here (no adb, no device).

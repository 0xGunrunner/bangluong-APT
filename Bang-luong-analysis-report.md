# Static Analysis Report — "Bảng lương" (Salary Sheet) Malware Package

**Date:** 2026-11-17
**Analyst environment:** Kali Linux, static analysis only (no execution)
**Sample:** `/home/kali/Mal-DFIR/Bảng lương.zip`
**Verdict:** Full-featured RAT dropper (Winos 4.0 / ValleyRAT-style toolchain) with kernel-mode EDR killing, triple persistence, and vendor-signed components. Targeted phishing lure against Vietnamese users (payroll theme), operated by a Chinese-speaking actor.

---

## 1. Sample Identification

| Object | Value |
|---|---|
| Container | `Bảng lương.zip` (3,029,913 B) — ZIP v6.3, 1 entry |
| ZIP SHA-256 | `ec1a685c6eaf825d670f789857002a4e32a8f6a162bbcc31144df25ac72790ed` |
| ZIP MD5 | `c3600267ffb341a808bdc941cd213e78` |
| Payload | `Bảng lương.exe` (3,242,897 B) — PE32+ x64 GUI |
| Payload SHA-256 | `f8ef62e4276e61b01435874c2385ba8b80d8b98d7b7d056f2f3ddffd27a3c5a8` |
| Type | WinRAR SFX (self-extracting archive), stub compiled 2024-02-26 (MSVC 14.33) |
| Stub PDB | `D:\Projects\WinRAR\sfx\build\sfxrar64\Release\sfxrar.pdb` (legitimate WinRAR stub) |
| Appended data | RAR v7 archive at file offset 422,912 (29 files, 7,565,638 B uncompressed) |

Note: the ZIP's local-header filename uses a legacy codepage that mismatches the central directory — one more sign of sloppy/hand-built tooling.

## 2. SFX Script (embedded in RAR comment, with a Chinese operator note `;下面的注释包含自解压脚本命令`)

```
Path=C:\ProgramLog\Windows\AppData\Log
Setup=WeChatAppEx.exe
Setup=TGFile.exe hide.log
Setup=TGFile.exe regite.log
Setup=TGFile.exe new.jpg
Silent=1
Overwrite=2
```

Silent extraction into a fake-`AppData` folder (`C:\ProgramLog\...` is not a Windows directory), then auto-execution of four commands in order.

## 3. Execution Chain

1. **Victim runs `Bảng lương.exe`** (disguised as a salary document) → silent SFX extraction of 29 files to `C:\ProgramLog\Windows\AppData\Log`.
2. **`WeChatAppEx.exe`** (genuine, Tencent-signed WeChat browser engine v2.2.0.13227) starts and **sideloads the attacker's `xweb_elf.dll`** (its first import dependency).
3. **`xweb_elf.dll`** (orchestrator, unsigned):
   - Detects Sandboxie sandboxes (`SbieDll_GetServiceRegistryValue`, `SbieDll_IsBoxedService`, `SbieDll_StartBoxedService`).
   - Enumerates processes (`CreateToolhelp32Snapshot`, `Process32FirstW/NextW`).
   - Installs **`TG_Soft.sys` as a kernel service** (`CreateServiceW`/`StartServiceW`/`ChangeServiceConfigW`; debug strings incl. "CreateServiceW OK, ImagePath: %s", "ABORT: driver load failed", annotated Win32 errors 1060/577/1275=DRIVER_BLOCKED).
   - Kills security products via the driver (`DeviceIoControl` → `\Device\ProcKill`).
   - References a next-stage module `cuhjctyasbdtas.dll`.
4. **`TGFile.exe hide.log`** — a Sangfor-signed LuaJIT script runner executes the encrypted LuaJIT bytecode plugin `hide.log`, which:
   - Reads `set.log`, decrypts it with **RC4 (key `s3ch0bachky`)**.
   - Allocates RWX memory (`VirtualAlloc`/`VirtualProtect`) and runs the shellcode via `CreateThread` (guarded by mutex `Global\TGFile_ShellcodeMutex`).
   - Uses `EnumCalendarInfoA` callback abuse (emulation/analysis evasion) and `IsDebuggerPresent` checks.
5. **The decrypted shellcode** (321,324 B, entropy 8.00 → 5.93 after decryption, tail marker `"dave"`) carries an **embedded x64 RAT DLL** (318,464 B, ImageBase `0x180000000`) and reflectively loads it; exports `load`, `run`, and `zidingyixiugaidaochuhanshu` ("custom-modified export function" — pinyin).
6. **`TGFile.exe regite.log`** — COM **TypeLib hijack persistence**: writes the scriptlet path into `HKLM\SOFTWARE\Classes\TypeLib\{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\1.1\0\win64` (the Internet Explorer WebBrowser TypeLib GUID); any application loading that typelib triggers `log.s`. Also hides `C:\ProgramLog` via `SetFileAttributesA` (mutex `Local\TGFile_SetupMutex`).
7. **`TGFile.exe new.jpg`** — scheduled-task persistence via hidden `cmd.exe`: `schtasks /create /tn "OneDirverUpdata" /tr "...\TGFile.exe ...\hide.log" /sc onlogon /f` (task name deliberately resembles a OneDrive updater; contains Chinese dev comments).
8. **C2:** the RAT communicates over a custom TCP protocol; transport evidence in the bundled `vpncore.log` (a real leaked OpenVPN client log) shows a tunnel to **182.140.242.59:13444** (Tencent Cloud range). No plaintext C2 indicators inside the RAT DLL (runtime-decrypted config or delivered via tunnel).

## 4. The Kernel Driver — `TG_Soft.sys` (signed EDR killer)

- 15,616 B, native x64 driver, built 2025-12-21, MSVC 14.44.
- **PDB:** `D:\tools\驱动\MyDriver1-master\x64\Release\MyDrv1.pdb` (`驱动` = "driver"; `MyDriver1-master` = downloaded GitHub template project).
- **Signed by:** `CN=Anneng electronic Co. Ltd., Fuzhou, Fujian, CN` — Thawte Code Signing CA-G2, serial `2602bb9ba2ae651aeaa79aec38a3cb3d`, valid **2013-05-06 → 2014-05-06** (long-expired, abused legacy cert).
- Device `\Device\ProcKill`, symlink `\??\ProcKill`.
- IOCTL `0x80001c00` (device 0x22, function 7, METHOD_BUFFERED, FILE_ANY_ACCESS), input = 4-byte PID:
  `ZwOpenProcess(PROCESS_ALL_ACCESS)` → `ZwTerminateProcess(handle, 0)` → `ZwClose`.
- Kills any process, including PPL-protected AV/EDR, from kernel context. No CVE involved — the malicious capability is the driver's only feature (BYOVD-equivalent effect, "signed-but-malicious" mechanism).

## 5. RAT Module Capabilities (from import analysis of carved DLL)

- **Keylogging:** `SetWindowsHookExW`, `GetLastInputInfo`, `GetForegroundWindow`, `GetWindowTextW`
- **Screen capture:** gdi32/gdiplus/dxgi suite (`GdipSaveImageToStream`, `CreateDIBSection`, `StretchBlt`, `CreateDXGIFactory`)
- **Clipboard theft:** `OpenClipboard`, `GetClipboardData`
- **File manager:** `GetLogicalDriveStringsW`, `GetDriveTypeW`, file I/O
- **Process control / shell:** `CreateProcessW/A`, `OpenProcess`, `GetProcessImageFileNameW`
- **Registry:** full `Reg*W` set
- **Anti-forensics:** `OpenEventLogW`, `ClearEventLogW` (Windows event-log wiping)
- **Privilege manipulation:** `LookupPrivilegeValueW`, `AdjustTokenPrivileges`
- **Host control:** `ExitWindowsEx`
- **C2:** raw WS2_32 socket stack (`connect`, `send`, `recv`, `select`, `gethostbyname`, …)

## 6. Component Inventory & Signature Provenance

| File | Role | Signature |
|---|---|---|
| `WeChatAppEx.exe` | Legit sideloading host | **Tencent Technology (Shenzhen)** — genuine, serial `ddaf2fe51f3b2e94cbb695a4a5174fc` |
| `xweb_elf.dll` | Malicious orchestrator/loader | Unsigned (Chromium-crashpad-style export names as mimicry) |
| `TG_Soft.sys` | Kernel EDR-killer driver | **Anneng electronic Co. Ltd.** (expired 2013 Thawte cert) |
| `TGFile.exe` | LuaJIT plugin runner | **Sangfor Technologies Inc.**, serial `9f980676d7d7e8d5eb042d2df477848`, valid 2023→2026 — **no version resource** |
| `libepsbase.dll` | Actor support lib (path utils, exec, sockets) | **Sangfor** (same cert) — no version resource |
| `libssh2.dll` | SSH/network lib | **AsiaInfo Technologies (Chengdu)**, serial `e3e33f20e065bf2b903353c2fb8e8e4`, valid 2023→2026 |
| `lua51.dll` | LuaJIT 2.1.0-beta3 engine | Unsigned (stock engine) |
| `hide.log` | LuaJIT plugin — shellcode stager (RC4 `s3ch0bachky`) | — |
| `regite.log` | LuaJIT plugin — COM TypeLib hijack + hiding | — |
| `new.jpg` | LuaJIT **plaintext source** — schtasks persistence | — |
| `set.log` | RC4-encrypted PIC shellcode container (RAT DLL) | — |
| `log.s` | JScript COM scriptlet (persistence payload) | — |
| `vpncore.log` | Decoy/OpenVPN log — **leaks C2 182.140.242.59:13444** | — |
| `pnpdiag.dll` | Unattributed, unsigned; registry + `DeviceIoControl` imports; MS-style name | Unsigned — suspicious, role not fully reversed |
| `iumdll.dll`, `jsproxy.dll`, `ksuser.dll`, `ttdloader.dll`, `msvcp100.dll`, `msvcr100.dll`, `vccorlib120.dll`, `vcruntime.dll`, `vcruntime140*.dll` | Genuine Microsoft DLLs (decoy ballast / dependencies) | Genuine Microsoft (Ireland Operations) |
| `readme.txt`, `websucker.py`, `wsgui.py` | 1997–2016-era Python webchecker demo junk (padding) | — |
| `normnfd.nls` | Unicode NLS normalization table (support) | — |

## 7. Anti-Analysis & Defense Evasion

- Sandboxie detection (`SbieDll_*`) in `xweb_elf.dll`
- `IsDebuggerPresent` checks across loader/plugin
- `EnumCalendarInfoA` callback execution (emulation bypass)
- Forged/absurd PE TimeDateStamps (1977, 2042, 2073, 2097…) on most files; real dates retained only on key components
- Everything user-visible is trusted-vendor-signed (Tencent / Sangfor / AsiaInfo / Microsoft); malicious logic confined to unsigned satellites
- Windows event-log clearing (RAT)
- Hidden folder attributes on `C:\ProgramLog`
- RC4 payload encryption (entropy 8.00)
- Kernel driver to defeat PPL-protected processes

## 8. Attribution Assessment

**Chinese-speaking crimeware actor; high-confidence toolchain match with the Winos 4.0 / ValleyRAT / Silver Fox cluster:**
- Chinese artifacts throughout: SFX operator note, PDB path `D:\tools\驱动\...`, pinyin export name `zidingyixiugaidaochuhanshu`, Chinese comments inside the Lua plugin source
- Abuse pattern of Chinese-vendor code-signing certificates (Anneng 2013 legacy; Sangfor; AsiaInfo) — all certs still valid or Windows-loadable via timestamping
- Winos 4.0 hallmarks: SFX + legit signed-binary sideloading (WeChat components), LuaJIT plugin framework, signed kill-driver, gambling/finance lures across SE Asia
- Vietnamese payroll lure ("Bảng lương") — consistent with the cluster's expansion into Vietnam
- The RC4 key `s3ch0bachky` is publicly reported in a Chinese forum analysis of a sibling sample → shared builder / serial campaign (moderate-to-high confidence cluster attribution; no specific actor identity claimed)

## 9. MITRE ATT&CK Mapping (selection)

| Tactic | Technique |
|---|---|
| Initial Access | T1566.002 Spearphishing Link/Attachment (payroll lure, suspected delivery) |
| Execution | T1204.002 User Execution (malicious file), T1059.003 Windows Command Shell (`cmd.exe`), T1218.010 Regsvr32/Scriptlet (`log.s`) |
| Persistence | T1053.005 Scheduled Task ("OneDirverUpdata"), T1546.015 COM Hijacking (TypeLib GUID hijack), T1543.003 Windows Service (driver service) |
| Privilege Escalation | T1547.006 Kernel Modules (signed driver load) |
| Defense Evasion | T1574.002 DLL Side-Loading (xweb_elf.dll, lua51.dll), T1562.001 Impair Defenses (driver-based process kill), T1070.001 Clear Windows Event Logs, T1027 Obfuscated Files (RC4), T1036.005 Match Legitimate Name/Location (WeChatAppEx, fake AppData path), T1553.002 Code Signing (abused certs), T1564.001 Hidden Files and Directories |
| Discovery | T1518 Software Discovery, T1082 System Info, T1057 Process Discovery |
| Collection | T1056.001 Keylogging, T1113 Screen Capture, T1115 Clipboard Data |
| C2 | T1095 Non-Application Layer Protocol (raw TCP), T1573 Encrypted Channel (OpenVPN tunnel) |

## 10. Indicators of Compromise

See `iocs.csv` for the machine-readable list. Highlights:

- C2: `182.140.242.59:13444` (TCP / OpenVPN)
- RC4 key: `s3ch0bachky`
- Drop path: `C:\ProgramLog\Windows\AppData\Log`
- Scheduled task: `OneDirverUpdata`
- Registry hijack: `HKLM\SOFTWARE\Classes\TypeLib\{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\1.1\0\win64`
- Driver device: `\Device\ProcKill` / `\??\ProcKill`, IOCTL `0x80001c00`
- Mutexes: `Global\TGFile_ShellcodeMutex`, `Local\TGFile_SetupMutex`
- Certificates: Anneng serial `2602bb9ba2ae651aeaa79aec38a3cb3d`; Sangfor serial `9f980676d7d7e8d5eb042d2df477848`; AsiaInfo serial `e3e33f20e065bf2b903353c2fb8e8e4`
- PDB: `D:\tools\驱动\MyDriver1-master\x64\Release\MyDrv1.pdb`
- Export: `zidingyixiugaidaochuhanshu`
- Hash manifest: `analysis-artifacts/hashes.sha256`

## 11. Detection & Response Recommendations

1. **Hunting:** scheduled tasks named `OneDirverUpdata`; services with ImagePath under `C:\ProgramLog`; the TypeLib GUID value pointing to `.s` files; `TGFile.exe` execution from `ProgramLog`; LuaJIT-magic (`1B 4C 4A 02`) files in user-writable paths.
2. **Network:** block/monitor `182.140.242.59` (all ports); alert on long-lived TCP sessions to Tencent Cloud IPs on non-standard ports from workstations.
3. **Driver:** add `TG_Soft.sys` hash + Anneng certificate serial to the Microsoft Vulnerable Driver Blocklist; alert on any service creating devices named `ProcKill`.
4. **Certificates:** notify Sangfor and AsiaInfo of the abuse (or confirm compromise of their signing processes). Treat their signatures as untrusted for these specific hashes.
5. **Email/gateway:** block zips containing WinRAR SFX with `Silent=1` + `Setup=` scripts; Vietnamese-payroll-themed lures.
6. YARA: `bang-luong-campaign.yar` (included) covers the SFX script, the kill driver, the Lua plugins, and the RAT export.

## 12. Limitations

- Static-only per engagement scope; execution chain reconstructed from embedded evidence (SFX script, plugin constants, import tables, debug strings) — no behavioral confirmation.
- `pnpdiag.dll` exact role and the RAT's full C2 protocol were not reversed.
- `set.log`/RAT relationship to `cuhjctyasbdtas.dll` inferred but not fully traced.

## 13. Artifacts

| Artifact | Path |
|---|---|
| Extracted payload files (29) | `analysis-artifacts/payload-files/` |
| Carved RAR archive | `analysis-artifacts/payload.rar` |
| Decrypted shellcode | `analysis-artifacts/set_log_decrypted.bin` |
| Carved RAT DLL | `analysis-artifacts/embedded_rat_pe.bin` |
| Hash manifest | `analysis-artifacts/hashes.sha256` |
| YARA rules | `bang-luong-campaign.yar` |
| IOC list | `iocs.csv` |
